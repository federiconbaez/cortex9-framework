// SPDX-License-Identifier: Apache-2.0
//! `c9-policy`: one declarative policy, three kernel enforcement points.
//!
//! A single TOML document describes the network surface (compiled to XDP
//! BPF maps and to the in-kernel Rust classifier), the workloads (compiled
//! to cgroup v2 controls) and the exec trust rules (compiled to an
//! Aho-Corasick automaton plus a SHA-256 allowlist).
//!
//! Compilation is where the pillars meet: cross-pillar contradictions such
//! as a workload exposing a port that the firewall denies are rejected
//! before anything touches the kernel, and every enforcer stamps the same
//! content fingerprint so a node can prove all of them run one policy.

use c9_classify::{Flags, Prefix, Rules, IPPROTO_TCP, IPPROTO_UDP};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Capacities of the BPF maps in `bpf/xdp_fw.bpf.c`. Checked against the C
/// source by a unit test so the two cannot drift.
pub const XDP_MAX_PREFIXES: usize = 4096;
pub const XDP_MAX_PORTS: usize = 1024;
/// Shortest signature accepted: shorter byte strings match benign binaries.
pub const MIN_SIGNATURE_LEN: usize = 6;

// ---------------------------------------------------------------- source --

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    meta: Meta,
    #[serde(default)]
    network: NetworkSpec,
    #[serde(default, rename = "workload")]
    workloads: Vec<WorkloadSpec>,
    #[serde(default)]
    exec: ExecSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    name: String,
    generation: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSpec {
    #[serde(default = "yes")]
    drop_malformed: bool,
    #[serde(default)]
    drop_fragments: bool,
    #[serde(default)]
    allow_src: Vec<String>,
    #[serde(default)]
    deny_src: Vec<String>,
    #[serde(default)]
    deny_dst_ports: Vec<String>,
}

impl Default for NetworkSpec {
    fn default() -> Self {
        NetworkSpec {
            drop_malformed: true,
            drop_fragments: false,
            allow_src: vec![],
            deny_src: vec![],
            deny_dst_ports: vec![],
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadSpec {
    name: String,
    memory_max: String,
    memory_high: Option<String>,
    #[serde(default = "zero")]
    swap_max: String,
    pids_max: Option<u64>,
    #[serde(default = "yes")]
    oom_group: bool,
    cpu_weight: Option<u64>,
    psi: Option<PsiSpec>,
    #[serde(default)]
    on_pressure: PressureAction,
    #[serde(default)]
    expose: Vec<String>,
    #[serde(default)]
    gpu_devices: Vec<String>,
}

fn zero() -> String {
    "0".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PsiSpec {
    #[serde(default)]
    kind: PsiKind,
    stall_ms: u64,
    window_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecSpec {
    #[serde(default)]
    mode: ExecMode,
    #[serde(default)]
    watch: Vec<String>,
    #[serde(default = "default_scan")]
    max_scan_bytes: String,
    #[serde(default)]
    on_scan_error: ScanErrorAction,
    #[serde(default)]
    trusted_sha256: Vec<String>,
    #[serde(default)]
    signatures: Vec<SignatureSpec>,
}

impl Default for ExecSpec {
    fn default() -> Self {
        ExecSpec {
            mode: ExecMode::Enforce,
            watch: vec![],
            max_scan_bytes: default_scan(),
            on_scan_error: ScanErrorAction::Deny,
            trusted_sha256: vec![],
            signatures: vec![],
        }
    }
}

fn default_scan() -> String {
    "64M".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureSpec {
    id: String,
    text: Option<String>,
    hex: Option<String>,
    #[serde(default)]
    description: String,
}

// ------------------------------------------------------------------ plan --

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PressureAction {
    #[default]
    Log,
    Freeze,
    Kill,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PsiKind {
    #[default]
    Some,
    Full,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecMode {
    #[default]
    Enforce,
    Audit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanErrorAction {
    #[default]
    Deny,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PortRule {
    pub proto: u8,
    pub port: u16,
}

impl fmt::Display for PortRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = if self.proto == IPPROTO_TCP { "tcp" } else { "udp" };
        write!(f, "{p}/{}", self.port)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPlan {
    #[serde(with = "prefixes")]
    pub allow: Vec<Prefix>,
    #[serde(with = "prefixes")]
    pub deny: Vec<Prefix>,
    pub deny_ports: Vec<PortRule>,
    pub drop_malformed: bool,
    pub drop_fragments: bool,
}

impl NetworkPlan {
    pub fn flags(&self) -> Flags {
        Flags { drop_malformed: self.drop_malformed, drop_fragments: self.drop_fragments }
    }
}

impl Rules for NetworkPlan {
    fn src_allowed(&self, ip: u32) -> bool {
        self.allow.iter().any(|p| p.contains(ip))
    }
    fn src_denied(&self, ip: u32) -> bool {
        self.deny.iter().any(|p| p.contains(ip))
    }
    fn port_denied(&self, proto: u8, port: u16) -> bool {
        self.deny_ports.binary_search(&PortRule { proto, port }).is_ok()
    }
    fn flags(&self) -> Flags {
        NetworkPlan::flags(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsiPlan {
    pub kind: PsiKind,
    pub stall_us: u64,
    pub window_us: u64,
}

impl PsiPlan {
    /// The exact line written to `memory.pressure` to arm a trigger.
    pub fn trigger_line(&self) -> String {
        let k = match self.kind {
            PsiKind::Some => "some",
            PsiKind::Full => "full",
        };
        format!("{k} {} {}", self.stall_us, self.window_us)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPlan {
    pub name: String,
    /// `None` means "max".
    pub memory_max: Option<u64>,
    pub memory_high: Option<u64>,
    pub swap_max: Option<u64>,
    pub pids_max: Option<u64>,
    pub oom_group: bool,
    pub cpu_weight: Option<u64>,
    pub psi: Option<PsiPlan>,
    pub on_pressure: PressureAction,
    pub expose: Vec<PortRule>,
    pub gpu_devices: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    #[serde(with = "hexbytes")]
    pub bytes: Vec<u8>,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPlan {
    pub mode: ExecMode,
    pub watch: Vec<String>,
    pub max_scan_bytes: u64,
    pub on_scan_error: ScanErrorAction,
    pub trusted_sha256: Vec<String>,
    pub signatures: Vec<Signature>,
}

impl ExecPlan {
    pub fn is_trusted(&self, sha256_hex: &str) -> bool {
        self.trusted_sha256.binary_search_by(|h| h.as_str().cmp(sha256_hex)).is_ok()
    }
}

/// The compiled, canonical form of a policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub name: String,
    pub generation: u64,
    pub network: NetworkPlan,
    pub workloads: Vec<WorkloadPlan>,
    pub exec: ExecPlan,
}

impl Plan {
    /// SHA-256 of the canonical JSON encoding. Two policy files that differ
    /// only in ordering, duplicates, host bits or comments share it.
    pub fn fingerprint(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("plan serialises");
        Sha256::digest(&json).into()
    }
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }
    /// First 8 bytes, the form stored in the XDP config map.
    pub fn fingerprint_u64(&self) -> u64 {
        let f = self.fingerprint();
        u64::from_be_bytes(f[..8].try_into().unwrap())
    }
    pub fn workload(&self, name: &str) -> Option<&WorkloadPlan> {
        self.workloads.iter().find(|w| w.name == name)
    }
}

// ----------------------------------------------------------- diagnostics --

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{s}[{}] {}: {}", self.code, self.path, self.message)
    }
}

#[derive(Default)]
struct Diags(Vec<Diagnostic>);

impl Diags {
    fn err(&mut self, code: &'static str, path: impl Into<String>, msg: impl Into<String>) {
        self.0.push(Diagnostic { severity: Severity::Error, code, path: path.into(), message: msg.into() });
    }
    fn warn(&mut self, code: &'static str, path: impl Into<String>, msg: impl Into<String>) {
        self.0.push(Diagnostic { severity: Severity::Warning, code, path: path.into(), message: msg.into() });
    }
    fn has_errors(&self) -> bool {
        self.0.iter().any(|d| d.severity == Severity::Error)
    }
}

/// Result of a successful compilation: the plan plus any warnings.
#[derive(Debug)]
pub struct Compiled {
    pub plan: Plan,
    pub warnings: Vec<Diagnostic>,
}

/// Compile a policy. On failure every diagnostic found is returned, not
/// just the first one.
pub fn compile(src: &str) -> Result<Compiled, Vec<Diagnostic>> {
    let file: PolicyFile = toml::from_str(src).map_err(|e| {
        vec![Diagnostic {
            severity: Severity::Error,
            code: "C9E000",
            path: "<toml>".into(),
            message: e.to_string(),
        }]
    })?;
    let mut d = Diags::default();
    let network = compile_network(&file.network, &mut d);
    let workloads = compile_workloads(&file.workloads, &mut d);
    let exec = compile_exec(&file.exec, &mut d);
    cross_check(&network, &workloads, &mut d);
    if d.has_errors() {
        return Err(d.0);
    }
    Ok(Compiled {
        plan: Plan { name: file.meta.name, generation: file.meta.generation, network, workloads, exec },
        warnings: d.0,
    })
}

pub fn parse_cidr(s: &str) -> Result<Prefix, String> {
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip, len.parse::<u8>().map_err(|_| format!("bad prefix length in {s:?}"))?),
        None => (s, 32),
    };
    let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("bad IPv4 address in {s:?}"))?;
    Prefix::new(u32::from(addr), len).ok_or_else(|| format!("prefix length > 32 in {s:?}"))
}

pub fn format_prefix(p: &Prefix) -> String {
    format!("{}/{}", std::net::Ipv4Addr::from(p.addr()), p.len())
}

pub fn parse_port(s: &str) -> Result<PortRule, String> {
    let (proto, port) = s.split_once('/').ok_or_else(|| format!("expected tcp/N or udp/N, got {s:?}"))?;
    let proto = match proto {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        _ => return Err(format!("unknown protocol in {s:?}")),
    };
    let port = port.parse::<u16>().map_err(|_| format!("bad port in {s:?}"))?;
    Ok(PortRule { proto, port })
}

/// Parses `512M`, `2G`, `1048576`, `64K`; `max` returns `None`.
pub fn parse_size(s: &str) -> Result<Option<u64>, String> {
    let t = s.trim();
    if t == "max" {
        return Ok(None);
    }
    let (num, mul) = match t.chars().last() {
        Some('K') | Some('k') => (&t[..t.len() - 1], 1u64 << 10),
        Some('M') | Some('m') => (&t[..t.len() - 1], 1 << 20),
        Some('G') | Some('g') => (&t[..t.len() - 1], 1 << 30),
        _ => (t, 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("bad size {s:?}"))?;
    n.checked_mul(mul).map(Some).ok_or_else(|| format!("size overflows u64: {s:?}"))
}

fn compile_prefixes(list: &[String], path: &str, d: &mut Diags) -> Vec<Prefix> {
    let mut out: Vec<Prefix> = list
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match parse_cidr(s) {
            Ok(p) => Some(p),
            Err(e) => {
                d.err("C9E001", format!("{path}[{i}]"), e);
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn compile_network(n: &NetworkSpec, d: &mut Diags) -> NetworkPlan {
    let allow = compile_prefixes(&n.allow_src, "network.allow_src", d);
    let deny = compile_prefixes(&n.deny_src, "network.deny_src", d);
    let mut deny_ports: Vec<PortRule> = n
        .deny_dst_ports
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match parse_port(s) {
            Ok(p) => Some(p),
            Err(e) => {
                d.err("C9E001", format!("network.deny_dst_ports[{i}]"), e);
                None
            }
        })
        .collect();
    deny_ports.sort();
    deny_ports.dedup();

    if allow.len() > XDP_MAX_PREFIXES || deny.len() > XDP_MAX_PREFIXES {
        d.err("C9E007", "network", format!("more than {XDP_MAX_PREFIXES} prefixes do not fit the XDP LPM tries"));
    }
    if deny_ports.len() > XDP_MAX_PORTS {
        d.err("C9E007", "network.deny_dst_ports", format!("more than {XDP_MAX_PORTS} ports do not fit the XDP map"));
    }
    for p in &deny {
        if let Some(a) = allow.iter().find(|a| a.covers(*p)) {
            d.warn(
                "C9W101",
                "network.deny_src",
                format!("{} can never match: allow_src {} covers it", format_prefix(p), format_prefix(a)),
            );
        } else if let Some(o) = deny.iter().find(|o| *o != p && o.covers(*p)) {
            d.warn("C9W102", "network.deny_src", format!("{} is redundant with {}", format_prefix(p), format_prefix(o)));
        }
    }
    NetworkPlan { allow, deny, deny_ports, drop_malformed: n.drop_malformed, drop_fragments: n.drop_fragments }
}

fn compile_workloads(ws: &[WorkloadSpec], d: &mut Diags) -> Vec<WorkloadPlan> {
    let mut out = Vec::new();
    for (i, w) in ws.iter().enumerate() {
        let path = format!("workload[{i}]");
        if w.name.is_empty() || !w.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            d.err("C9E010", format!("{path}.name"), "name must be [A-Za-z0-9_-]+ (it becomes a cgroup directory)");
        }
        if ws[..i].iter().any(|o| o.name == w.name) {
            d.err("C9E005", format!("{path}.name"), format!("duplicate workload {:?}", w.name));
        }
        let size = |s: &str, field: &str, d: &mut Diags| match parse_size(s) {
            Ok(v) => v,
            Err(e) => {
                d.err("C9E001", format!("{path}.{field}"), e);
                None
            }
        };
        let memory_max = size(&w.memory_max, "memory_max", d);
        let memory_high = w.memory_high.as_deref().and_then(|s| size(s, "memory_high", d));
        let swap_max = size(&w.swap_max, "swap_max", d);
        if let (Some(h), Some(m)) = (memory_high, memory_max) {
            if h > m {
                d.err("C9E003", format!("{path}.memory_high"), "memory_high above memory_max never throttles");
            }
        }
        let psi = w.psi.as_ref().map(|p| PsiPlan { kind: p.kind, stall_us: p.stall_ms * 1000, window_us: p.window_ms * 1000 });
        if let Some(p) = &psi {
            // Kernel bounds (Documentation/accounting/psi.rst): 500ms..10s window.
            if !(500_000..=10_000_000).contains(&p.window_us) || p.stall_us == 0 || p.stall_us > p.window_us {
                d.err("C9E009", format!("{path}.psi"), "window must be 500..10000 ms and 0 < stall <= window");
            }
        }
        if w.on_pressure != PressureAction::Log && psi.is_none() {
            d.err("C9E011", format!("{path}.on_pressure"), "freeze/kill on pressure needs a psi trigger");
        }
        let mut expose: Vec<PortRule> = w
            .expose
            .iter()
            .filter_map(|s| match parse_port(s) {
                Ok(p) => Some(p),
                Err(e) => {
                    d.err("C9E001", format!("{path}.expose"), e);
                    None
                }
            })
            .collect();
        expose.sort();
        expose.dedup();
        if !w.gpu_devices.is_empty() {
            d.warn(
                "C9W105",
                format!("{path}.gpu_devices"),
                "GPU device isolation is a design in docs/gpu.md; it is not enforced or tested",
            );
        }
        out.push(WorkloadPlan {
            name: w.name.clone(),
            memory_max,
            memory_high,
            swap_max,
            pids_max: w.pids_max,
            oom_group: w.oom_group,
            cpu_weight: w.cpu_weight,
            psi,
            on_pressure: w.on_pressure,
            expose,
            gpu_devices: w.gpu_devices.clone(),
        });
    }
    out
}

fn compile_exec(e: &ExecSpec, d: &mut Diags) -> ExecPlan {
    for (i, w) in e.watch.iter().enumerate() {
        if !w.starts_with('/') {
            d.err("C9E006", format!("exec.watch[{i}]"), "watch paths must be absolute");
        }
    }
    let max_scan_bytes = match parse_size(&e.max_scan_bytes) {
        Ok(Some(v)) => v,
        Ok(None) => u64::MAX,
        Err(m) => {
            d.err("C9E001", "exec.max_scan_bytes", m);
            0
        }
    };
    let mut trusted = Vec::new();
    for (i, h) in e.trusted_sha256.iter().enumerate() {
        let h = h.to_ascii_lowercase();
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            d.err("C9E008", format!("exec.trusted_sha256[{i}]"), "expected 64 hex digits");
        } else {
            trusted.push(h);
        }
    }
    trusted.sort();
    trusted.dedup();
    let mut sigs: Vec<Signature> = Vec::new();
    for (i, s) in e.signatures.iter().enumerate() {
        let path = format!("exec.signatures[{i}]");
        let bytes = match (&s.text, &s.hex) {
            (Some(t), None) => t.as_bytes().to_vec(),
            (None, Some(h)) => match hex::decode(h.replace(' ', "")) {
                Ok(b) => b,
                Err(_) => {
                    d.err("C9E001", &path, "invalid hex");
                    continue;
                }
            },
            _ => {
                d.err("C9E001", &path, "exactly one of text or hex is required");
                continue;
            }
        };
        if bytes.len() < MIN_SIGNATURE_LEN {
            d.err("C9E004", &path, format!("signatures shorter than {MIN_SIGNATURE_LEN} bytes cause false positives"));
        }
        if sigs.iter().any(|o| o.id == s.id) {
            d.err("C9E005", &path, format!("duplicate signature id {:?}", s.id));
        }
        sigs.push(Signature { id: s.id.clone(), bytes, description: s.description.clone() });
    }
    sigs.sort_by(|a, b| a.id.cmp(&b.id));
    let mut watch = e.watch.clone();
    watch.sort();
    watch.dedup();
    ExecPlan { mode: e.mode, watch, max_scan_bytes, on_scan_error: e.on_scan_error, trusted_sha256: trusted, signatures: sigs }
}

/// Contradictions that only appear when the pillars are looked at together.
fn cross_check(net: &NetworkPlan, ws: &[WorkloadPlan], d: &mut Diags) {
    for (i, w) in ws.iter().enumerate() {
        for p in &w.expose {
            if net.deny_ports.binary_search(p).is_ok() {
                d.err(
                    "C9E002",
                    format!("workload[{i}].expose"),
                    format!("workload {:?} exposes {p} but network.deny_dst_ports drops it at XDP", w.name),
                );
            }
        }
    }
}

mod prefixes {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[Prefix], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(format_prefix))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Prefix>, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        v.iter().map(|s| parse_cidr(s).map_err(serde::de::Error::custom)).collect()
    }
}

mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
