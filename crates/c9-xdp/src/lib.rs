// SPDX-License-Identifier: Apache-2.0
//! `c9-xdp`: loads the cortex9 XDP firewall and keeps its BPF maps in sync
//! with a compiled policy.
//!
//! Reloads never touch the program. Rules are double-buffered in two epochs
//! of maps: [`Maps::apply`] rewrites the inactive epoch to match the plan and
//! then flips a one-word selector that the program reads once per packet.

use anyhow::{bail, Context, Result};
use aya::maps::{lpm_trie::Key, Array, HashMap, LpmTrie, Map, MapData, PerCpuArray};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader, Pod};
use c9_classify::{Prefix, REASON_COUNT};
use c9_policy::{NetworkPlan, Plan};
use std::collections::BTreeSet;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/cortex9";
pub const PROGRAM: &str = "c9_xdp";

/// The verified object file, embedded at build time.
pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_fw.o"));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Epoch {
    pub flags: u32,
    pub reserved: u32,
    pub generation: u64,
    pub fingerprint: u64,
}

// SAFETY: plain old data with no padding (u32, u32, u64, u64), matches `struct c9_epoch`.
unsafe impl Pod for Epoch {}

type Lpm = LpmTrie<MapData, u32, u8>;
type Ports = HashMap<MapData, u32, u8>;

/// Owned handles on every map of the program, either taken from a freshly
/// loaded object or reopened from bpffs pins by another process.
pub struct Maps {
    allow: [Lpm; 2],
    deny: [Lpm; 2],
    ports: [Ports; 2],
    epoch: Array<MapData, Epoch>,
    active: Array<MapData, u32>,
    stats: PerCpuArray<MapData, u64>,
}

const MAP_NAMES: [&str; 9] = [
    "c9_allow_0",
    "c9_allow_1",
    "c9_deny_0",
    "c9_deny_1",
    "c9_ports_0",
    "c9_ports_1",
    "c9_epoch",
    "c9_active",
    "c9_stats",
];

/// What a reload did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub epoch: u32,
    pub inserted: usize,
    pub removed: usize,
    pub elapsed: Duration,
}

fn port_key(proto: u8, port: u16) -> u32 {
    ((proto as u32) << 16) | port as u32
}

fn sync_lpm(map: &mut Lpm, want: &[Prefix]) -> Result<(usize, usize)> {
    let want: BTreeSet<(u32, u32)> = want
        .iter()
        .map(|p| (p.prefix_len() as u32, p.addr().to_be()))
        .collect();
    let mut have = BTreeSet::new();
    for k in map.keys() {
        let k = k?;
        have.insert((k.prefix_len(), k.data()));
    }
    let mut ins = 0;
    for &(len, addr) in want.difference(&have) {
        map.insert(&Key::new(len, addr), 1, 0)?;
        ins += 1;
    }
    let mut rem = 0;
    for &(len, addr) in have.difference(&want) {
        map.remove(&Key::new(len, addr))?;
        rem += 1;
    }
    Ok((ins, rem))
}

fn sync_ports(map: &mut Ports, net: &NetworkPlan) -> Result<(usize, usize)> {
    let want: BTreeSet<u32> = net
        .deny_ports
        .iter()
        .map(|p| port_key(p.proto, p.port))
        .collect();
    let have: BTreeSet<u32> = map.keys().collect::<Result<_, _>>()?;
    let mut ins = 0;
    for k in want.difference(&have) {
        map.insert(k, 1, 0)?;
        ins += 1;
    }
    let mut rem = 0;
    for k in have.difference(&want) {
        map.remove(k)?;
        rem += 1;
    }
    Ok((ins, rem))
}

impl Maps {
    fn from_maps(mut get: impl FnMut(&str) -> Result<Map>) -> Result<Maps> {
        let mut lpm = |n: &str| -> Result<Lpm> { Ok(Lpm::try_from(get(n)?)?) };
        let allow = [lpm("c9_allow_0")?, lpm("c9_allow_1")?];
        let deny = [lpm("c9_deny_0")?, lpm("c9_deny_1")?];
        let ports = [
            Ports::try_from(get("c9_ports_0")?)?,
            Ports::try_from(get("c9_ports_1")?)?,
        ];
        Ok(Maps {
            allow,
            deny,
            ports,
            epoch: Array::try_from(get("c9_epoch")?)?,
            active: Array::try_from(get("c9_active")?)?,
            stats: PerCpuArray::try_from(get("c9_stats")?)?,
        })
    }

    /// Reopen the maps pinned by a running firewall.
    pub fn from_pins(dir: &Path) -> Result<Maps> {
        Maps::from_maps(|name| {
            let path = dir.join(name);
            let data = MapData::from_pin(&path)
                .with_context(|| format!("open pinned map {}", path.display()))?;
            Ok(match name {
                n if n.starts_with("c9_allow") || n.starts_with("c9_deny") => Map::LpmTrie(data),
                n if n.starts_with("c9_ports") => Map::HashMap(data),
                "c9_stats" => Map::PerCpuArray(data),
                _ => Map::Array(data),
            })
        })
    }

    pub fn active_epoch(&self) -> Result<u32> {
        Ok(self.active.get(&0, 0)? & 1)
    }

    pub fn epoch_info(&self, e: u32) -> Result<Epoch> {
        Ok(self.epoch.get(&(e & 1), 0)?)
    }

    /// Make the inactive epoch equal to `plan`, then switch to it.
    pub fn apply(&mut self, plan: &Plan) -> Result<ApplyReport> {
        let t0 = Instant::now();
        let target = 1 - self.active_epoch()?;
        let i = target as usize;
        let net = &plan.network;
        let (a_i, a_r) = sync_lpm(&mut self.allow[i], &net.allow)?;
        let (d_i, d_r) = sync_lpm(&mut self.deny[i], &net.deny)?;
        let (p_i, p_r) = sync_ports(&mut self.ports[i], net)?;
        let ep = Epoch {
            flags: net.flags().to_bits(),
            reserved: 0,
            generation: plan.generation,
            fingerprint: plan.fingerprint_u64(),
        };
        self.epoch.set(target, ep, 0)?;
        self.active.set(0, target, 0)?;
        Ok(ApplyReport {
            epoch: target,
            inserted: a_i + d_i + p_i,
            removed: a_r + d_r + p_r,
            elapsed: t0.elapsed(),
        })
    }

    /// Per-reason packet counters summed over CPUs.
    pub fn stats(&self) -> Result<[u64; REASON_COUNT]> {
        let mut out = [0u64; REASON_COUNT];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.stats.get(&(i as u32), 0)?.iter().sum();
        }
        Ok(out)
    }
}

/// A loaded (and optionally attached) firewall.
pub struct Firewall {
    ebpf: Ebpf,
    pub maps: Maps,
    pin_dir: Option<PathBuf>,
}

/// Result of one BPF_PROG_TEST_RUN.
#[derive(Clone, Copy, Debug)]
pub struct TestRun {
    pub retval: u32,
    /// Average kernel-measured time per run, nanoseconds.
    pub duration_ns: u32,
}

pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;

impl Firewall {
    /// Load and verify the program. With `pin_dir`, maps are pinned there
    /// (reused if already pinned) so `cortex9 xdp reload` can update them.
    pub fn load(pin_dir: Option<&Path>) -> Result<Firewall> {
        let mut loader = EbpfLoader::new();
        if let Some(d) = pin_dir {
            std::fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
            loader.default_map_pin_directory(d);
        }
        let mut ebpf = loader
            .load(OBJECT)
            .context("load BPF object (needs CAP_BPF / root)")?;
        let prog: &mut Xdp = ebpf
            .program_mut(PROGRAM)
            .context("program missing")?
            .try_into()?;
        prog.load().context("verifier rejected the XDP program")?;
        let maps =
            Maps::from_maps(|n| ebpf.take_map(n).with_context(|| format!("map {n} missing")))?;
        Ok(Firewall {
            ebpf,
            maps,
            pin_dir: pin_dir.map(Path::to_path_buf),
        })
    }

    fn prog(&self) -> Result<&Xdp> {
        Ok(self
            .ebpf
            .program(PROGRAM)
            .context("program missing")?
            .try_into()?)
    }

    pub fn attach(&mut self, iface: &str, skb_mode: bool) -> Result<()> {
        let prog: &mut Xdp = self
            .ebpf
            .program_mut(PROGRAM)
            .context("program missing")?
            .try_into()?;
        let mode = if skb_mode {
            XdpMode::Skb
        } else {
            XdpMode::Driver
        };
        prog.attach(iface, mode)
            .with_context(|| format!("attach XDP to {iface} ({mode:?})"))?;
        Ok(())
    }

    /// Kernel id of the loaded program; unchanged across reloads.
    pub fn program_id(&self) -> Result<u32> {
        Ok(self.prog()?.info()?.id())
    }

    pub fn pin_dir(&self) -> Option<&Path> {
        self.pin_dir.as_deref()
    }

    /// Run the program on one frame inside the kernel (BPF_PROG_TEST_RUN).
    pub fn test_run(&self, frame: &[u8], repeat: u32) -> Result<TestRun> {
        let fd = self.prog()?.fd()?.as_fd().as_raw_fd();
        prog_test_run(fd, frame, repeat)
    }
}

/// Remove the pins left by `Firewall::load`.
pub fn unpin(dir: &Path) -> Result<()> {
    for n in MAP_NAMES {
        let p = dir.join(n);
        if p.exists() {
            std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
        }
    }
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

#[repr(C)]
#[derive(Default)]
struct TestAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

const BPF_PROG_TEST_RUN: libc::c_long = 10;

fn prog_test_run(fd: i32, frame: &[u8], repeat: u32) -> Result<TestRun> {
    if frame.len() < c9_classify::ETH_HLEN {
        bail!("BPF_PROG_TEST_RUN needs at least an Ethernet header");
    }
    let mut attr = TestAttr {
        prog_fd: fd as u32,
        data_size_in: frame.len() as u32,
        data_in: frame.as_ptr() as u64,
        repeat,
        ..Default::default()
    };
    // SAFETY: `attr` is a valid, fully initialised bpf_attr prefix for this
    // command; the kernel only reads `frame` (data_out is NULL).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &mut attr as *mut TestAttr,
            std::mem::size_of::<TestAttr>(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_PROG_TEST_RUN");
    }
    Ok(TestRun {
        retval: attr.retval,
        duration_ns: attr.duration,
    })
}

/// Outcome of running the kernel program and the Rust engine on one corpus.
#[derive(Clone, Debug, Default)]
pub struct DiffReport {
    pub frames: usize,
    pub compared: usize,
    pub agree: usize,
    /// Frames shorter than an Ethernet header: the kernel refuses to test-run them.
    pub skipped_short: usize,
    pub histogram: [usize; REASON_COUNT],
    pub first_mismatch: Option<(Vec<u8>, u32, u32)>,
}

/// Differential test: every frame goes through BPF_PROG_TEST_RUN and through
/// `c9_classify::classify` with the same plan; the reason observed in the
/// kernel (via the per-reason counters) must equal the Rust one.
pub fn differential(fw: &Firewall, plan: &Plan, frames: &[Vec<u8>]) -> Result<DiffReport> {
    let mut r = DiffReport {
        frames: frames.len(),
        ..Default::default()
    };
    let mut before = fw.maps.stats()?;
    for f in frames {
        if f.len() < c9_classify::ETH_HLEN {
            r.skipped_short += 1;
            continue;
        }
        let run = fw.test_run(f, 1)?;
        let after = fw.maps.stats()?;
        let moved: Vec<usize> = (0..REASON_COUNT)
            .filter(|&i| after[i] != before[i])
            .collect();
        before = after;
        let want = c9_classify::classify(f, &plan.network);
        r.compared += 1;
        r.histogram[want as usize] += 1;
        let got = match moved.as_slice() {
            [one] => *one as u32,
            _ => u32::MAX,
        };
        let ret_ok = run.retval == if want.is_drop() { XDP_DROP } else { XDP_PASS };
        if got == want as u32 && ret_ok {
            r.agree += 1;
        } else if r.first_mismatch.is_none() {
            r.first_mismatch = Some((f.clone(), want as u32, got));
        }
    }
    Ok(r)
}
