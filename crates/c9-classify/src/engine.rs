// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
//! Packet classification engine.
//!
//! This file depends on `core` only. It is compiled three ways:
//! * as part of the `c9-classify` crate (userspace tests, CLI, XDP oracle);
//! * verbatim inside the Rust-for-Linux module in `kernel/` via `#[path]`;
//! * under Miri in CI.
//!
//! The decision procedure is mirrored line by line by `bpf/xdp_fw.bpf.c`.
//! Any change here must be reflected there; the differential test in
//! `c9-xdp` runs both on the same packets and fails on the first mismatch.

pub const ETH_HLEN: usize = 14;
pub const VLAN_HLEN: usize = 4;
pub const IPV4_MIN_HLEN: usize = 20;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88A8;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Why a packet got its verdict. The numeric values are ABI: they index the
/// per-CPU statistics array of the XDP program.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Reason {
    PassNotIpv4 = 0,
    PassAllowSrc = 1,
    PassDefault = 2,
    DropDenySrc = 3,
    DropDenyPort = 4,
    DropMalformed = 5,
    DropFragment = 6,
    PassMalformed = 7,
    PassFragment = 8,
}

pub const REASON_COUNT: usize = 9;

pub const ALL_REASONS: [Reason; REASON_COUNT] = [
    Reason::PassNotIpv4,
    Reason::PassAllowSrc,
    Reason::PassDefault,
    Reason::DropDenySrc,
    Reason::DropDenyPort,
    Reason::DropMalformed,
    Reason::DropFragment,
    Reason::PassMalformed,
    Reason::PassFragment,
];

impl Reason {
    pub const fn is_drop(self) -> bool {
        matches!(
            self,
            Reason::DropDenySrc
                | Reason::DropDenyPort
                | Reason::DropMalformed
                | Reason::DropFragment
        )
    }

    pub const fn from_u32(v: u32) -> Option<Reason> {
        if (v as usize) < REASON_COUNT {
            Some(ALL_REASONS[v as usize])
        } else {
            None
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Reason::PassNotIpv4 => "pass_not_ipv4",
            Reason::PassAllowSrc => "pass_allow_src",
            Reason::PassDefault => "pass_default",
            Reason::DropDenySrc => "drop_deny_src",
            Reason::DropDenyPort => "drop_deny_port",
            Reason::DropMalformed => "drop_malformed",
            Reason::DropFragment => "drop_fragment",
            Reason::PassMalformed => "pass_malformed",
            Reason::PassFragment => "pass_fragment",
        }
    }
}

/// Behaviour switches that come from the policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub drop_malformed: bool,
    pub drop_fragments: bool,
}

impl Flags {
    pub const fn to_bits(self) -> u32 {
        (self.drop_malformed as u32) | ((self.drop_fragments as u32) << 1)
    }
    pub const fn from_bits(b: u32) -> Flags {
        Flags {
            drop_malformed: b & 1 != 0,
            drop_fragments: b & 2 != 0,
        }
    }
}

/// An IPv4 prefix with host bits cleared at construction, so two prefixes
/// that cover the same set always compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    addr: u32,
    len: u8,
}

impl Prefix {
    /// Returns `None` when `len > 32`.
    pub const fn new(addr: u32, len: u8) -> Option<Prefix> {
        if len > 32 {
            return None;
        }
        Some(Prefix {
            addr: addr & mask(len),
            len,
        })
    }
    pub const fn addr(self) -> u32 {
        self.addr
    }
    pub const fn prefix_len(self) -> u8 {
        self.len
    }
    pub const fn contains(self, ip: u32) -> bool {
        ip & mask(self.len) == self.addr
    }
    /// True when every address of `other` is also in `self`.
    pub const fn covers(self, other: Prefix) -> bool {
        self.len <= other.len && self.contains(other.addr)
    }
}

const fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    }
}

/// Rule storage. Implemented by fixed-capacity arrays (kernel, no alloc),
/// by the compiled policy (userspace), and conceptually by BPF maps.
pub trait Rules {
    fn src_allowed(&self, ip: u32) -> bool;
    fn src_denied(&self, ip: u32) -> bool;
    fn port_denied(&self, proto: u8, port: u16) -> bool;
    fn flags(&self) -> Flags;
}

#[inline]
fn be16(p: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    match p.get(off..end) {
        Some(&[a, b]) => Some(u16::from_be_bytes([a, b])),
        _ => None,
    }
}

#[inline]
fn be32(p: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    match p.get(off..end) {
        Some(&[a, b, c, d]) => Some(u32::from_be_bytes([a, b, c, d])),
        _ => None,
    }
}

/// Classify one Ethernet frame. Total function: never panics, never reads
/// outside `pkt`, never allocates.
pub fn classify<R: Rules + ?Sized>(pkt: &[u8], rules: &R) -> Reason {
    let flags = rules.flags();
    let malformed = if flags.drop_malformed {
        Reason::DropMalformed
    } else {
        Reason::PassMalformed
    };

    let mut l3 = ETH_HLEN;
    let mut ethertype = match be16(pkt, 12) {
        Some(t) => t,
        None => return Reason::PassNotIpv4,
    };
    if ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD {
        ethertype = match be16(pkt, ETH_HLEN + 2) {
            Some(t) => t,
            None => return Reason::PassNotIpv4,
        };
        l3 = ETH_HLEN + VLAN_HLEN;
    }
    if ethertype != ETH_P_IP {
        return Reason::PassNotIpv4;
    }

    let ip = match pkt.get(l3..) {
        Some(ip) if ip.len() >= IPV4_MIN_HLEN => ip,
        _ => return malformed,
    };
    let vihl = ip[0];
    if vihl >> 4 != 4 {
        return malformed;
    }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HLEN || ip.len() < ihl {
        return malformed;
    }
    let tot_len = match be16(ip, 2) {
        Some(v) => v as usize,
        None => return malformed,
    };
    if tot_len < ihl {
        return malformed;
    }
    let src = match be32(ip, 12) {
        Some(v) => v,
        None => return malformed,
    };

    if rules.src_allowed(src) {
        return Reason::PassAllowSrc;
    }
    if rules.src_denied(src) {
        return Reason::DropDenySrc;
    }

    let frag = match be16(ip, 6) {
        Some(v) => v,
        None => return malformed,
    };
    let offset = frag & 0x1fff;
    let more = frag & 0x2000 != 0;
    if offset != 0 {
        // Non-first fragment: carries no L4 header.
        return if flags.drop_fragments {
            Reason::DropFragment
        } else {
            Reason::PassFragment
        };
    }
    if more && flags.drop_fragments {
        return Reason::DropFragment;
    }

    let proto = ip[9];
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        // Tiny first fragments that hide the port are malformed by design.
        let dport = match be16(ip, ihl + 2) {
            Some(p) => p,
            None => return malformed,
        };
        if rules.port_denied(proto, dport) {
            return Reason::DropDenyPort;
        }
    }
    Reason::PassDefault
}

/// Fixed-capacity rule table: no allocation, usable in the kernel.
pub struct StaticRules<const N: usize> {
    allow: [Prefix; N],
    n_allow: usize,
    deny: [Prefix; N],
    n_deny: usize,
    ports: [(u8, u16); N],
    n_ports: usize,
    flags: Flags,
}

/// Error returned when a fixed table is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

impl<const N: usize> StaticRules<N> {
    pub const fn new(flags: Flags) -> Self {
        const Z: Prefix = Prefix { addr: 0, len: 0 };
        StaticRules {
            allow: [Z; N],
            n_allow: 0,
            deny: [Z; N],
            n_deny: 0,
            ports: [(0, 0); N],
            n_ports: 0,
            flags,
        }
    }
    pub fn allow(&mut self, p: Prefix) -> Result<(), Full> {
        let slot = self.allow.get_mut(self.n_allow).ok_or(Full)?;
        *slot = p;
        self.n_allow += 1;
        Ok(())
    }
    pub fn deny(&mut self, p: Prefix) -> Result<(), Full> {
        let slot = self.deny.get_mut(self.n_deny).ok_or(Full)?;
        *slot = p;
        self.n_deny += 1;
        Ok(())
    }
    pub fn deny_port(&mut self, proto: u8, port: u16) -> Result<(), Full> {
        let slot = self.ports.get_mut(self.n_ports).ok_or(Full)?;
        *slot = (proto, port);
        self.n_ports += 1;
        Ok(())
    }
}

impl<const N: usize> Rules for StaticRules<N> {
    fn src_allowed(&self, ip: u32) -> bool {
        self.allow[..self.n_allow].iter().any(|p| p.contains(ip))
    }
    fn src_denied(&self, ip: u32) -> bool {
        self.deny[..self.n_deny].iter().any(|p| p.contains(ip))
    }
    fn port_denied(&self, proto: u8, port: u16) -> bool {
        self.ports[..self.n_ports]
            .iter()
            .any(|&(pr, po)| pr == proto && po == port)
    }
    fn flags(&self) -> Flags {
        self.flags
    }
}

/// Self-test vectors shared by the unit tests and the kernel module's
/// init-time self check. Each entry: (description, frame, flags, expected).
pub mod vectors {
    use super::*;

    pub const DENY_SRC: u32 = 0xCB00_7100; // 203.0.113.0/24
    pub const ALLOW_SRC: u32 = 0xCB00_7180; // 203.0.113.128/25 punches a hole
    pub const DENY_PORT: u16 = 23;

    pub fn rules(flags: Flags) -> StaticRules<4> {
        let mut r = StaticRules::new(flags);
        // Capacity 4 is enough; these cannot fail.
        let _ = r.deny(Prefix {
            addr: DENY_SRC,
            len: 24,
        });
        let _ = r.allow(Prefix {
            addr: ALLOW_SRC,
            len: 25,
        });
        let _ = r.deny_port(IPPROTO_TCP, DENY_PORT);
        r
    }

    /// Writes a minimal Ethernet+IPv4+L4 frame into `buf`, returns its length.
    pub fn frame(buf: &mut [u8; 64], src: u32, proto: u8, dport: u16, frag: u16) -> usize {
        *buf = [0u8; 64];
        buf[12] = 0x08;
        buf[13] = 0x00;
        let ip = ETH_HLEN;
        buf[ip] = 0x45;
        let tot = (IPV4_MIN_HLEN + 8) as u16;
        buf[ip + 2..ip + 4].copy_from_slice(&tot.to_be_bytes());
        buf[ip + 6..ip + 8].copy_from_slice(&frag.to_be_bytes());
        buf[ip + 8] = 64;
        buf[ip + 9] = proto;
        buf[ip + 12..ip + 16].copy_from_slice(&src.to_be_bytes());
        buf[ip + 16..ip + 20].copy_from_slice(&0x0A00_0001u32.to_be_bytes());
        let l4 = ip + IPV4_MIN_HLEN;
        buf[l4..l4 + 2].copy_from_slice(&40000u16.to_be_bytes());
        buf[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
        l4 + 8
    }

    pub struct Case {
        pub name: &'static str,
        pub src: u32,
        pub proto: u8,
        pub dport: u16,
        pub frag: u16,
        pub truncate_to: usize,
        pub expect: Reason,
    }

    pub const CASES: [Case; 8] = [
        Case {
            name: "deny-src",
            src: DENY_SRC | 7,
            proto: IPPROTO_UDP,
            dport: 53,
            frag: 0,
            truncate_to: 0,
            expect: Reason::DropDenySrc,
        },
        Case {
            name: "allow-hole",
            src: ALLOW_SRC | 9,
            proto: IPPROTO_TCP,
            dport: DENY_PORT,
            frag: 0,
            truncate_to: 0,
            expect: Reason::PassAllowSrc,
        },
        Case {
            name: "deny-port",
            src: 0x0A00_0002,
            proto: IPPROTO_TCP,
            dport: DENY_PORT,
            frag: 0,
            truncate_to: 0,
            expect: Reason::DropDenyPort,
        },
        Case {
            name: "udp-same-port",
            src: 0x0A00_0002,
            proto: IPPROTO_UDP,
            dport: DENY_PORT,
            frag: 0,
            truncate_to: 0,
            expect: Reason::PassDefault,
        },
        Case {
            name: "default",
            src: 0x0A00_0002,
            proto: IPPROTO_TCP,
            dport: 443,
            frag: 0,
            truncate_to: 0,
            expect: Reason::PassDefault,
        },
        Case {
            name: "non-first-fragment",
            src: 0x0A00_0002,
            proto: IPPROTO_TCP,
            dport: DENY_PORT,
            frag: 0x0010,
            truncate_to: 0,
            expect: Reason::DropFragment,
        },
        Case {
            name: "tiny-first-fragment",
            src: 0x0A00_0002,
            proto: IPPROTO_TCP,
            dport: DENY_PORT,
            frag: 0,
            truncate_to: ETH_HLEN + IPV4_MIN_HLEN + 2,
            expect: Reason::DropMalformed,
        },
        Case {
            name: "truncated-ip",
            src: 0x0A00_0002,
            proto: IPPROTO_TCP,
            dport: 443,
            frag: 0,
            truncate_to: ETH_HLEN + 10,
            expect: Reason::DropMalformed,
        },
    ];

    /// Runs every vector with `drop_malformed` and `drop_fragments` set.
    /// Returns the number of failures (0 = all good).
    pub fn run_all() -> usize {
        let rules = rules(Flags {
            drop_malformed: true,
            drop_fragments: true,
        });
        let mut failures = 0;
        let mut buf = [0u8; 64];
        for c in CASES.iter() {
            let mut n = frame(&mut buf, c.src, c.proto, c.dport, c.frag);
            if c.truncate_to != 0 {
                n = c.truncate_to;
            }
            if classify(&buf[..n], &rules) != c.expect {
                failures += 1;
            }
        }
        failures
    }
}
