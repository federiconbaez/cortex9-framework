// SPDX-License-Identifier: Apache-2.0
//! Frame construction and a deterministic corpus generator (std only).
//!
//! The generator is used by the differential test against the XDP program
//! and by the veth benchmark sender, so both see byte-identical traffic for
//! a given seed.

use crate::{ETH_HLEN, ETH_P_8021Q, ETH_P_IP, IPPROTO_TCP, IPPROTO_UDP};

/// SplitMix64: tiny, deterministic, good enough for corpus generation.
#[derive(Clone, Debug)]
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameSpec {
    pub vlan: Option<u16>,
    pub ethertype: u16,
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    /// Raw IPv4 flags+fragment-offset field.
    pub frag: u16,
    /// IPv4 options length in 32-bit words (0..=10).
    pub opt_words: u8,
    pub payload: usize,
}

impl Default for FrameSpec {
    fn default() -> Self {
        FrameSpec {
            vlan: None,
            ethertype: ETH_P_IP,
            src: 0x0A00_0002,
            dst: 0x0A00_0001,
            proto: IPPROTO_UDP,
            sport: 40000,
            dport: 9,
            frag: 0,
            opt_words: 0,
            payload: 18,
        }
    }
}

impl FrameSpec {
    pub fn build(&self) -> Vec<u8> {
        let mut f = Vec::with_capacity(64 + self.payload);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // dst mac
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src mac
        if let Some(tci) = self.vlan {
            f.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
            f.extend_from_slice(&tci.to_be_bytes());
        }
        f.extend_from_slice(&self.ethertype.to_be_bytes());
        if self.ethertype != ETH_P_IP {
            f.resize(f.len() + 46, 0);
            return f;
        }
        let ihl = 5 + self.opt_words.min(10) as usize;
        let l4_len = match self.proto {
            IPPROTO_TCP => 20,
            IPPROTO_UDP => 8,
            _ => 0,
        };
        let tot = (ihl * 4 + l4_len + self.payload) as u16;
        let ip_start = f.len();
        f.push(0x40 | ihl as u8);
        f.push(0);
        f.extend_from_slice(&tot.to_be_bytes());
        f.extend_from_slice(&0x1234u16.to_be_bytes());
        f.extend_from_slice(&self.frag.to_be_bytes());
        f.push(64);
        f.push(self.proto);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&self.src.to_be_bytes());
        f.extend_from_slice(&self.dst.to_be_bytes());
        for _ in 0..(ihl - 5) {
            f.extend_from_slice(&[1, 1, 1, 1]); // NOP options
        }
        let csum = ipv4_checksum(&f[ip_start..ip_start + ihl * 4]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
        match self.proto {
            IPPROTO_TCP => {
                f.extend_from_slice(&self.sport.to_be_bytes());
                f.extend_from_slice(&self.dport.to_be_bytes());
                f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
            }
            IPPROTO_UDP => {
                f.extend_from_slice(&self.sport.to_be_bytes());
                f.extend_from_slice(&self.dport.to_be_bytes());
                f.extend_from_slice(&((8 + self.payload) as u16).to_be_bytes());
                f.extend_from_slice(&[0, 0]);
            }
            _ => {}
        }
        f.resize(f.len() + self.payload, 0xA5);
        f
    }
}

pub fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for (i, c) in hdr.chunks(2).enumerate() {
        if i == 5 {
            continue;
        }
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { (c[0] as u16) << 8 };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Interesting address/port pools, so random traffic actually hits rules.
#[derive(Clone, Debug, Default)]
pub struct Pools {
    pub srcs: Vec<u32>,
    pub ports: Vec<u16>,
}

/// Generate one adversarial frame: mostly well-formed traffic drawn from the
/// pools, plus VLAN tags, IP options, fragments, odd ethertypes, bad
/// versions, bad IHL, short totals and truncation at every boundary.
pub fn random_frame(rng: &mut SplitMix64, pools: &Pools) -> Vec<u8> {
    let mut s = FrameSpec::default();
    s.src = if !pools.srcs.is_empty() && rng.chance(3, 4) {
        let base = pools.srcs[rng.below(pools.srcs.len() as u64) as usize];
        base ^ (rng.below(4) as u32) // near the boundary of the pool entry
    } else {
        rng.next_u64() as u32
    };
    s.dport = if !pools.ports.is_empty() && rng.chance(1, 2) {
        pools.ports[rng.below(pools.ports.len() as u64) as usize]
    } else {
        rng.next_u64() as u16
    };
    s.sport = rng.next_u64() as u16;
    s.proto = match rng.below(10) {
        0..=3 => IPPROTO_TCP,
        4..=7 => IPPROTO_UDP,
        8 => 1, // ICMP
        _ => rng.next_u64() as u8,
    };
    if rng.chance(1, 8) {
        s.vlan = Some(rng.next_u64() as u16 & 0x0fff);
    }
    if rng.chance(1, 10) {
        s.opt_words = rng.below(11) as u8;
    }
    if rng.chance(1, 8) {
        s.frag = match rng.below(3) {
            0 => 0x2000,                                   // MF, offset 0
            1 => (rng.next_u64() as u16 & 0x1fff).max(1),  // non-first
            _ => 0x4000,                                   // DF only
        };
    }
    if rng.chance(1, 20) {
        s.ethertype = [0x86DD, 0x0806, 0x88A8, 0x8100][rng.below(4) as usize];
    }
    s.payload = rng.below(64) as usize;
    let mut f = s.build();

    // Mutations that the parser must survive.
    let l3 = if s.vlan.is_some() { ETH_HLEN + 4 } else { ETH_HLEN };
    match rng.below(12) {
        0 => {
            let cut = rng.below(f.len() as u64 + 1) as usize;
            f.truncate(cut);
        }
        1 if f.len() > l3 => f[l3] = (rng.below(16) as u8) << 4 | (f[l3] & 0x0f), // version
        2 if f.len() > l3 => f[l3] = (f[l3] & 0xf0) | rng.below(16) as u8,       // IHL
        3 if f.len() > l3 + 3 => {
            let t = rng.below(80) as u16; // tot_len possibly < ihl
            f[l3 + 2..l3 + 4].copy_from_slice(&t.to_be_bytes());
        }
        _ => {}
    }
    f
}
