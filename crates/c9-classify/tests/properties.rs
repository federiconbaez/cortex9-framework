// SPDX-License-Identifier: Apache-2.0
use c9_classify::packet::{random_frame, FrameSpec, Pools, SplitMix64};
use c9_classify::*;
use proptest::prelude::*;

/// Reference model written independently of `engine.rs`, in the most
/// obvious style, to cross-check the optimised parser.
fn reference(
    pkt: &[u8],
    allow: &[Prefix],
    deny: &[Prefix],
    ports: &[(u8, u16)],
    f: Flags,
) -> Reason {
    let bad = if f.drop_malformed {
        Reason::DropMalformed
    } else {
        Reason::PassMalformed
    };
    if pkt.len() < 14 {
        return Reason::PassNotIpv4;
    }
    let mut et = u16::from_be_bytes([pkt[12], pkt[13]]);
    let mut l3 = 14;
    if et == 0x8100 || et == 0x88A8 {
        if pkt.len() < 18 {
            return Reason::PassNotIpv4;
        }
        et = u16::from_be_bytes([pkt[16], pkt[17]]);
        l3 = 18;
    }
    if et != 0x0800 {
        return Reason::PassNotIpv4;
    }
    let ip = &pkt[l3..];
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return bad;
    }
    let ihl = (ip[0] & 15) as usize * 4;
    if ihl < 20 || ip.len() < ihl || (u16::from_be_bytes([ip[2], ip[3]]) as usize) < ihl {
        return bad;
    }
    let src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    if allow.iter().any(|p| p.contains(src)) {
        return Reason::PassAllowSrc;
    }
    if deny.iter().any(|p| p.contains(src)) {
        return Reason::DropDenySrc;
    }
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x1fff != 0 {
        return if f.drop_fragments {
            Reason::DropFragment
        } else {
            Reason::PassFragment
        };
    }
    if frag & 0x2000 != 0 && f.drop_fragments {
        return Reason::DropFragment;
    }
    if ip[9] == 6 || ip[9] == 17 {
        if ip.len() < ihl + 4 {
            return bad;
        }
        let dport = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
        if ports.contains(&(ip[9], dport)) {
            return Reason::DropDenyPort;
        }
    }
    Reason::PassDefault
}

fn arb_prefix() -> impl Strategy<Value = Prefix> {
    (any::<u32>(), 0u8..=32).prop_map(|(a, l)| Prefix::new(a, l).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn total_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..128), dm: bool, df: bool) {
        let r = vectors::rules(Flags { drop_malformed: dm, drop_fragments: df });
        let _ = classify(&bytes, &r); // must not panic
    }

    #[test]
    fn engine_matches_reference(
        seed: u64,
        allow in proptest::collection::vec(arb_prefix(), 0..4),
        deny in proptest::collection::vec(arb_prefix(), 0..8),
        ports in proptest::collection::vec((prop_oneof![Just(6u8), Just(17u8)], any::<u16>()), 0..8),
        dm: bool, df: bool,
    ) {
        let flags = Flags { drop_malformed: dm, drop_fragments: df };
        let mut r: StaticRules<8> = StaticRules::new(flags);
        for p in &allow { r.allow(*p).unwrap(); }
        for p in &deny { r.deny(*p).unwrap(); }
        for &(pr, po) in &ports { r.deny_port(pr, po).unwrap(); }
        let pools = Pools {
            srcs: allow.iter().chain(deny.iter()).map(|p| p.addr()).collect(),
            ports: ports.iter().map(|p| p.1).collect(),
        };
        let mut rng = SplitMix64(seed);
        for _ in 0..32 {
            let f = random_frame(&mut rng, &pools);
            prop_assert_eq!(classify(&f, &r), reference(&f, &allow, &deny, &ports, flags));
        }
    }

    #[test]
    fn allow_always_beats_deny(a: u32, len in 0u8..=32, dport: u16) {
        let p = Prefix::new(a, len).unwrap();
        let mut r: StaticRules<2> = StaticRules::new(Flags::default());
        r.allow(p).unwrap();
        r.deny(p).unwrap();
        r.deny_port(6, dport).unwrap();
        let f = FrameSpec { src: a, proto: 6, dport, ..Default::default() }.build();
        prop_assert_eq!(classify(&f, &r), Reason::PassAllowSrc);
    }

    #[test]
    fn prefix_normalisation(a: u32, b: u32, len in 0u8..=32) {
        let p = Prefix::new(a, len).unwrap();
        prop_assert!(p.contains(a));
        prop_assert_eq!(p.contains(b), Prefix::new(b, len).unwrap() == p);
        prop_assert!(Prefix::new(a, 0).unwrap().covers(p));
    }
}

#[test]
fn shared_vectors_pass() {
    assert_eq!(vectors::run_all(), 0);
}

#[test]
fn capacity_is_enforced() {
    let mut r: StaticRules<1> = StaticRules::new(Flags::default());
    assert!(r.deny(Prefix::new(1, 32).unwrap()).is_ok());
    assert_eq!(r.deny(Prefix::new(2, 32).unwrap()), Err(Full));
}

#[test]
fn reason_abi_is_stable() {
    for (i, r) in ALL_REASONS.iter().enumerate() {
        assert_eq!(*r as u32 as usize, i);
        assert_eq!(Reason::from_u32(i as u32), Some(*r));
    }
    assert_eq!(Reason::from_u32(REASON_COUNT as u32), None);
}
