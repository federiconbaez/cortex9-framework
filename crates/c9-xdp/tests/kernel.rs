// SPDX-License-Identifier: Apache-2.0
//! Loads the XDP program into the running kernel. Requires root; fails loudly otherwise.
use c9_classify::packet::{random_frame, FrameSpec, Pools, SplitMix64};
use c9_xdp::*;

fn require_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged-tests need root: run under sudo"
    );
}

fn plan(src: &str) -> c9_policy::Plan {
    c9_policy::compile(src).expect("policy compiles").plan
}

const BASE: &str = include_str!("../../../policy/cortex9.toml");

fn corpus(plan: &c9_policy::Plan, n: usize, seed: u64) -> Vec<Vec<u8>> {
    let pools = Pools {
        srcs: plan
            .network
            .allow
            .iter()
            .chain(plan.network.deny.iter())
            .map(|p| p.addr())
            .collect(),
        ports: plan.network.deny_ports.iter().map(|p| p.port).collect(),
    };
    let mut rng = SplitMix64(seed);
    (0..n).map(|_| random_frame(&mut rng, &pools)).collect()
}

#[test]
fn kernel_program_agrees_with_rust_engine() {
    require_root();
    let mut fw = Firewall::load(None).expect("load");
    let p = plan(BASE);
    fw.maps.apply(&p).unwrap();
    let frames = corpus(&p, 5000, 7);
    let r = differential(&fw, &p, &frames).unwrap();
    assert!(
        r.first_mismatch.is_none(),
        "mismatch: {:?}",
        r.first_mismatch
    );
    assert_eq!(r.agree, r.compared);
    assert!(r.compared > 4500);
}

#[test]
fn hot_reload_switches_epoch_without_touching_the_program() {
    require_root();
    let mut fw = Firewall::load(None).expect("load");
    let id = fw.program_id().unwrap();
    let p1 = plan(BASE);
    let r1 = fw.maps.apply(&p1).unwrap();
    let probe = FrameSpec {
        src: u32::from_be_bytes([10, 9, 9, 9]),
        proto: 6,
        dport: 8443,
        ..Default::default()
    }
    .build();
    assert_eq!(fw.test_run(&probe, 1).unwrap().retval, XDP_PASS);

    let p2 = plan(
        &BASE
            .replace("generation = 1", "generation = 2")
            .replace(r#""tcp/23","#, r#""tcp/23", "tcp/8443","#),
    );
    let r2 = fw.maps.apply(&p2).unwrap();
    assert_ne!(r1.epoch, r2.epoch);
    assert_eq!(
        fw.test_run(&probe, 1).unwrap().retval,
        XDP_DROP,
        "new rule active"
    );
    assert_eq!(fw.program_id().unwrap(), id, "program not reloaded");
    let ep = fw.maps.epoch_info(r2.epoch).unwrap();
    assert_eq!(ep.generation, 2);
    assert_eq!(ep.fingerprint, p2.fingerprint_u64());

    // Back to p1: the stale epoch is diffed, not rebuilt.
    let r3 = fw.maps.apply(&p1).unwrap();
    assert_eq!(r3.epoch, r1.epoch);
    assert_eq!(r3.inserted + r3.removed, 0, "epoch already held p1");
    assert_eq!(fw.test_run(&probe, 1).unwrap().retval, XDP_PASS);
}

#[test]
fn pinned_maps_can_be_updated_from_another_handle() {
    require_root();
    let dir = std::env::temp_dir().join(format!("c9pin{}", std::process::id()));
    let bpffs = std::path::Path::new("/sys/fs/bpf").join(dir.file_name().unwrap());
    let mut fw = Firewall::load(Some(&bpffs)).expect("load pinned");
    let p1 = plan(BASE);
    fw.maps.apply(&p1).unwrap();
    let mut other = Maps::from_pins(&bpffs).expect("reopen pins");
    let p2 = plan(&BASE.replace(
        r#"deny_src = ["203.0.113.0/24", "198.51.100.7/32"]"#,
        r#"deny_src = ["10.9.0.0/16"]"#,
    ));
    other.apply(&p2).unwrap();
    let probe = FrameSpec {
        src: u32::from_be_bytes([10, 9, 1, 1]),
        ..Default::default()
    }
    .build();
    assert_eq!(fw.test_run(&probe, 1).unwrap().retval, XDP_DROP);
    drop(other);
    drop(fw);
    unpin(&bpffs).unwrap();
}
