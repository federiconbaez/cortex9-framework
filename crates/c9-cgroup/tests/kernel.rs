// SPDX-License-Identifier: Apache-2.0
//! Real cgroup v2 containment. Requires root; fails loudly otherwise.
use c9_cgroup::*;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const HOG: &str = env!("CARGO_BIN_EXE_c9-hog");

fn require_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged-tests need root: run under sudo"
    );
}

fn workload(extra: &str) -> c9_policy::WorkloadPlan {
    let src = format!(
        "[meta]\nname = \"t\"\ngeneration = 1\n[[workload]]\nname = \"hog\"\nmemory_max = \"128M\"\nswap_max = \"0\"\npids_max = 16\n{extra}\n"
    );
    c9_policy::compile(&src).unwrap().plan.workloads.remove(0)
}

fn slice(tag: &str) -> Cgroup {
    Cgroup::create(
        Path::new(DEFAULT_ROOT),
        &format!("c9-test-{tag}-{}", std::process::id()),
    )
    .expect("create slice")
}

#[test]
fn hog_is_killed_inside_its_cgroup_and_canary_survives() {
    require_root();
    let s = slice("oom");
    let canary = Command::new(HOG)
        .args(["canary", "4000"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let host_before = host_oom_kills().unwrap();
    let w = workload("");
    let r = contain(
        s.path(),
        Some(&w),
        Command::new(HOG).args(["load", "512", "8"]),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(r.exit, Exit::Signal(9), "{r:?}");
    assert!(r.oom_kills >= 1, "{r:?}");
    assert!(
        r.max_rss_bytes <= (128 << 20) + (8 << 20),
        "rss {} above budget",
        r.max_rss_bytes
    );
    let out = canary.wait_with_output().unwrap();
    assert!(out.status.success(), "canary died: {out:?}");
    // vmstat oom_kill counts memcg kills too: exactly ours, nothing else.
    assert_eq!(host_oom_kills().unwrap() - host_before, r.oom_kills);
}

#[test]
fn without_cgroup_the_budget_is_not_enforced() {
    require_root();
    let r = contain(
        Path::new(DEFAULT_ROOT),
        None,
        Command::new(HOG)
            .args(["load", "256", "8"])
            .stdout(Stdio::null()),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(r.exit, Exit::Code(0));
    assert!(r.max_rss_bytes >= 256 << 20, "{r:?}");
}

#[test]
fn psi_trigger_kills_before_the_kernel_oom_killer() {
    require_root();
    let s = slice("psi");
    let w = workload("memory_high = \"64M\"\npsi = { kind = \"some\", stall_ms = 50, window_ms = 500 }\non_pressure = \"kill\"");
    let r = contain(
        s.path(),
        Some(&w),
        Command::new(HOG)
            .args(["load", "512", "4"])
            .stdout(Stdio::null()),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(r.pressure_fired, "{r:?}");
    assert_eq!(r.exit, Exit::Signal(9), "{r:?}");
    assert_eq!(r.oom_kills, 0, "supervisor acted first: {r:?}");
}
