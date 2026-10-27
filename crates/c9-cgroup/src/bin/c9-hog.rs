// SPDX-License-Identifier: Apache-2.0
//! Workload stand-ins for the containment experiment.
//!
//! `c9-hog load <MiB> [step MiB]`: simulates loading model shards: allocates
//! and touches memory step by step until it holds <MiB>, then exits 0.
//!
//! `c9-hog canary <millis>`: a latency-sensitive neighbour: wakes every
//! millisecond, touches a small working set, and on exit prints the worst
//! scheduling gap it observed in microseconds.
use std::time::{Duration, Instant};

fn load(mib: usize, step_mib: usize) {
    let step = step_mib.max(1) << 20;
    let mut shards: Vec<Vec<u8>> = Vec::new();
    let mut held = 0usize;
    while held < mib << 20 {
        let mut shard = vec![0u8; step];
        for i in (0..shard.len()).step_by(4096) {
            shard[i] = (i >> 12) as u8 | 1;
        }
        held += shard.len();
        shards.push(shard);
    }
    let sum: u64 = shards.iter().map(|s| s[4096] as u64).sum();
    println!("loaded {} MiB checksum {sum}", held >> 20);
}

fn canary(millis: u64) {
    let mut ws = vec![1u8; 4 << 20];
    let end = Instant::now() + Duration::from_millis(millis);
    let mut last = Instant::now();
    let mut worst = Duration::ZERO;
    let mut ticks = 0u64;
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
        for i in (0..ws.len()).step_by(4096) {
            ws[i] = ws[i].wrapping_add(1);
        }
        let now = Instant::now();
        worst = worst.max(now - last);
        last = now;
        ticks += 1;
    }
    println!("canary ticks={ticks} worst_gap_us={}", worst.as_micros());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let num = |i: usize, d: u64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    match a.get(1).map(String::as_str) {
        Some("load") => load(num(2, 512) as usize, num(3, 16) as usize),
        Some("canary") => canary(num(2, 3000)),
        _ => {
            eprintln!("usage: c9-hog load <MiB> [step] | canary <millis>");
            std::process::exit(2);
        }
    }
}
