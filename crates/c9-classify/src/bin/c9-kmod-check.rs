// SPDX-License-Identifier: Apache-2.0
//! Differential check of the in-kernel classifier.
//!
//! Generates a fixed-seed adversarial corpus, sends it to `/dev/c9-classify`
//! (the Rust-for-Linux module) and compares every kernel verdict with the
//! userspace engine. Prints one machine-readable result line.
use c9_classify::packet::{random_frame, Pools, SplitMix64};
use c9_classify::{classify, vectors, Flags};
use std::io::{Read, Write};

fn main() {
    let mut args = std::env::args().skip(1);
    let dev = args.next().unwrap_or_else(|| "/dev/c9-classify".into());
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0xC0_47E9);

    // The module is loaded with its default flags (drop_malformed | drop_fragments).
    let rules = vectors::rules(Flags { drop_malformed: true, drop_fragments: true });
    let pools = Pools {
        srcs: vec![vectors::DENY_SRC, vectors::ALLOW_SRC, vectors::DENY_SRC | 0x80],
        ports: vec![vectors::DENY_PORT, 53, 443],
    };
    let mut rng = SplitMix64(seed);
    let frames: Vec<Vec<u8>> = (0..n).map(|_| random_frame(&mut rng, &pools)).collect();

    let mut agree = 0usize;
    let mut hist = [0usize; c9_classify::REASON_COUNT];
    for chunk in frames.chunks(1000) {
        let mut batch = Vec::new();
        for f in chunk {
            batch.extend_from_slice(&(f.len() as u16).to_le_bytes());
            batch.extend_from_slice(f);
        }
        let mut fh = std::fs::OpenOptions::new().read(true).write(true).open(&dev).expect("open device");
        fh.write_all(&batch).expect("write batch");
        let mut out = Vec::new();
        fh.read_to_end(&mut out).expect("read verdicts");
        assert_eq!(out.len(), chunk.len(), "one verdict per frame");
        for (f, k) in chunk.iter().zip(out) {
            let u = classify(f, &rules) as u8;
            hist[u as usize] += 1;
            if u == k {
                agree += 1;
            } else {
                eprintln!("MISMATCH user={u} kernel={k} frame={f:02x?}");
            }
        }
    }
    let hist: Vec<String> = c9_classify::ALL_REASONS.iter().map(|r| format!("{}={}", r.name(), hist[*r as usize])).collect();
    println!("C9-KMOD-RESULT agree={agree} total={n} seed={seed} {}", hist.join(" "));
    std::process::exit(if agree == n { 0 } else { 1 });
}
