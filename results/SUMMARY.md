# Measured results (GitHub Actions run 40808440418, 2026-10-29)

Numbers below come from CI artifacts of
https://github.com/federiconbaez/cortex9-framework/actions/runs/40808440418
on branch `fix/ci-msrv-1.88`. Re-run the commands in each job to reproduce;
do not edit the JSON by hand.

## Pillar 1 — Rust classifier in the kernel

| metric | value |
|---|---|
| kernel | 7.2.13 (CONFIG_RUST=y), QEMU TCG |
| differential agree | 20000/20000 (seed 12601449) |
| CWE cases | 15 |
| Rust compile_time | 9 |
| Rust runtime_check | 4 |
| Rust not_prevented | 2 (CWE-401, CWE-367) |
| C accepted by gcc -Wall -Wextra | 15/15 |
| rustc (CWE job) | 1.88.0 |

## Pillar 2 — XDP dynamic firewall

| metric | value |
|---|---|
| frames per case | 50000 |
| nftables drop rate (deny_src) | 1.0 |
| XDP drop rate (deny_src) | 1.0 (BPF stats 50000) |
| XDP pass rate (clean) | 1.0 |
| XDP sender pps (deny) | 389443 |
| nftables sender pps (deny) | 410089 |
| hot-reload avg | 1577 µs (100 reloads) |
| attach | peer veth ingress, SKB mode |

## Pillar 3 — cgroup v2 containment

| metric | value |
|---|---|
| memory.max | 128 MiB |
| oom_kills in cgroup | 2 |
| host oom_kill delta | 2 |
| canary survived | true |
| elapsed | 73 ms |
| GPU | not present; see docs/gpu.md |

## Pillar 4 — exec guard

| metric | value |
|---|---|
| fanotify deny e2e | 0.424 ms |
| fanotify allow e2e | 1.588 ms |
| decision p50 / p99 | 0.121 / 0.121 ms |
| false positives (benign corpus) | 0 |
| malicious corpus blocked | 4/4 |
