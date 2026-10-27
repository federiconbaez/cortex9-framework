// SPDX-License-Identifier: Apache-2.0
//! cortex9: one policy file, four enforcement points.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "cortex9",
    about = "One policy, four enforcement points",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Compile a policy and print the plan / fingerprint / diagnostics.
    Policy {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        fingerprint: bool,
    },
    /// Load / reload / stats for the XDP firewall.
    Xdp {
        #[command(subcommand)]
        cmd: XdpCmd,
    },
    /// Run a command inside a cgroup shaped by a workload in the policy.
    Cgroup {
        #[arg(long, default_value = "policy/cortex9.toml")]
        policy: PathBuf,
        #[arg(long)]
        workload: String,
        #[arg(long, default_value = c9_cgroup::DEFAULT_ROOT)]
        parent: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Intercept execve with fanotify (root) or seccomp-unotify.
    Exec {
        #[arg(long, default_value = "policy/cortex9.toml")]
        policy: PathBuf,
        #[arg(long, default_value = "fanotify", value_parser = ["fanotify", "seccomp"])]
        backend: String,
        #[arg(long, default_value = "/")]
        path: PathBuf,
        /// With seccomp: the command to run under the filter.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Run the shared classifier on a single hex frame (debug).
    Classify {
        #[arg(long, default_value = "policy/cortex9.toml")]
        policy: PathBuf,
        /// Ethernet frame as hex (spaces allowed).
        frame: String,
    },
}

#[derive(Subcommand, Debug)]
enum XdpCmd {
    /// Load the program, apply the policy, optionally attach.
    Load {
        #[arg(long, default_value = "policy/cortex9.toml")]
        policy: PathBuf,
        #[arg(long, default_value = c9_xdp::DEFAULT_PIN_DIR)]
        pin_dir: PathBuf,
        #[arg(long)]
        iface: Option<String>,
        #[arg(long)]
        skb: bool,
    },
    /// Hot-reload rules into the pinned maps (program stays attached).
    Reload {
        #[arg(long, default_value = "policy/cortex9.toml")]
        policy: PathBuf,
        #[arg(long, default_value = c9_xdp::DEFAULT_PIN_DIR)]
        pin_dir: PathBuf,
    },
    /// Print per-reason counters.
    Stats {
        #[arg(long, default_value = c9_xdp::DEFAULT_PIN_DIR)]
        pin_dir: PathBuf,
    },
    /// Unpin maps and detach is left to ip link.
    Unload {
        #[arg(long, default_value = c9_xdp::DEFAULT_PIN_DIR)]
        pin_dir: PathBuf,
    },
}

fn load_plan(path: &PathBuf) -> Result<c9_policy::Plan> {
    let src = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    match c9_policy::compile(&src) {
        Ok(c) => {
            for w in &c.warnings {
                eprintln!("{w}");
            }
            Ok(c.plan)
        }
        Err(diags) => {
            for d in &diags {
                eprintln!("{d}");
            }
            bail!("{} diagnostic(s)", diags.len());
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Policy {
            file,
            json,
            fingerprint,
        } => {
            let plan = load_plan(&file)?;
            if fingerprint {
                println!("{}", plan.fingerprint_hex());
            } else if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!(
                    "policy {:?} generation {} fingerprint {}",
                    plan.name,
                    plan.generation,
                    plan.fingerprint_hex()
                );
                println!(
                    "  network: {} allow, {} deny, {} ports (malformed={} fragments={})",
                    plan.network.allow.len(),
                    plan.network.deny.len(),
                    plan.network.deny_ports.len(),
                    plan.network.drop_malformed,
                    plan.network.drop_fragments
                );
                for w in &plan.workloads {
                    println!(
                        "  workload {:?}: memory_max={:?} oom_group={} expose={}",
                        w.name,
                        w.memory_max,
                        w.oom_group,
                        w.expose.len()
                    );
                }
                println!(
                    "  exec: mode={:?} signatures={} trusted={}",
                    plan.exec.mode,
                    plan.exec.signatures.len(),
                    plan.exec.trusted_sha256.len()
                );
            }
        }
        Cmd::Xdp { cmd } => match cmd {
            XdpCmd::Load {
                policy,
                pin_dir,
                iface,
                skb,
            } => {
                let plan = load_plan(&policy)?;
                let mut fw = c9_xdp::Firewall::load(Some(&pin_dir))?;
                let report = fw.maps.apply(&plan)?;
                println!(
                    "loaded program_id={} epoch={} +{} -{} in {:?}",
                    fw.program_id()?,
                    report.epoch,
                    report.inserted,
                    report.removed,
                    report.elapsed
                );
                if let Some(iface) = iface {
                    fw.attach(&iface, skb)?;
                    println!("attached to {iface} (skb={skb})");
                    // Keep maps pinned; drop the process without unpinning.
                    std::mem::forget(fw);
                }
            }
            XdpCmd::Reload { policy, pin_dir } => {
                let plan = load_plan(&policy)?;
                let mut maps = c9_xdp::Maps::from_pins(&pin_dir)?;
                let report = maps.apply(&plan)?;
                println!(
                    "reloaded epoch={} fingerprint={} +{} -{} in {:?}",
                    report.epoch,
                    plan.fingerprint_hex(),
                    report.inserted,
                    report.removed,
                    report.elapsed
                );
            }
            XdpCmd::Stats { pin_dir } => {
                let maps = c9_xdp::Maps::from_pins(&pin_dir)?;
                let stats = maps.stats()?;
                for (i, n) in stats.iter().enumerate() {
                    if let Some(r) = c9_classify::Reason::from_u32(i as u32) {
                        println!("{:>5}  {}", n, r.name());
                    }
                }
            }
            XdpCmd::Unload { pin_dir } => {
                c9_xdp::unpin(&pin_dir)?;
                println!("unpinned {}", pin_dir.display());
            }
        },
        Cmd::Cgroup {
            policy,
            workload,
            parent,
            command,
        } => {
            let plan = load_plan(&policy)?;
            let w = plan
                .workload(&workload)
                .with_context(|| format!("no workload {workload:?}"))?
                .clone();
            let mut cmd = Command::new(&command[0]);
            cmd.args(&command[1..]);
            let r = c9_cgroup::contain(&parent, Some(&w), &mut cmd, Duration::from_secs(3600))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "oom_kills": r.oom_kills,
                    "max_rss_bytes": r.max_rss_bytes,
                    "memory_max": r.memory_max,
                    "exit": format!("{:?}", r.exit),
                    "pressure_fired": r.pressure_fired,
                    "pressure_ms": r.pressure_ms,
                    "elapsed_ms": r.elapsed_ms,
                }))?
            );
            if !matches!(r.exit, c9_cgroup::Exit::Code(0)) {
                std::process::exit(1);
            }
        }
        Cmd::Exec {
            policy,
            backend,
            path,
            command,
        } => {
            let plan = load_plan(&policy)?;
            let engine = c9_execguard::Engine::new(&plan.exec)?;
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            match backend.as_str() {
                "fanotify" => {
                    let mut g = c9_execguard::fanotify::FanotifyGuard::new(engine, &path, true)?;
                    g.run(&stop2, |ev| print_event(&ev))?;
                }
                "seccomp" => {
                    if command.is_empty() {
                        bail!("seccomp backend needs a command");
                    }
                    let argv: Vec<_> = command.iter().map(std::ffi::OsStr::new).collect();
                    let (mut session, mut child) = c9_execguard::seccomp::spawn(engine, &argv)?;
                    while child.try_wait()?.is_none() && !stop2.load(Ordering::Relaxed) {
                        if let Some(ev) = session.recv()? {
                            print_event(&ev);
                        }
                    }
                    let st = child.wait()?;
                    if !c9_execguard::seccomp::Child::success(st) {
                        std::process::exit(1);
                    }
                }
                _ => unreachable!(),
            }
        }
        Cmd::Classify { policy, frame } => {
            let plan = load_plan(&policy)?;
            let bytes = parse_hex(&frame)?;
            let r = c9_classify::classify(&bytes, &plan.network);
            println!(
                "{} ({})",
                r.name(),
                if r.is_drop() { "DROP" } else { "PASS" }
            );
        }
    }
    Ok(())
}

fn print_event(ev: &c9_execguard::Event) {
    println!(
        "[{}] pid={} {} allow={} {:.3}ms scanned={} why={:?}",
        ev.backend,
        ev.pid,
        ev.path,
        ev.decision.allow,
        ev.latency_ns as f64 / 1e6,
        ev.decision.scanned_bytes,
        ev.decision.why
    );
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let h: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(hex::decode(h)?)
}
