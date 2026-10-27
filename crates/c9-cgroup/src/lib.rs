// SPDX-License-Identifier: Apache-2.0
//! `c9-cgroup`: a cgroups v2 supervisor for inference-like workloads.
//!
//! A workload from the shared policy is placed in its own child cgroup with
//! `memory.max`, `memory.high`, `memory.swap.max`, `memory.oom.group` and a
//! PSI memory-pressure trigger. The point it proves: when the workload
//! exceeds its budget it is OOM-killed *inside its cgroup* (the whole group
//! at once with `oom.group=1`) while a canary process outside the cgroup is
//! never touched and the host does not OOM.
//!
//! There is NO GPU on the development machine, so GPU isolation is only a
//! design (`docs/gpu.md`); `gpu_devices` in a policy is surfaced as a
//! warning and never enforced here.

use anyhow::{bail, Context, Result};
use c9_policy::{PressureAction, WorkloadPlan};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub const DEFAULT_ROOT: &str = "/sys/fs/cgroup";

/// A managed child cgroup.
pub struct Cgroup {
    path: PathBuf,
    created: bool,
}

fn write(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {value:?} to {}", path.display()))
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn size_str(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "max".into())
}

impl Cgroup {
    /// Enable the controllers this supervisor needs on `parent`, then create
    /// `parent/<name>`. `parent` must be a delegated cgroup the caller owns;
    /// enabling controllers needs write access to its `cgroup.subtree_control`.
    pub fn create(parent: &Path, name: &str) -> Result<Cgroup> {
        if !parent.join("cgroup.controllers").exists() {
            bail!("{} is not a cgroup v2 directory", parent.display());
        }
        let avail = read(&parent.join("cgroup.controllers"))?;
        for c in ["memory", "pids"] {
            if !avail.split_whitespace().any(|x| x == c) {
                bail!("controller {c} not available in {}", parent.display());
            }
        }
        // Idempotent: writing an already-enabled controller is fine.
        let _ = write(&parent.join("cgroup.subtree_control"), "+memory +pids");
        let path = parent.join(name);
        fs::create_dir(&path).with_context(|| format!("create cgroup {}", path.display()))?;
        Ok(Cgroup {
            path,
            created: true,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Apply the limits from a workload plan.
    pub fn apply(&self, w: &WorkloadPlan) -> Result<()> {
        write(&self.path.join("memory.max"), &size_str(w.memory_max))?;
        if let Some(h) = w.memory_high {
            write(&self.path.join("memory.high"), &h.to_string())?;
        }
        // No swap for inference workloads by default, so the budget is real RAM.
        let swap = self.path.join("memory.swap.max");
        if swap.exists() {
            write(&swap, &size_str(w.swap_max))?;
        }
        write(
            &self.path.join("memory.oom.group"),
            if w.oom_group { "1" } else { "0" },
        )?;
        if let Some(p) = w.pids_max {
            write(&self.path.join("pids.max"), &p.to_string())?;
        }
        if let Some(cw) = w.cpu_weight {
            let cpuw = self.path.join("cpu.weight");
            if cpuw.exists() {
                write(&cpuw, &cw.to_string())?;
            }
        }
        Ok(())
    }

    /// Move a process into this cgroup.
    pub fn add_pid(&self, pid: i32) -> Result<()> {
        write(&self.path.join("cgroup.procs"), &pid.to_string())
    }

    /// Current `memory.current` in bytes.
    pub fn memory_current(&self) -> Result<u64> {
        Ok(read(&self.path.join("memory.current"))?.trim().parse()?)
    }

    /// Parse `memory.events` into (key, value) pairs; e.g. `oom_kill`, `max`, `high`.
    pub fn memory_events(&self) -> Result<Vec<(String, u64)>> {
        Ok(read(&self.path.join("memory.events"))?
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(' ')?;
                Some((k.to_string(), v.parse().ok()?))
            })
            .collect())
    }

    pub fn event(&self, key: &str) -> Result<u64> {
        Ok(self
            .memory_events()?
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .unwrap_or(0))
    }

    /// Arm a PSI memory-pressure trigger; poll the returned fd for stalls.
    pub fn arm_pressure(&self, line: &str) -> Result<PressureFd> {
        let path = self.path.join("memory.pressure");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let fd = file.as_raw_fd();
        let n = unsafe { libc::write(fd, line.as_ptr() as *const _, line.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("arm PSI trigger {line:?}"));
        }
        Ok(PressureFd { _file: file })
    }

    pub fn kill_all(&self) -> Result<()> {
        let kill = self.path.join("cgroup.kill");
        if kill.exists() {
            write(&kill, "1")?;
        }
        Ok(())
    }

    fn pids(&self) -> Result<Vec<i32>> {
        Ok(read(&self.path.join("cgroup.procs"))?
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.created {
            return;
        }
        let _ = self.kill_all();
        for _ in 0..100 {
            match self.pids() {
                Ok(p) if p.is_empty() => break,
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}

/// A PSI trigger file. `poll`ing it returns readable when pressure exceeds
/// the armed threshold.
pub struct PressureFd {
    _file: fs::File,
}

impl PressureFd {
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self._file.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("poll PSI trigger");
        }
        Ok(pfd.revents & libc::POLLPRI != 0)
    }
}

/// Outcome of a containment run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Containment {
    /// `oom_kill` from the workload's `memory.events`.
    pub oom_kills: u64,
    /// `ru_maxrss` of the workload process, bytes.
    pub max_rss_bytes: u64,
    pub memory_max: Option<u64>,
    /// How the workload ended: exit code or terminating signal.
    pub exit: Exit,
    pub pressure_fired: bool,
    /// Milliseconds from start to the first PSI notification.
    pub pressure_ms: Option<u128>,
    pub action_taken: Option<PressureAction>,
    pub elapsed_ms: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

/// Spawn `cmd` directly inside a cgroup built from `w` (the child joins the
/// cgroup before `exec`, so not a single page is charged elsewhere) and
/// supervise it until it ends. With `w = None` the command runs unconfined,
/// which is the baseline.
pub fn contain(
    parent: &Path,
    w: Option<&WorkloadPlan>,
    cmd: &mut Command,
    timeout: Duration,
) -> Result<Containment> {
    let t0 = Instant::now();
    let cg = match w {
        Some(w) => {
            let cg = Cgroup::create(parent, &w.name)?;
            cg.apply(w)?;
            Some(cg)
        }
        None => None,
    };
    if let Some(cg) = cg {
        let procs = fs::OpenOptions::new()
            .write(true)
            .open(cg.path().join("cgroup.procs"))?;
        let fd = procs.as_raw_fd();
        // SAFETY: only async-signal-safe calls (write) run between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                let b = b"0";
                if libc::write(fd, b.as_ptr() as *const _, 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().context("spawn workload")?;
        drop(procs);
        supervise(cg, w.unwrap(), child, t0, timeout)
    } else {
        let child = cmd.spawn().context("spawn workload")?;
        let (exit, rss) = wait_rusage(child.id() as i32)?;
        Ok(Containment {
            oom_kills: 0,
            max_rss_bytes: rss,
            memory_max: None,
            exit,
            pressure_fired: false,
            pressure_ms: None,
            action_taken: None,
            elapsed_ms: t0.elapsed().as_millis(),
        })
    }
}

fn supervise(
    cg: Cgroup,
    w: &WorkloadPlan,
    child: Child,
    t0: Instant,
    timeout: Duration,
) -> Result<Containment> {
    let pid = child.id() as i32;
    let pressure = w
        .psi
        .as_ref()
        .map(|p| cg.arm_pressure(&p.trigger_line()))
        .transpose()?;
    let mut pressure_ms = None;
    let mut action = None;
    loop {
        if let Some(pf) = &pressure {
            if pressure_ms.is_none() && pf.wait(Duration::from_millis(5))? {
                pressure_ms = Some(t0.elapsed().as_millis());
                action = Some(w.on_pressure);
                match w.on_pressure {
                    PressureAction::Kill => cg.kill_all()?,
                    PressureAction::Freeze => {
                        write(&cg.path().join("cgroup.freeze"), "1")?;
                        // Frozen workloads hold memory but make no progress;
                        // the supervisor reclaims them after a grace period.
                        std::thread::sleep(Duration::from_millis(200));
                        cg.kill_all()?;
                    }
                    PressureAction::Log => {}
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
        // Peek without reaping so wait4 can still collect rusage.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if r < 0 || unsafe { info.si_pid() } == pid {
            break;
        }
        if t0.elapsed() > timeout {
            cg.kill_all()?;
            bail!("workload did not terminate within {timeout:?}");
        }
    }
    let (exit, rss) = wait_rusage(pid)?;
    Ok(Containment {
        oom_kills: cg.event("oom_kill")?,
        max_rss_bytes: rss,
        memory_max: w.memory_max,
        exit,
        pressure_fired: pressure_ms.is_some(),
        pressure_ms,
        action_taken: action,
        elapsed_ms: t0.elapsed().as_millis(),
    })
}

/// Reap `pid`, returning how it ended and its peak RSS in bytes.
fn wait_rusage(pid: i32) -> Result<(Exit, u64)> {
    let mut status = 0;
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
    if r != pid {
        return Err(io::Error::last_os_error()).context("wait4");
    }
    let exit = if libc::WIFSIGNALED(status) {
        Exit::Signal(libc::WTERMSIG(status))
    } else {
        Exit::Code(libc::WEXITSTATUS(status))
    };
    Ok((exit, ru.ru_maxrss as u64 * 1024))
}

/// Read `/proc/pressure/memory` "full" total (microseconds), host-wide.
pub fn host_memory_pressure_full_us() -> Result<u64> {
    let s = read(Path::new("/proc/pressure/memory"))?;
    for l in s.lines() {
        if let Some(rest) = l.strip_prefix("full ") {
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix("total=") {
                    return Ok(v.parse()?);
                }
            }
        }
    }
    bail!("no full line in /proc/pressure/memory")
}

/// Host-wide OOM kills so far (`oom_kill` in /proc/vmstat).
pub fn host_oom_kills() -> Result<u64> {
    let s = read(Path::new("/proc/vmstat"))?;
    s.lines()
        .find_map(|l| l.strip_prefix("oom_kill ").map(|v| v.trim().parse::<u64>()))
        .transpose()?
        .context("no oom_kill in /proc/vmstat")
}
