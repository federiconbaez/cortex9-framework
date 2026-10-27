// SPDX-License-Identifier: Apache-2.0
//! Enforcing backend: fanotify `FAN_OPEN_EXEC_PERM`.
//!
//! The kernel blocks every `execve` of a file on the marked mount until we
//! answer. The decision is taken on the very file descriptor the kernel
//! hands us, so there is no path-based race. Needs `CAP_SYS_ADMIN`.
use crate::scan::Engine;
use crate::Event;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub struct FanotifyGuard {
    fd: OwnedFd,
    engine: Engine,
}

impl FanotifyGuard {
    /// Watch every exec on the mount (or, with `filesystem`, the whole
    /// filesystem) that contains `path`.
    pub fn new(engine: Engine, path: &Path, filesystem: bool) -> Result<FanotifyGuard> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("fanotify_init (needs CAP_SYS_ADMIN)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .context("path contains NUL")?;
        let scope = if filesystem {
            libc::FAN_MARK_FILESYSTEM
        } else {
            libc::FAN_MARK_MOUNT
        };
        let rc = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                libc::FAN_MARK_ADD | scope,
                libc::FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                cpath.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("fanotify_mark {}", path.display()));
        }
        Ok(FanotifyGuard { fd, engine })
    }

    /// Process events until `stop` is set. Returns one Event per decision.
    pub fn run(&mut self, stop: &AtomicBool, mut on_event: impl FnMut(Event)) -> Result<()> {
        let mut buf = vec![0u8; 8192];
        while !stop.load(Ordering::Relaxed) {
            let n =
                unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EINTR) {
                    // Brief sleep so a busy-loop does not burn a core when idle.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(e).context("read fanotify");
            }
            let mut off = 0usize;
            while off + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
                let meta =
                    unsafe { &*(buf.as_ptr().add(off) as *const libc::fanotify_event_metadata) };
                if meta.event_len as usize == 0 {
                    bail!("fanotify event_len is 0");
                }
                if meta.fd >= 0 {
                    let t0 = Instant::now();
                    let file = unsafe { File::from_raw_fd(meta.fd) };
                    let path = readlink_fd(meta.fd).unwrap_or_else(|_| format!("pid={}", meta.pid));
                    let decision = self.engine.decide(&file);
                    respond(&self.fd, meta.fd, decision.allow)?;
                    // Closing file closes meta.fd; do not close it again.
                    drop(file);
                    on_event(Event {
                        backend: "fanotify",
                        path,
                        pid: meta.pid,
                        decision,
                        latency_ns: t0.elapsed().as_nanos() as u64,
                    });
                }
                off += meta.event_len as usize;
            }
        }
        Ok(())
    }
}

fn respond(fan: &OwnedFd, fd: i32, allow: bool) -> Result<()> {
    let resp = libc::fanotify_response {
        fd,
        response: if allow {
            libc::FAN_ALLOW
        } else {
            libc::FAN_DENY
        },
    };
    let n = unsafe {
        libc::write(
            fan.as_raw_fd(),
            &resp as *const _ as *const _,
            std::mem::size_of_val(&resp),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error()).context("fanotify response");
    }
    Ok(())
}

fn readlink_fd(fd: i32) -> Result<String> {
    let link = format!("/proc/self/fd/{fd}");
    Ok(std::fs::read_link(link)?.to_string_lossy().into_owned())
}
