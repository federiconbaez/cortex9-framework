// SPDX-License-Identifier: Apache-2.0
//! Fallback backend: `SECCOMP_RET_USER_NOTIF` on `execve`/`execveat`.
//!
//! Works without CAP_SYS_ADMIN. The notifier opens the target binary via
//! `/proc/<pid>/root/...`, scans it, and answers CONTINUE or ERRNO(EPERM).
//!
//! Race note: between the notification and the open the target could replace
//! the file. Fanotify does not have that race; this backend is for the
//! environments where fanotify is unavailable. The README states the
//! difference clearly.
//!
//! Spawn note: `std::process::Command::spawn` deadlocks with USER_NOTIF
//! because the parent waits for exec success while the child waits for an
//! answer. This module therefore forks and execs itself.
use crate::scan::{Decision, Engine, Why};
use crate::Event;
use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

fn exec_filter() -> [SockFilter; 9] {
    [
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 4,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_execve as u32,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_USER_NOTIF,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_execveat as u32,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_USER_NOTIF,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

/// Child handle: a pid we own and must reap.
pub struct Child {
    pub pid: i32,
    reaped: bool,
    status: Option<i32>,
}

impl Child {
    pub fn try_wait(&mut self) -> Result<Option<i32>> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        let mut st = 0;
        let r = unsafe { libc::waitpid(self.pid, &mut st, libc::WNOHANG) };
        if r < 0 {
            return Err(io::Error::last_os_error()).context("waitpid");
        }
        if r == 0 {
            return Ok(None);
        }
        self.reaped = true;
        self.status = Some(st);
        Ok(Some(st))
    }

    pub fn wait(&mut self) -> Result<i32> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let mut st = 0;
        let r = unsafe { libc::waitpid(self.pid, &mut st, 0) };
        if r < 0 {
            return Err(io::Error::last_os_error()).context("waitpid");
        }
        self.reaped = true;
        self.status = Some(st);
        Ok(st)
    }

    pub fn kill(&self) {
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }

    pub fn success(status: i32) -> bool {
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    pub fn signaled(status: i32) -> bool {
        libc::WIFSIGNALED(status)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let mut st = 0;
            unsafe { libc::waitpid(self.pid, &mut st, 0) };
        }
    }
}

/// Fork + exec `argv[0]` with `argv` under a USER_NOTIF filter.
pub fn spawn(engine: Engine, argv: &[&OsStr]) -> Result<(SeccompSession, Child)> {
    if argv.is_empty() {
        bail!("empty argv");
    }
    let mut sv = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("socketpair");
    }
    let (parent_sock, child_sock) = (sv[0], sv[1]);

    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()).context("fork"),
        0 => {
            // Child: install filter, hand listener to parent, exec.
            unsafe { libc::close(parent_sock) };
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(127) };
            }
            let filter = exec_filter();
            let prog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };
            let listener = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
                    libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    &prog as *const SockFprog as *const libc::c_void,
                )
            };
            if listener < 0 {
                unsafe { libc::_exit(127) };
            }
            if send_fd(child_sock, listener as RawFd).is_err() {
                unsafe { libc::_exit(127) };
            }
            unsafe {
                libc::close(listener as i32);
                libc::close(child_sock);
            }
            let c_argv: Vec<CString> = argv
                .iter()
                .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
                .collect();
            let mut ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };
            unsafe { libc::_exit(127) };
        }
        pid => {
            unsafe { libc::close(child_sock) };
            let listener = match recv_fd(parent_sock) {
                Ok(fd) => fd,
                Err(e) => {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    let mut st = 0;
                    unsafe { libc::waitpid(pid, &mut st, 0) };
                    unsafe { libc::close(parent_sock) };
                    return Err(e);
                }
            };
            unsafe { libc::close(parent_sock) };
            Ok((
                SeccompSession { listener, engine },
                Child {
                    pid,
                    reaped: false,
                    status: None,
                },
            ))
        }
    }
}

pub struct SeccompSession {
    listener: OwnedFd,
    engine: Engine,
}

impl SeccompSession {
    pub fn recv(&mut self) -> Result<Option<Event>> {
        let mut req = unsafe { std::mem::zeroed::<libc::seccomp_notif>() };
        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut req as *mut _,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::ENOENT) => Ok(None),
                _ => Err(e).context("SECCOMP_IOCTL_NOTIF_RECV"),
            };
        }
        let t0 = Instant::now();
        let (path, decision) = match open_target(req.pid, &req.data) {
            Ok((p, f)) => (p, self.engine.decide(&f)),
            Err(e) => (
                format!("pid={}", req.pid),
                Decision {
                    allow: false,
                    why: Why::ScanError(e.to_string()),
                    cached: false,
                    scanned_bytes: 0,
                },
            ),
        };
        let mut resp = libc::seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: if decision.allow { 0 } else { -libc::EPERM },
            flags: if decision.allow {
                libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32
            } else {
                0
            },
        };
        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &mut resp as *mut _,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOENT) {
                return Err(e).context("SECCOMP_IOCTL_NOTIF_SEND");
            }
        }
        Ok(Some(Event {
            backend: "seccomp-unotify",
            path,
            pid: req.pid as i32,
            decision,
            latency_ns: t0.elapsed().as_nanos() as u64,
        }))
    }

    pub fn run(&mut self, stop: &AtomicBool, mut on_event: impl FnMut(Event)) -> Result<()> {
        while !stop.load(Ordering::Relaxed) {
            match self.recv()? {
                Some(ev) => on_event(ev),
                None => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
        Ok(())
    }
}

fn open_target(pid: u32, data: &libc::seccomp_data) -> Result<(String, File)> {
    let path = if data.nr == libc::SYS_execve as i32 {
        read_c_string(pid, data.args[0])?
    } else {
        let p = read_c_string(pid, data.args[1])?;
        if Path::new(&p).is_absolute() {
            p
        } else {
            let dirfd = data.args[0] as i32;
            let base = if dirfd == libc::AT_FDCWD {
                std::fs::read_link(format!("/proc/{pid}/cwd"))?
            } else {
                std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}"))?
            };
            base.join(p).to_string_lossy().into_owned()
        }
    };
    let rooted = PathBuf::from(format!("/proc/{pid}/root")).join(path.trim_start_matches('/'));
    let f = File::open(&rooted).with_context(|| format!("open {}", rooted.display()))?;
    Ok((path, f))
}

fn read_c_string(pid: u32, addr: u64) -> Result<String> {
    let mut mem = File::open(format!("/proc/{pid}/mem")).context("open /proc/pid/mem")?;
    mem.seek(SeekFrom::Start(addr)).context("seek")?;
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 64];
    loop {
        let n = mem.read(&mut tmp).context("read")?;
        if n == 0 {
            break;
        }
        if let Some(i) = tmp[..n].iter().position(|&b| b == 0) {
            buf.extend_from_slice(&tmp[..i]);
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 4096 {
            bail!("pathname longer than 4096 bytes");
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let mut dummy = [0u8; 1];
    let mut cmsg = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len() as _;
    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(hdr) as *mut RawFd, fd);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    let mut dummy = [0u8; 1];
    let mut cmsg = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len() as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error()).context("recvmsg");
    }
    let hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if hdr.is_null() {
        bail!("no control message with listener fd");
    }
    let fd = unsafe { std::ptr::read(libc::CMSG_DATA(hdr) as *const RawFd) };
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
