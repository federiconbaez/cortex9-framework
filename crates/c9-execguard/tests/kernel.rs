// SPDX-License-Identifier: Apache-2.0
//! Real interception: fanotify (root) and seccomp-unotify (unprivileged).
use c9_execguard::*;
use c9_policy::compile;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn require_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged-tests need root: run under sudo"
    );
}

fn plan() -> c9_policy::Plan {
    compile(include_str!("../../../policy/cortex9.toml"))
        .unwrap()
        .plan
}

fn make_bin(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(b"#!/bin/sh\n").unwrap();
    f.write_all(body).unwrap();
    f.write_all(b"\necho ok\n").unwrap();
    drop(f);
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("c9eg{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn engine_blocks_signature_and_trusts_allowlist() {
    let dir = tmp();
    let bad = make_bin(&dir, "bad", b"hello stratum+tcp://pool.example\n");
    let clean = make_bin(&dir, "clean", b"hello world\n");
    let mut eng = Engine::new(&plan().exec).unwrap();
    let d = eng.decide(&std::fs::File::open(&bad).unwrap());
    assert!(!d.allow, "{d:?}");
    assert!(matches!(d.why, Why::Matched { .. }), "{d:?}");
    let d = eng.decide(&std::fs::File::open(&clean).unwrap());
    assert!(d.allow && matches!(d.why, Why::Clean), "{d:?}");
    let d2 = eng.decide(&std::fs::File::open(&clean).unwrap());
    assert!(d2.cached);
}

#[test]
fn fanotify_blocks_within_milliseconds() {
    require_root();
    let dir = tmp();
    assert_eq!(
        unsafe {
            let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            libc::mount(
                c.as_ptr(),
                c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0,
        "bind mount: {}",
        std::io::Error::last_os_error()
    );

    let bad = make_bin(&dir, "miner", b"XMRig/6.0\n");
    let good = make_bin(&dir, "app", b"printf hi\n");
    let eng = Engine::new(&plan().exec).unwrap();
    let mut guard = fanotify::FanotifyGuard::new(eng, &dir, false).expect("fanotify");
    let stop = Arc::new(AtomicBool::new(false));
    let events = Arc::new(Mutex::new(Vec::new()));
    let stop2 = stop.clone();
    let events2 = events.clone();
    let th = std::thread::spawn(move || {
        let _ = guard.run(&stop2, |ev| events2.lock().unwrap().push(ev));
    });
    std::thread::sleep(Duration::from_millis(50));

    // DENY: fanotify makes execve return EPERM; Command surfaces that as Err.
    let t0 = std::time::Instant::now();
    let denied = Command::new(&bad)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let deny_ms = t0.elapsed().as_secs_f64() * 1000.0;
    match denied {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        Ok(st) => assert!(!st.success(), "malicious binary must be denied, got {st}"),
    }

    let t1 = std::time::Instant::now();
    let allowed = Command::new(&good)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let allow_ms = t1.elapsed().as_secs_f64() * 1000.0;
    assert!(allowed.success(), "clean binary must run");

    stop.store(true, Ordering::Relaxed);
    let _ = th.join();
    unsafe {
        let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        libc::umount(c.as_ptr());
    }
    let ev = events.lock().unwrap();
    assert!(ev.len() >= 2, "expected >=2 events, got {}", ev.len());
    let mut lat: Vec<u64> = ev.iter().map(|e| e.latency_ns).collect();
    lat.sort_unstable();
    let p50 = percentile(&lat, 50.0).unwrap() as f64 / 1e6;
    let p99 = percentile(&lat, 99.0).unwrap() as f64 / 1e6;
    eprintln!(
        "C9-EXEC-FANOTIFY deny_ms={deny_ms:.3} allow_ms={allow_ms:.3} p50_ms={p50:.3} p99_ms={p99:.3} events={}",
        ev.len()
    );
    assert!(p99 < 100.0, "p99 {p99} ms exceeds 100 ms budget");
    assert!(deny_ms < 100.0, "end-to-end deny {deny_ms} ms");
}

fn drain_until_exit(
    session: &mut seccomp::SeccompSession,
    child: &mut seccomp::Child,
) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            while let Ok(Some(ev)) = session.recv() {
                out.push(ev);
            }
            return out;
        }
        if std::time::Instant::now() > deadline {
            child.kill();
            panic!("child did not exit within timeout; events so far: {out:?}");
        }
        match session.recv() {
            Ok(Some(ev)) => out.push(ev),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => panic!("session error: {e}"),
        }
    }
}

#[test]
fn seccomp_unotify_blocks_without_root() {
    let dir = tmp();
    let bad = make_bin(&dir, "miner", b"stratum+tcp://x\n");
    let good = make_bin(&dir, "app", b"true\n");
    let wrapper = make_bin(&dir, "wrap", b"exec \"$1\"\n");

    let eng = Engine::new(&plan().exec).unwrap();
    let (mut session, mut child) =
        seccomp::spawn(eng, &[wrapper.as_os_str(), bad.as_os_str()]).expect("spawn under seccomp");
    let ev = drain_until_exit(&mut session, &mut child);
    assert!(
        ev.iter().any(|e| !e.decision.allow),
        "expected a deny: {ev:?}"
    );

    let eng = Engine::new(&plan().exec).unwrap();
    let (mut session, mut child) =
        seccomp::spawn(eng, &[wrapper.as_os_str(), good.as_os_str()]).expect("spawn");
    let ev = drain_until_exit(&mut session, &mut child);
    assert!(
        ev.iter().all(|e| e.decision.allow),
        "expected all allow: {ev:?}"
    );
    let st = child.wait().unwrap();
    assert!(seccomp::Child::success(st), "clean child status {st:#x}");
}
