// SPDX-License-Identifier: Apache-2.0
use c9_execguard::*;
use c9_policy::compile;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn plan_with(extra_sig_hex: Option<&str>) -> c9_policy::ExecPlan {
    let mut src = include_str!("../../../policy/cortex9.toml").to_string();
    if let Some(h) = extra_sig_hex {
        src.push_str(&format!(
            "\n[[exec.signatures]]\nid = \"EXTRA\"\nhex = \"{h}\"\n"
        ));
    }
    compile(&src).unwrap().plan.exec
}

fn write_bin(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(body).unwrap();
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

#[test]
fn zero_false_positives_on_benign_corpus() {
    let dir = std::env::temp_dir().join(format!("c9benign{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Fixed-seed pseudo-benign corpus: ELF-ish headers, random printable text,
    // copies of /bin/sh and /bin/true if present.
    let mut rng = 0xC9E9_u64;
    let mut next = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng
    };
    for i in 0..200 {
        let mut body = Vec::new();
        match i % 5 {
            0 => {
                body.extend_from_slice(b"\x7fELF\x02\x01\x01");
                body.resize(64 + (next() as usize % 4096), 0);
            }
            1 => {
                body.extend_from_slice(b"#!/usr/bin/env bash\n");
                for _ in 0..200 {
                    body.push(b'a' + (next() % 26) as u8);
                }
            }
            2 => body.extend_from_slice(b"PK\x03\x04portable document"),
            3 => body.extend_from_slice(&next().to_le_bytes().repeat(128)),
            _ => body.extend_from_slice(b"printf 'hello world'\n"),
        }
        write_bin(&dir, &format!("b{i}"), &body);
    }
    for host in ["/bin/true", "/bin/sh", "/usr/bin/env"] {
        if let Ok(bytes) = std::fs::read(host) {
            write_bin(
                &dir,
                PathBuf::from(host).file_name().unwrap().to_str().unwrap(),
                &bytes,
            );
        }
    }
    let eng = Engine::new(&plan_with(None)).unwrap();
    let mut fp = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let d = eng.scan_path(&p).unwrap();
        if !d.allow {
            fp += 1;
            eprintln!("FP {} {:?}", p.display(), d.why);
        }
    }
    assert_eq!(fp, 0, "false positives on benign corpus");
}

#[test]
fn blocks_every_seeded_malicious_sample() {
    let dir = std::env::temp_dir().join(format!("c9mal{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let markers: &[&[u8]] = &[
        b"stratum+tcp://",
        b"/dev/tcp/0.0.0.0/",
        b"XMRig/",
        b"C9-MALWARE-TEST-MARKER",
    ];
    for (i, m) in markers.iter().enumerate() {
        let mut body = vec![0u8; 1024];
        body[100..100 + m.len()].copy_from_slice(m);
        write_bin(&dir, &format!("m{i}"), &body);
    }
    let eng = Engine::new(&plan_with(None)).unwrap();
    for e in std::fs::read_dir(&dir).unwrap() {
        let d = eng.scan_path(&e.unwrap().path()).unwrap();
        assert!(!d.allow, "{d:?}");
    }
}
