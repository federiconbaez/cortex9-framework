// SPDX-License-Identifier: Apache-2.0
//! Compiles bpf/xdp_fw.bpf.c with clang. A missing toolchain is a hard error.
use std::{env, path::PathBuf, process::Command};

fn main() {
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../bpf/xdp_fw.bpf.c");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("xdp_fw.o");
    println!("cargo:rerun-if-changed={}", src.display());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        other => panic!("unsupported target arch {other}"),
    };
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-Wall", "-Werror", "-target", "bpf"])
        .arg(format!("-I/usr/include/{arch}"))
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("cannot run {clang} to build the XDP program: {e}"));
    assert!(
        status.success(),
        "clang failed to compile {}",
        src.display()
    );
}
