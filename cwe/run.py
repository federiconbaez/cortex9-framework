#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Memory-safety bug class matrix: the same bug written in C and in safe Rust.

For every case this compiles and runs both versions and records what
actually happened. Nothing is hard-coded except the expectation file,
which only serves to fail CI when an outcome changes.

  C:    gcc -Wall -Wextra -O2   -> accepted? how many warnings?
        gcc -fsanitize=...      -> does the bug show up at run time?
  Rust: rustc -O -C overflow-checks=on (the kernel's CONFIG_RUST_OVERFLOW_CHECKS
        default) -> compile_time (rejected), runtime_check (panics instead
        of corrupting memory) or not_prevented.
"""
import json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def c_case(src, tmp):
    exe = os.path.join(tmp, "c.bin")
    r = run(["gcc", "-std=c11", "-Wall", "-Wextra", "-O2", src, "-o", exe, "-lpthread"])
    warnings = len(re.findall(r"warning:", r.stderr))
    san = "thread" if "data-race" in src else "address,undefined"
    sexe = os.path.join(tmp, "c.san")
    s = run(["gcc", "-std=c11", "-O1", "-g", "-fno-omit-frame-pointer", f"-fsanitize={san}", src, "-o", sexe, "-lpthread"])
    detected = None
    if s.returncode == 0:
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1", TSAN_OPTIONS="halt_on_error=1")
        p = run([sexe], env=env)
        out = p.stdout + p.stderr
        detected = p.returncode != 0 and ("Sanitizer" in out or "runtime error" in out)
    return {"compiles": r.returncode == 0, "warnings": warnings, "sanitizer": san, "sanitizer_detects": detected}


def rust_case(src, tmp):
    exe = os.path.join(tmp, "r.bin")
    r = run(["rustc", "--edition", "2021", "-C", "opt-level=2", "-C", "overflow-checks=on", src, "-o", exe])
    if r.returncode != 0:
        codes = sorted(set(re.findall(r"error\[(E\d{4})\]", r.stderr)))
        first = next((l for l in r.stderr.splitlines() if l.startswith("error")), "")
        return {"outcome": "compile_time", "errors": codes, "first_error": first}
    p = run([exe])
    if p.returncode == 101 and "panicked" in p.stderr:
        msg = next((l for l in p.stderr.splitlines() if "panicked" not in l and l.strip()), "")
        return {"outcome": "runtime_check", "panic": msg.strip()}
    return {"outcome": "not_prevented", "exit": p.returncode}


def main():
    expected = json.load(open(os.path.join(HERE, "expected.json")))
    rustc = run(["rustc", "--version"]).stdout.strip()
    gcc = run(["gcc", "--version"]).stdout.splitlines()[0]
    rows, bad = [], []
    for name in sorted(os.listdir(CASES)):
        with tempfile.TemporaryDirectory() as tmp:
            c = c_case(os.path.join(CASES, name, "bug.c"), tmp)
            rs = rust_case(os.path.join(CASES, name, "bug.rs"), tmp)
        rows.append({"case": name, "c": c, "rust": rs})
        if expected.get(name) != rs["outcome"]:
            bad.append(f"{name}: expected {expected.get(name)}, measured {rs['outcome']}")
    count = lambda k: sum(1 for r in rows if r["rust"]["outcome"] == k)
    summary = {
        "cases": len(rows),
        "rust_compile_time": count("compile_time"),
        "rust_runtime_check": count("runtime_check"),
        "rust_not_prevented": count("not_prevented"),
        "c_accepted_by_gcc_wall_wextra": sum(1 for r in rows if r["c"]["compiles"]),
        "c_cases_with_any_warning": sum(1 for r in rows if r["c"]["warnings"] > 0),
        "c_detected_by_sanitizers_at_runtime": sum(1 for r in rows if r["c"]["sanitizer_detects"]),
    }
    out = {"pillar": "rust-kernel/cwe-matrix", "rustc": rustc, "gcc": gcc, "summary": summary, "cases": rows}
    dest = sys.argv[1] if len(sys.argv) > 1 else None
    if dest:
        json.dump(out, open(dest, "w"), indent=2)
    print(f"{'case':38} {'gcc':8} {'warn':>4} {'sanitizer':>9}  rust")
    for r in rows:
        c, rs = r["c"], r["rust"]
        det = {True: "yes", False: "no", None: "n/a"}[c["sanitizer_detects"]]
        extra = ",".join(rs.get("errors", [])) if rs["outcome"] == "compile_time" else ""
        print(f"{r['case']:38} {'accepts' if c['compiles'] else 'rejects':8} {c['warnings']:>4} {det:>9}  {rs['outcome']} {extra}")
    print(json.dumps(summary))
    if bad:
        print("OUTCOME CHANGED:\n  " + "\n  ".join(bad), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
