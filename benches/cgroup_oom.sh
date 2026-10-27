#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOG=${HOG:-$ROOT/target/release/c9-hog}
OUT=${1:-/tmp/cgroup-bench.json}
[[ $(id -u) -eq 0 ]] || { echo "FATAL: need root" >&2; exit 2; }
command -v "$HOG" >/dev/null || { echo "FATAL: $HOG missing" >&2; exit 2; }
PARENT=/sys/fs/cgroup
NAME=c9bench-$$
mkdir "$PARENT/$NAME"
echo "+memory +pids" > "$PARENT/$NAME/cgroup.subtree_control"
# canary outside
"$HOG" canary 5000 > /tmp/c9canary-$$.out &
CAN=$!
# run via the library test binary path: use a tiny python driver calling the same syscalls
python3 - "$PARENT" "$NAME" "$HOG" "$OUT" "$CAN" <<'PY'
import json, os, signal, subprocess, sys, time
parent, name, hog, out, can = sys.argv[1:6]
can = int(can)
cg = f"{parent}/{name}/hog"
os.mkdir(cg)
open(f"{cg}/memory.max","w").write(str(128<<20))
open(f"{cg}/memory.swap.max","w").write("0")
open(f"{cg}/memory.oom.group","w").write("1")
open(f"{cg}/pids.max","w").write("16")
host_before = int([l.split()[1] for l in open("/proc/vmstat") if l.startswith("oom_kill ")][0])
t0 = time.time()
p = subprocess.Popen([hog, "load", "512", "8"], stdout=subprocess.DEVNULL)
open(f"{cg}/cgroup.procs","w").write(str(p.pid))
rc = p.wait(timeout=30)
elapsed = time.time() - t0
events = dict(l.split() for l in open(f"{cg}/memory.events"))
oom = int(events.get("oom_kill", 0))
host_after = int([l.split()[1] for l in open("/proc/vmstat") if l.startswith("oom_kill ")][0])
canary_alive = os.path.exists(f"/proc/{can}")
os.kill(can, signal.SIGTERM)
json.dump({
  "pillar": "cgroup",
  "exit_signal_or_code": rc,
  "oom_kills_in_cgroup": oom,
  "host_oom_delta": host_after - host_before,
  "canary_survived": canary_alive,
  "memory_max_bytes": 128<<20,
  "elapsed_ms": int(elapsed*1000),
}, open(out,"w"), indent=2)
print(open(out).read())
assert rc != 0 and oom >= 1 and canary_alive and host_after - host_before == oom
PY
# cleanup
echo 1 > "$PARENT/$NAME/hog/cgroup.kill" 2>/dev/null || true
sleep 0.1
rmdir "$PARENT/$NAME/hog" 2>/dev/null || true
rmdir "$PARENT/$NAME" 2>/dev/null || true
