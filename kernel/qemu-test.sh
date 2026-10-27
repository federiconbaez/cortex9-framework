#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot a kernel in QEMU, insmod the Rust classifier and run the differential
# check against the userspace engine. Fails loudly on any missing piece.
#
#   kernel/qemu-test.sh <bzImage> <c9_classifier.ko> <c9-kmod-check> [out.json]
set -euo pipefail
BZ=${1:?bzImage}; KO=${2:?module}; CHK=${3:?checker}; OUT=${4:-}
BUSYBOX=$(command -v busybox) || { echo "FATAL: busybox not found" >&2; exit 2; }
command -v qemu-system-x86_64 >/dev/null || { echo "FATAL: qemu-system-x86_64 not found" >&2; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"/{bin,dev,proc,sys}
cp "$BUSYBOX" "$work/root/bin/busybox"
for a in sh mount insmod dmesg cat grep poweroff mkdir; do ln -s busybox "$work/root/bin/$a"; done
cp "$KO" "$work/root/c9_classifier.ko"
cp "$CHK" "$work/root/c9-kmod-check"
cat > "$work/root/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
echo "C9-BOOT kernel=$(cat /proc/sys/kernel/osrelease)"
if insmod /c9_classifier.ko; then echo "C9-INSMOD ok"; else echo "C9-INSMOD failed"; fi
dmesg | grep "c9:"
/c9-kmod-check /dev/c9-classify 20000 12601449
echo "C9-CHECK-EXIT $?"
poweroff -f
INIT
chmod +x "$work/root/init"
(cd "$work/root" && find . | cpio -o -H newc --quiet | gzip -9) > "$work/initrd.gz"

accel=(-accel tcg)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); fi
echo "qemu accel: ${accel[*]}"
start=$(date +%s.%N)
timeout 600 qemu-system-x86_64 "${accel[@]}" -m 512 -smp 2 -nographic -no-reboot \
  -kernel "$BZ" -initrd "$work/initrd.gz" \
  -append "console=ttyS0 panic=-1 quiet loglevel=4" | tee "$work/console.log"
end=$(date +%s.%N)

grep -q "C9-INSMOD ok" "$work/console.log" || { echo "FATAL: module did not load" >&2; exit 1; }
grep -q "c9: selftest ok" "$work/console.log" || { echo "FATAL: in-kernel selftest failed" >&2; exit 1; }
line=$(grep -a "C9-KMOD-RESULT" "$work/console.log" | tr -d '\r') || { echo "FATAL: checker did not run" >&2; exit 1; }
grep -q "C9-CHECK-EXIT 0" "$work/console.log" || { echo "FATAL: kernel and userspace disagree" >&2; exit 1; }
echo "$line"
if [ -n "$OUT" ]; then
  python3 - "$line" "$OUT" "$(grep -a C9-BOOT "$work/console.log" | tr -d '\r')" "${accel[*]}" <<'PY'
import json, sys
line, out, boot, accel = sys.argv[1:5]
kv = dict(t.split("=", 1) for t in line.split()[1:])
json.dump({"pillar": "rust-kernel", "kernel": boot.split("=", 1)[1], "qemu_accel": accel,
           "agree": int(kv.pop("agree")), "total": int(kv.pop("total")), "seed": int(kv.pop("seed")),
           "verdict_histogram": {k: int(v) for k, v in kv.items()}}, open(out, "w"), indent=2)
PY
fi
