#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Download, verify and build a minimal CONFIG_RUST=y kernel for the QEMU test.
#   kernel/build-kernel.sh <workdir>
# Produces <workdir>/out/arch/x86/boot/bzImage and a tree usable as KDIR.
set -euo pipefail
VER=7.2.13
SHA256=08e7b0c4f2dd1971f972da274b5e589a98989390ac56acd7a1a5af922363ea6c
W=${1:?workdir}
mkdir -p "$W"; cd "$W"
if [ ! -d "linux-$VER" ]; then
  curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$VER.tar.xz" -o "linux-$VER.tar.xz"
  echo "$SHA256  linux-$VER.tar.xz" | sha256sum -c -
  tar xf "linux-$VER.tar.xz"
fi
cd "linux-$VER"
make LLVM=1 rustavailable
make LLVM=1 O=../out tinyconfig
./scripts/config --file ../out/.config \
  -e 64BIT -e MODULES -e MODULE_UNLOAD -e PRINTK -e TTY -e SERIAL_8250 -e SERIAL_8250_CONSOLE \
  -e BLK_DEV_INITRD -e RD_GZIP -e BINFMT_ELF -e BINFMT_SCRIPT -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e PROC_FS -e SYSFS -e TMPFS -e MULTIUSER -e FUTEX -e EPOLL -e EARLY_PRINTK -e ACPI -e PCI \
  -e RUST -d MODVERSIONS -d RANDSTRUCT -e RANDSTRUCT_NONE
make LLVM=1 O=../out olddefconfig
grep -q '^CONFIG_RUST=y' ../out/.config || { echo "FATAL: CONFIG_RUST did not stick" >&2; exit 1; }
make LLVM=1 O=../out -j"$(nproc)"
