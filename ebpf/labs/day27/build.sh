#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# ANCHOR: book
#
# Day 27 build wrapper: build the EXACT upstream scx_central from the locked
# Linux v7.1 source tree, using the kernel's own tools/sched_ext Makefile.
#
# scx_central is read, not modified, on Day 27, so this builds the unmodified
# in-tree example. `O=` redirects every artifact into .output/day27/build so the
# pinned kernel source tree is never written to.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)

SRC=$("$ROOT/scripts/linux-source.sh" path)   # verified locked v7.1 tree
OUT="$ROOT/.output/day27"
VMLINUX_H=$("$ROOT/scripts/kernel-btf.sh" sched-ext)
BPFTOOL=$("$ROOT/scripts/linux-bpftool.sh")

mkdir -p "$OUT"
make -C "$SRC/tools/sched_ext" O="$OUT" \
    BPFTOOL="$BPFTOOL" VMLINUX_BTF="$VMLINUX_H" VMLINUX_H="$VMLINUX_H" \
    scx_central

BIN="$OUT/build/bin/scx_central"
test -x "$BIN"
printf 'day27: built upstream %s\n' "$BIN"
# ANCHOR_END: book
