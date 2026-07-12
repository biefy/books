#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# ANCHOR: book
#
# Day 25 build wrapper: build the EXACT upstream scx_simple from the locked
# Linux v7.1 source tree, using the kernel's own tools/sched_ext Makefile.
#
# Nothing here is repo-owned scheduler code: the point of Day 25 is to run the
# unmodified in-tree example. `O=` redirects every build artifact into
# .output/day25/build so the pinned kernel source tree is never written to.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)

SRC=$("$ROOT/scripts/linux-source.sh" path)   # verified locked v7.1 tree
OUT="$ROOT/.output/day25"
VMLINUX_H=$("$ROOT/scripts/kernel-btf.sh" sched-ext)
BPFTOOL=$("$ROOT/scripts/linux-bpftool.sh")

mkdir -p "$OUT"
make -C "$SRC/tools/sched_ext" O="$OUT" \
    BPFTOOL="$BPFTOOL" VMLINUX_BTF="$VMLINUX_H" VMLINUX_H="$VMLINUX_H" \
    scx_simple

# The kernel Makefile emits scheduler binaries under build/bin/.
BIN="$OUT/build/bin/scx_simple"
test -x "$BIN"
printf 'day25: built upstream %s\n' "$BIN"
# ANCHOR_END: book
