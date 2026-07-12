#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Day 26 build wrapper: compile the repo-owned scx_priority derivative against
# the locked Linux v7.1 sched_ext support (libbpf, bpftool, vmlinux.h, and the
# scx/*.h BPF headers), WITHOUT modifying the pinned kernel source tree.
#
# Strategy:
#   1. Build the stock scx_simple once with the kernel's own tools/sched_ext
#      Makefile, redirecting all output to .output/day26 via O=. That
#      materialises the exact toolchain the upstream schedulers use:
#      libbpf.a, a bootstrap bpftool, and a generated vmlinux.h.
#   2. Compile scx_priority.bpf.c and generate its skeleton by driving the
#      stock pattern rules with VPATH pointed at this lab directory (the .bpf.o
#      / .bpf.skel.h rules use $< and honour VPATH).
#   3. Compile and link the userspace driver with the same CFLAGS the sched_ext
#      Makefile uses for its C schedulers.
#
# This is a build utility, not a chapter listing; the reader-facing sources are
# scx_priority.bpf.c, scx_priority.c, and run.sh.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)

SRC=$("$ROOT/scripts/linux-source.sh" path)
SEXT="$SRC/tools/sched_ext"
OUT="$ROOT/.output/day26"
BUILD="$OUT/build"
VMLINUX_H=$("$ROOT/scripts/kernel-btf.sh" sched-ext)
BPFTOOL=$("$ROOT/scripts/linux-bpftool.sh")
CLANG=${CLANG:-clang}
CC=${CC:-cc}

mkdir -p "$OUT"

# 1. Shared sched_ext toolchain + baseline (also proves the base still builds).
make -C "$SEXT" O="$OUT" \
    BPFTOOL="$BPFTOOL" VMLINUX_BTF="$VMLINUX_H" VMLINUX_H="$VMLINUX_H" \
    scx_simple

# 2. Derivative BPF object + struct_ops skeleton via the stock rules (VPATH lets
#    make find our .bpf.c without copying it into the kernel tree).
make -C "$SEXT" O="$OUT" VPATH="$HERE" \
    BPFTOOL="$BPFTOOL" VMLINUX_BTF="$VMLINUX_H" VMLINUX_H="$VMLINUX_H" \
    "$BUILD/include/scx_priority.bpf.skel.h"

# 3. Userspace driver, matching tools/sched_ext/Makefile CFLAGS/LDFLAGS.
INCLUDES=(
	-I"$BUILD/include"
	-I"$SRC/include/generated"
	-I"$SRC/tools/lib"
	-I"$SRC/tools/include"
	-I"$SRC/tools/include/uapi"
	-I"$SEXT/include"
)
mkdir -p "$BUILD/obj/sched_ext" "$BUILD/bin"
"$CC" -g -O2 -rdynamic -pthread -Wall "${INCLUDES[@]}" \
	-c "$HERE/scx_priority.c" -o "$BUILD/obj/sched_ext/scx_priority.o"
"$CC" -o "$BUILD/bin/scx_priority" \
	"$BUILD/obj/sched_ext/scx_priority.o" \
	"$BUILD/obj/libbpf/libbpf.a" \
	-lelf -lz -lpthread

test -x "$BUILD/bin/scx_priority"
printf 'day26: built %s\n' "$BUILD/bin/scx_priority"
