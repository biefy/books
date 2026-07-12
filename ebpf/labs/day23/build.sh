#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# build.sh — build wrapper for the Day 23 repo-owned DCTCP telemetry derivative.
#
# The central dispatcher (scripts/build-day.sh) execs this with no arguments for
# the "kernel-derivative" backend. The derivative uses the shared vendored
# libbpf toolchain, but compiles against the deterministic TCP type header built
# from the locked Linux v7.1 tree. The shared Makefile then produces the loader,
# BPF object, and skeleton.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${OUTPUT:-.output}
if [[ $OUTPUT == /* ]]; then
    OUTPUT_DIR=$OUTPUT
else
    OUTPUT_DIR="$ROOT/$OUTPUT"
fi

TYPE_SOURCE=$("$ROOT/scripts/kernel-btf.sh" tcp)
TYPE_DIR="$OUTPUT_DIR/day23/kernel-types"
VMLINUX="$TYPE_DIR/vmlinux.h"
mkdir -p "$TYPE_DIR"
cp "$TYPE_SOURCE" "$VMLINUX"

exec make -C "$ROOT" OUTPUT="$OUTPUT_DIR" VMLINUX="$VMLINUX" \
    "$OUTPUT_DIR/day23/logged_dctcp"
