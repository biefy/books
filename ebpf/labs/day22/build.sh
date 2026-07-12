#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# build.sh — build wrapper for the Day 22 kernel-selftest DCTCP target.
#
# The central dispatcher (scripts/build-day.sh) execs this with no arguments for
# the "kernel-selftest" backend. It does not copy the upstream program; it builds
# the in-tree selftest from a verified v7.1 kernel source tree, resolved through
# scripts/linux-source.sh (which honors $LINUX_SRC if set, else the pinned/fetched
# default) — nothing needs LINUX_SRC exported by hand.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LABS=$(cd -- "$HERE/.." && pwd)
# shellcheck source=/dev/null
. "$HERE/config.env"

JOBS=${JOBS:-$(nproc 2>/dev/null || echo 1)}

fail() { printf 'day22-build: %s\n' "$*" >&2; exit 1; }

LINUX_SRC_DIR=$("$LABS/scripts/linux-source.sh" path) ||
    fail "could not resolve a verified ${DAY22_KERNEL_TAG} kernel source (see scripts/linux-source.sh)"
SELFTEST_DIR="$LINUX_SRC_DIR/$DAY22_SELFTEST_DIR"
BUILD_DIR="$LABS/.output/day22"

[[ -f "$LINUX_SRC_DIR/$DAY22_DCTCP_SRC" ]] ||
    fail "upstream DCTCP source missing: $LINUX_SRC_DIR/$DAY22_DCTCP_SRC"
VMLINUX_H=$("$LABS/scripts/kernel-btf.sh" tcp)
BPFTOOL=$("$LABS/scripts/linux-bpftool.sh")
mkdir -p "$BUILD_DIR"

printf 'day22-build: make -j%s OUTPUT=%s %s in %s\n' \
    "$JOBS" "$BUILD_DIR" "$DAY22_DCTCP_OBJ" "$SELFTEST_DIR" >&2
# Request the generated DCTCP object directly. Building the monolithic
# test_progs runner also compiles hundreds of unrelated BPF programs and test
# modules; registration below only needs this canonical upstream object.
make -C "$SELFTEST_DIR" OUTPUT="$BUILD_DIR" \
    BPFTOOL="$BPFTOOL" VMLINUX_BTF="$VMLINUX_H" VMLINUX_H="$VMLINUX_H" \
    -j"$JOBS" "$BUILD_DIR/$DAY22_DCTCP_OBJ"

[[ -s "$BUILD_DIR/$DAY22_DCTCP_OBJ" ]] ||
    fail "DCTCP BPF object was not produced: $BUILD_DIR/$DAY22_DCTCP_OBJ"
"$BPFTOOL" btf dump file "$BUILD_DIR/$DAY22_DCTCP_OBJ" >/dev/null ||
    fail "DCTCP object has no readable BTF"
printf 'day22-build: verified %s\n' "$BUILD_DIR/$DAY22_DCTCP_OBJ" >&2
