#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run.sh — Day 22 operator for the kernel's in-tree BPF DCTCP struct_ops
# selftest. It does not copy the upstream program; it drives the artifacts that
# day22/build.sh produced from a verified v7.1 kernel source tree (resolved via
# scripts/linux-source.sh — no need to export LINUX_SRC).
#
# Subcommands (each owns only what it creates):
#   selftest    (default) temporarily register the canonical DCTCP object,
#               verify it appears, then unregister it and remove owned state
#   available   print tcp_available_congestion_control
#   register    register bpf_dctcp.bpf.o into the owned bpffs pin dir (persists)
#   inspect     bpftool struct_ops list / dump name dctcp
#   unregister  unregister the algorithm and remove the (empty) pin dir
#
# Privileged subcommands (selftest/register/inspect/unregister) are opt-in and
# require root, mirroring scripts/smoke.sh.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LABS=$(cd -- "$HERE/.." && pwd)
# shellcheck source=/dev/null
. "$HERE/config.env"

SELFTEST_DIR=
BUILD_DIR="$LABS/.output/day22"
SELFTEST_ACTIVE=0
SELFTEST_PIN=

log() { printf 'day22: %s\n' "$*" >&2; }
fail() { printf 'day22: %s\n' "$*" >&2; exit 1; }

require_priv() {
    if [[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} != 1 ]]; then
        fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge privileged BPF operations'
    fi
    (( EUID == 0 )) || fail 'run with sudo after setting EBPF_LABS_ALLOW_PRIVILEGED=1'
}

require_struct_ops() {
    require_priv
    [[ ${EBPF_LABS_ALLOW_STRUCT_OPS:-0} == 1 ]] ||
        fail 'set EBPF_LABS_ALLOW_STRUCT_OPS=1 to acknowledge TCP struct_ops registration'
}

resolve_tree() {
    [[ -n $SELFTEST_DIR ]] && return
    local src
    src=$("$LABS/scripts/linux-source.sh" path) ||
        fail "could not resolve a verified ${DAY22_KERNEL_TAG} kernel source"
    SELFTEST_DIR="$src/$DAY22_SELFTEST_DIR"
    [[ -d $SELFTEST_DIR ]] || fail "selftest tree not found: $SELFTEST_DIR"
}

cleanup_selftest() {
    local status=$?
    trap - EXIT INT TERM
    if (( SELFTEST_ACTIVE )); then
        bpftool struct_ops unregister name "$DAY22_VTABLE_OK" 2>/dev/null || true
    fi
    [[ -z $SELFTEST_PIN ]] || rmdir "$SELFTEST_PIN" 2>/dev/null || true
    exit "$status"
}

cmd_selftest() {
    require_struct_ops
    resolve_tree
    [[ -s "$BUILD_DIR/$DAY22_DCTCP_OBJ" ]] ||
        fail "run 'day22/build.sh' first: missing $BUILD_DIR/$DAY22_DCTCP_OBJ"
    command -v bpftool >/dev/null 2>&1 || fail 'bpftool is required at runtime'
    grep -qw "$DAY22_CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control &&
        fail "$DAY22_CC_NAME is already registered; refusing to unregister state this run does not own"

    SELFTEST_PIN="${DAY22_PIN_DIR}-selftest-$$"
    [[ ! -e $SELFTEST_PIN ]] || fail "owned pin directory already exists: $SELFTEST_PIN"
    mkdir "$SELFTEST_PIN"
    SELFTEST_ACTIVE=1
    trap cleanup_selftest EXIT INT TERM

    log "temporarily registering $DAY22_DCTCP_OBJ"
    # The intentionally incomplete dctcp_nouse vtable can make bpftool return
    # non-zero after the valid dctcp vtable has registered, so assert state.
    bpftool struct_ops register "$BUILD_DIR/$DAY22_DCTCP_OBJ" "$SELFTEST_PIN" || true
    grep -qw "$DAY22_CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control ||
        fail "$DAY22_CC_NAME did not appear in tcp_available_congestion_control"

    bpftool struct_ops unregister name "$DAY22_VTABLE_OK"
    SELFTEST_ACTIVE=0
    rmdir "$SELFTEST_PIN"
    SELFTEST_PIN=
    ! grep -qw "$DAY22_CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control ||
        fail "$DAY22_CC_NAME remained registered after cleanup"
    trap - EXIT INT TERM
    log "temporary registration verified and removed"
}

cmd_available() {
    cat /proc/sys/net/ipv4/tcp_available_congestion_control
}

cmd_register() {
    require_struct_ops
    resolve_tree
    [[ -f "$BUILD_DIR/$DAY22_DCTCP_OBJ" ]] ||
        fail "run 'day22/build.sh' first: missing $BUILD_DIR/$DAY22_DCTCP_OBJ"
    [[ ! -e $DAY22_PIN_DIR ]] ||
        fail "refusing to adopt existing pin directory: $DAY22_PIN_DIR"
    mkdir "$DAY22_PIN_DIR"
    log "registering $DAY22_DCTCP_OBJ (the $DAY22_VTABLE_REJECT decoy is expected to be rejected)"
    # bpftool prints a non-fatal error for the incomplete dctcp_nouse vtable and
    # still registers the valid one, so tolerate its non-zero exit.
    bpftool struct_ops register "$BUILD_DIR/$DAY22_DCTCP_OBJ" "$DAY22_PIN_DIR" || true
    grep -qw "$DAY22_CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control ||
        fail "$DAY22_CC_NAME did not appear in tcp_available_congestion_control"
    log "$DAY22_CC_NAME is now registered (run '$0 unregister' when done)"
}

cmd_inspect() {
    require_priv
    bpftool struct_ops list
    bpftool struct_ops dump name "$DAY22_VTABLE_OK"
}

cmd_unregister() {
    require_priv
    log "unregistering $DAY22_VTABLE_OK and removing $DAY22_PIN_DIR"
    bpftool struct_ops unregister name "$DAY22_VTABLE_OK" 2>/dev/null || true
    if [[ -d $DAY22_PIN_DIR ]]; then
        rmdir "$DAY22_PIN_DIR" ||
            fail "pin directory is not empty; refusing recursive removal: $DAY22_PIN_DIR"
    fi
}

case ${1:-selftest} in
    selftest)   cmd_selftest ;;
    available)  cmd_available ;;
    register)   cmd_register ;;
    inspect)    cmd_inspect ;;
    unregister) cmd_unregister ;;
    *)
        printf 'usage: %s {selftest|available|register|inspect|unregister}\n' "$0" >&2
        exit 2
        ;;
esac
