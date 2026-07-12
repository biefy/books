#!/usr/bin/env bash
set -u

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME=0
ERRORS=0
CLANG=${CLANG:-clang}
CC=${CC:-cc}

usage() {
    printf 'usage: %s [--runtime]\n' "$0"
}

fail() {
    printf 'preflight: %s\n' "$*" >&2
    ERRORS=$((ERRORS + 1))
}

check_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

case ${1:-} in
    '') ;;
    --runtime) RUNTIME=1 ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [[ $(uname -s) != Linux ]]; then
    fail 'the lab toolchain is supported on Linux only'
fi

for command_name in git make "$CLANG" "$CC"; do
    check_command "$command_name"
done

LOCK="$ROOT/bootstrap.commit"
VENDOR="$ROOT/vendor/libbpf-bootstrap"
if [[ ! -r $LOCK ]]; then
    fail "missing dependency lock: $LOCK"
elif [[ ! -d $VENDOR/.git && ! -f $VENDOR/.git ]]; then
    fail 'libbpf-bootstrap submodule is not initialized; run git submodule update --init --recursive'
else
    expected=$(tr -d '[:space:]' < "$LOCK")
    actual=$(git -C "$VENDOR" rev-parse HEAD 2>/dev/null || true)
    if [[ $actual != "$expected" ]]; then
        fail "libbpf-bootstrap is at ${actual:-unknown}, expected $expected"
    fi

    nested_status=$(git -C "$VENDOR" submodule status --recursive 2>/dev/null || true)
    if [[ -z $nested_status ]]; then
        fail 'nested libbpf-bootstrap submodules are unavailable'
    elif grep -Eq '^[-+U]' <<<"$nested_status"; then
        fail 'nested libbpf-bootstrap submodules are missing or at the wrong commit'
    fi

    dirty_status=$(git -C "$VENDOR" status --porcelain --ignore-submodules=none 2>/dev/null || true)
    if [[ -n $dirty_status ]]; then
        fail 'libbpf-bootstrap or a nested dependency has local changes'
    fi
fi

for required in \
    "$VENDOR/libbpf/src/Makefile" \
    "$VENDOR/bpftool/src/Makefile"; do
    [[ -r $required ]] || fail "missing vendored build input: $required"
done

machine=$(uname -m)
case $machine in
    x86_64) arch=x86 ;;
    aarch64) arch=arm64 ;;
    arm*) arch=arm ;;
    ppc64le) arch=powerpc ;;
    mips*) arch=mips ;;
    riscv64) arch=riscv ;;
    loongarch64) arch=loongarch ;;
    *) arch=$machine ;;
esac
VMLINUX="$VENDOR/vmlinux.h/include/$arch/vmlinux.h"
[[ -r $VMLINUX ]] || fail "no pinned vmlinux.h for architecture $machine (mapped to $arch)"

if command -v "$CLANG" >/dev/null 2>&1; then
    clang_version=$("$CLANG" --version 2>/dev/null || true)
    if [[ $clang_version =~ version[[:space:]]+([0-9]+) ]]; then
        (( BASH_REMATCH[1] >= 17 )) || fail "clang 17 or newer is required (found ${BASH_REMATCH[1]})"
    else
        fail 'could not determine clang version'
    fi

    targets=$("$CLANG" --print-targets 2>/dev/null || true)
    grep -Eq '(^|[[:space:]])bpf([[:space:]]|$)' <<<"$targets" ||
        fail 'clang does not advertise the BPF target'
fi

if command -v "$CC" >/dev/null 2>&1; then
    printf '#include <libelf.h>\n#include <zlib.h>\nint main(void) { return 0; }\n' |
        "$CC" -x c -fsyntax-only - >/dev/null 2>&1 ||
        fail 'C compiler cannot find libelf and zlib development headers'
fi

if (( RUNTIME )); then
    [[ -r /sys/kernel/btf/vmlinux ]] || fail 'runtime kernel does not expose /sys/kernel/btf/vmlinux'
fi

if (( ERRORS )); then
    printf 'preflight: %d check(s) failed\n' "$ERRORS" >&2
    exit 1
fi

printf 'preflight: OK (Linux %s, BPF arch %s, bootstrap %s)\n' \
    "$machine" "$arch" "$(tr -d '[:space:]' < "$LOCK")"
