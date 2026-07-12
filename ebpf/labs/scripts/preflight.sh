#!/usr/bin/env bash
set -u

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME=0
KERNEL=0
ERRORS=0
CLANG=${CLANG:-clang}
CC=${CC:-cc}

usage() {
    printf 'usage: %s [--kernel] [--runtime]\n' "$0"
}

fail() {
    printf 'preflight: %s\n' "$*" >&2
    ERRORS=$((ERRORS + 1))
}

check_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

check_submodule() {
    local name=$1 vendor=$2 lock=$3 expected actual nested dirty

    if [[ ! -r $lock ]]; then
        fail "missing dependency lock: $lock"
    elif [[ ! -d $vendor/.git && ! -f $vendor/.git ]]; then
        fail "$name submodule is not initialized; run git submodule update --init --recursive"
    else
        expected=$(tr -d '[:space:]' < "$lock")
        actual=$(git -C "$vendor" rev-parse HEAD 2>/dev/null || true)
        [[ $actual == "$expected" ]] ||
            fail "$name is at ${actual:-unknown}, expected $expected"

        nested=$(git -C "$vendor" submodule status --recursive 2>/dev/null || true)
        if [[ -z $nested ]]; then
            fail "$name nested submodules are unavailable"
        elif grep -Eq '^[-+U]' <<<"$nested"; then
            fail "$name nested submodules are missing or at the wrong commit"
        fi

        dirty=$(git -C "$vendor" status --porcelain --ignore-submodules=none 2>/dev/null || true)
        [[ -z $dirty ]] || fail "$name or a nested dependency has local changes"
    fi
}

while (($#)); do
    case $1 in
        --kernel) KERNEL=1 ;;
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
    shift
done

if [[ $(uname -s) != Linux ]]; then
    fail 'the lab toolchain is supported on Linux only'
fi

for command_name in git make python3 "$CLANG" "$CC"; do
    check_command "$command_name"
done

BOOTSTRAP_VENDOR="$ROOT/vendor/libbpf-bootstrap"
XDP_VENDOR="$ROOT/vendor/xdp-tools"
check_submodule libbpf-bootstrap "$BOOTSTRAP_VENDOR" "$ROOT/bootstrap.commit"
check_submodule xdp-tools "$XDP_VENDOR" "$ROOT/xdp-tools.commit"

for required in \
    "$BOOTSTRAP_VENDOR/libbpf/src/Makefile" \
    "$BOOTSTRAP_VENDOR/bpftool/src/Makefile" \
    "$XDP_VENDOR/lib/libxdp/Makefile" \
    "$XDP_VENDOR/headers/xdp/xsk.h"; do
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
VMLINUX="$BOOTSTRAP_VENDOR/vmlinux.h/include/$arch/vmlinux.h"
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
    printf '#include <libelf.h>\n#include <zlib.h>\n#include <pcap/dlt.h>\nint main(void) { return 0;}\n' |
        "$CC" -x c -fsyntax-only - >/dev/null 2>&1 ||
        fail 'C compiler cannot find libelf, zlib, and libpcap development headers'
fi

if (( KERNEL )); then
    for command_name in bc bison flex pahole readelf rsync sha256sum; do
        check_command "$command_name"
    done

    make_version=$(make --version 2>/dev/null || true)
    if [[ $make_version =~ GNU[[:space:]]Make[[:space:]]([0-9]+)\. ]]; then
        (( BASH_REMATCH[1] >= 4 )) ||
            fail "Linux v7.1 requires GNU Make 4 or newer (found ${BASH_REMATCH[1]})"
    else
        fail 'kernel backends require GNU Make 4 or newer'
    fi
    "$ROOT/scripts/linux-source.sh" verify >/dev/null 2>&1 ||
        fail 'locked Linux v7.1 source is unavailable; run scripts/linux-source.sh fetch or set LINUX_SRC'
fi

if (( RUNTIME )); then
    [[ -r /sys/kernel/btf/vmlinux ]] || fail 'runtime kernel does not expose /sys/kernel/btf/vmlinux'
    [[ -d /sys/fs/cgroup ]] || fail 'runtime host has no cgroup filesystem'
fi

if (( ERRORS )); then
    printf 'preflight: %d check(s) failed\n' "$ERRORS" >&2
    exit 1
fi

printf 'preflight: OK (Linux %s, BPF arch %s, bootstrap %s, xdp-tools %s)\n' \
    "$machine" "$arch" \
    "$(tr -d '[:space:]' < "$ROOT/bootstrap.commit")" \
    "$(tr -d '[:space:]' < "$ROOT/xdp-tools.commit")"
