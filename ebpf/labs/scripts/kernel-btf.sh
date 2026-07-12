#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Produce a small, deterministic BTF source from the locked Linux tree.
# Upstream BPF tool Makefiles normally read /sys/kernel/btf/vmlinux, which makes
# compilation depend on the host kernel. Linux v7.1 builds the relevant types
# into aggregate objects; encoding those objects' DWARF as BTF supplies the
# exact compile-time type universe without building a complete bootable kernel.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SRC=$("$ROOT/scripts/linux-source.sh" path)
LOCK="$ROOT/linux-source.lock.json"
ARCH=$(uname -m)
OUT="$ROOT/.output/kernel-btf-$ARCH"
STAMP="$OUT/.ebpf-labs-kernel-lock"
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 1)}
LOCK_ID=$(sha256sum "$LOCK" | cut -d' ' -f1)
HELPER_ID=$(sha256sum "$0" | cut -d' ' -f1)
EXPECTED="$LOCK_ID $HELPER_ID $ARCH"
MODE=${1:-}

fail() { printf 'kernel-btf: %s\n' "$*" >&2; exit 1; }

case $MODE in
    sched-ext)
        TARGET=kernel/sched/build_policy.o
        ;;
    tcp)
        TARGET=net/ipv4/bpf_tcp_ca.o
        ;;
    *)
        fail 'usage: kernel-btf.sh {sched-ext|tcp}'
        ;;
esac
OBJECT="$OUT/$TARGET"
HEADER="$OUT/$MODE-vmlinux.h"
BPFTOOL="$ROOT/.output/bpftool/bootstrap/bpftool"

prepare_tree() {
    if [[ -f $STAMP ]] && [[ $(<"$STAMP") == "$EXPECTED" ]] &&
       grep -qx 'CONFIG_DEBUG_INFO_BTF=y' "$OUT/.config" 2>/dev/null &&
       grep -qx 'CONFIG_SCHED_CLASS_EXT=y' "$OUT/.config" 2>/dev/null; then
        return
    fi

    printf 'kernel-btf: preparing locked Linux types in %s\n' "$OUT" >&2
    rm -rf -- "$OUT"
    mkdir -p "$OUT"
    make -s -C "$SRC" O="$OUT" defconfig
    "$SRC/scripts/config" --file "$OUT/.config" \
        -d DEBUG_INFO_REDUCED \
        -e DEBUG_INFO \
        -e DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
        -e DEBUG_INFO_BTF \
        -e BPF_SYSCALL \
        -e BPF_JIT
    make -s -C "$SRC" O="$OUT" olddefconfig
    "$SRC/scripts/config" --file "$OUT/.config" -e SCHED_CLASS_EXT
    make -s -C "$SRC" O="$OUT" olddefconfig prepare

    grep -qx 'CONFIG_DEBUG_INFO_BTF=y' "$OUT/.config" ||
        fail 'locked kernel config did not enable CONFIG_DEBUG_INFO_BTF'
    grep -qx 'CONFIG_SCHED_CLASS_EXT=y' "$OUT/.config" ||
        fail 'locked kernel config did not enable CONFIG_SCHED_CLASS_EXT'
    printf '%s\n' "$EXPECTED" > "$STAMP"
}

prepare_tree
if ! [[ -s $OBJECT ]] ||
   ! readelf --sections --wide "$OBJECT" 2>/dev/null | grep -q '[.]BTF'; then
    printf 'kernel-btf: building %s\n' "$TARGET" >&2
    make -s -C "$SRC" O="$OUT" -j"$JOBS" "$TARGET"
    pahole -J "$OBJECT"
fi
readelf --sections --wide "$OBJECT" | grep -q '[.]BTF' ||
    fail "$OBJECT has no BTF section"

# Use the repository's independently pinned bpftool. The narrow kernel BTF is
# intentionally only the type source for the lab, not for bpftool's own helper
# programs (which require many unrelated iterator types).
make -s -C "$ROOT" "$BPFTOOL" >&2
if ! [[ -s $HEADER && $HEADER -nt $OBJECT ]]; then
    TMP="$HEADER.tmp"
    "$BPFTOOL" btf dump file "$OBJECT" format c > "$TMP"
    python3 - "$TMP" "$MODE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
mode = sys.argv[2]
text = path.read_text()
marker = '\n#endif /* __VMLINUX_H__ */'
if marker not in text:
    raise SystemExit('kernel-btf: generated vmlinux.h has no include-guard terminator')

if mode == 'sched-ext':
    extra = '''

/* Linux v7.1 iterator states omitted from the scheduler aggregate's BTF. */
struct bpf_iter_bits { /* kernel/bpf/helpers.c:3369 */
	__u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_iter_num { /* include/uapi/linux/bpf.h:7669 */
	__u64 __opaque[1];
} __attribute__((aligned(8)));

struct bpf_timer { /* include/uapi/linux/bpf.h:7472 */
	__u64 __opaque[2];
} __attribute__((aligned(8)));

#define BPF_MAX_LOOPS (8 * 1024 * 1024) /* include/linux/bpf.h:2268 */
#define BPF_F_TIMER_CPU_PIN (1ULL << 1)  /* include/uapi/linux/bpf.h:7665 */
'''
elif mode == 'tcp':
    extra = '''

/* Linux v7.1 constants that DWARF/BTF does not retain in this aggregate. */
#define BPF_F_NO_PREALLOC (1U << 0) /* include/uapi/linux/bpf.h:1402 */
#define TCP_CA_Recovery 3           /* include/uapi/linux/tcp.h:220 */
#define ICSK_ACK_TIMER 2            /* include/net/inet_connection_sock.h:164 */
#define ICSK_ACK_NOW 16             /* include/net/inet_connection_sock.h:167 */
'''
else:
    raise SystemExit(f'kernel-btf: unsupported mode {mode}')

path.write_text(text.replace(marker, extra + marker, 1))
PY
    mv "$TMP" "$HEADER"
fi
[[ -s $HEADER ]] || fail "failed to generate $HEADER"
case $MODE in
    sched-ext)
        for type in bpf_iter_bits bpf_iter_num bpf_timer; do
            grep -q "^struct $type {" "$HEADER" ||
                fail "$HEADER has no $type definition"
        done
        for constant in BPF_MAX_LOOPS BPF_F_TIMER_CPU_PIN; do
            grep -q "^#define $constant " "$HEADER" ||
                fail "$HEADER has no $constant definition"
        done
        ;;
    tcp)
        for constant in BPF_F_NO_PREALLOC TCP_CA_Recovery ICSK_ACK_TIMER ICSK_ACK_NOW; do
            grep -q "^#define $constant " "$HEADER" ||
                fail "$HEADER has no $constant definition"
        done
        ;;
esac
printf 'kernel-btf: verified %s\n' "$HEADER" >&2
printf '%s\n' "$HEADER"
