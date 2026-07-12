#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Build the bootstrap bpftool from the locked Linux v7.1 tree. Kernel-owned BPF
# sources can rely on skeleton features from the same release without compiling
# bpftool's unrelated BPF helpers or consulting the host kernel's BTF.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SRC=$("$ROOT/scripts/linux-source.sh" path)
ARCH=$(uname -m)
OUT="$ROOT/.output/linux-bpftool-$ARCH"
BPFTOOL="$OUT/bootstrap/bpftool"
STAMP="$OUT/.ebpf-labs-linux-bpftool-lock"
LOCK_ID=$(sha256sum "$ROOT/linux-source.lock.json" | cut -d' ' -f1)
HELPER_ID=$(sha256sum "$0" | cut -d' ' -f1)
EXPECTED="$LOCK_ID $HELPER_ID $ARCH"

if ! [[ -x $BPFTOOL && -r $STAMP && $(<"$STAMP") == "$EXPECTED" ]]; then
    printf 'linux-bpftool: building locked v7.1 bootstrap bpftool\n' >&2
    rm -rf -- "$OUT"
    mkdir -p "$OUT"
    env -i PATH="$PATH" HOME="${HOME:-/tmp}" LANG=C LC_ALL=C \
        make -s -C "$SRC/tools/bpf/bpftool" OUTPUT="$OUT/" bootstrap >&2
    printf '%s\n' "$EXPECTED" > "$STAMP"
fi
[[ -x $BPFTOOL ]] || {
    printf 'linux-bpftool: build did not produce %s\n' "$BPFTOOL" >&2
    exit 1
}
"$BPFTOOL" version >/dev/null
printf '%s\n' "$BPFTOOL"
