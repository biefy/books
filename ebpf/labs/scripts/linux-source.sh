#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
LOCK="$ROOT/linux-source.lock.json"
OUTPUT="$ROOT/.output"

read_lock() {
    python3 - "$LOCK" "$1" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)[sys.argv[2]])
PY
}

VERSION=$(read_lock version)
URL=$(read_lock url)
SHA256=$(read_lock sha256)
GIT_COMMIT=$(read_lock git_commit)
DEFAULT_SOURCE="$OUTPUT/linux-$VERSION"
SOURCE=${LINUX_SRC:-$DEFAULT_SOURCE}
MARKER=.practical-ebpf-source-lock

fail() {
    printf 'linux-source: %s\n' "$*" >&2
    exit 1
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        fail 'sha256sum or shasum is required'
    fi
}

verify_source() {
    local source=$1 release actual marker toplevel

    [[ -r "$source/Makefile" ]] || fail "missing Linux source at $source"
    source=$(cd -- "$source" && pwd -P)
    release=$(python3 - "$source/Makefile" <<'PY'
import re
import sys
values = {}
for line in open(sys.argv[1], encoding="utf-8"):
    match = re.match(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*?)\s*$", line)
    if match:
        values[match.group(1)] = match.group(2)
base = f"{values.get('VERSION', '')}.{values.get('PATCHLEVEL', '')}"
sublevel = values.get("SUBLEVEL", "0")
if sublevel != "0":
    base += f".{sublevel}"
print(base + values.get("EXTRAVERSION", ""))
PY
)
    [[ $release == "$VERSION" ]] ||
        fail "$source reports kernel release ${release:-unknown}, expected $VERSION"

    toplevel=$(git -C "$source" rev-parse --show-toplevel 2>/dev/null || true)
    if [[ $toplevel == "$source" ]]; then
        actual=$(git -C "$source" rev-parse HEAD)
        [[ $actual == "$GIT_COMMIT" ]] ||
            fail "$source is at git commit $actual, expected $GIT_COMMIT"
    else
        marker="$source/$MARKER"
        [[ -r $marker ]] ||
            fail "$source is not an exact git checkout and has no verified archive marker"
        actual=$(tr -d '[:space:]' < "$marker")
        [[ $actual == "$SHA256" ]] ||
            fail "$source archive marker is $actual, expected $SHA256"
    fi
}

fetch_source() {
    local archive="$OUTPUT/linux-$VERSION.tar.xz" actual

    [[ -z ${LINUX_SRC:-} ]] ||
        fail 'fetch does not modify LINUX_SRC; unset it or use verify'
    if [[ -d $DEFAULT_SOURCE ]]; then
        verify_source "$DEFAULT_SOURCE"
        return
    fi

    command -v curl >/dev/null 2>&1 || fail 'curl is required to fetch Linux source'
    command -v tar >/dev/null 2>&1 || fail 'tar is required to extract Linux source'
    mkdir -p "$OUTPUT"
    printf 'linux-source: downloading %s\n' "$URL" >&2
    curl --fail --location --retry 3 --output "$archive.part" "$URL"
    actual=$(hash_file "$archive.part")
    [[ $actual == "$SHA256" ]] || {
        rm -f "$archive.part"
        fail "archive checksum is $actual, expected $SHA256"
    }
    mv "$archive.part" "$archive"
    tar -xJf "$archive" -C "$OUTPUT"
    printf '%s\n' "$SHA256" > "$DEFAULT_SOURCE/$MARKER"
    verify_source "$DEFAULT_SOURCE"
}

usage() {
    printf 'usage: %s {fetch|verify|path}\n' "$0"
}

case ${1:-} in
    fetch)
        fetch_source
        printf '%s\n' "$DEFAULT_SOURCE"
        ;;
    verify)
        verify_source "$SOURCE"
        printf 'linux-source: OK (%s, %s)\n' "$VERSION" "$SOURCE"
        ;;
    path)
        verify_source "$SOURCE"
        printf '%s\n' "$SOURCE"
        ;;
    -h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
