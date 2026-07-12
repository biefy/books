#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT="$ROOT/.output"
ACTIVE_PID=
WORKDIR=

cleanup() {
    local status=$?
    local attempts=0

    trap - EXIT INT TERM
    if [[ -n ${ACTIVE_PID:-} ]] && kill -0 "$ACTIVE_PID" 2>/dev/null; then
        kill -TERM "$ACTIVE_PID" 2>/dev/null || true
        while kill -0 "$ACTIVE_PID" 2>/dev/null && (( attempts < 20 )); do
            attempts=$((attempts + 1))
            sleep 0.1
        done
        if kill -0 "$ACTIVE_PID" 2>/dev/null; then
            kill -KILL "$ACTIVE_PID" 2>/dev/null || true
        fi
        wait "$ACTIVE_PID" 2>/dev/null || true
    fi
    [[ -z ${WORKDIR:-} ]] || rm -rf -- "$WORKDIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

fail() {
    printf 'smoke: %s\n' "$*" >&2
    exit 1
}

if [[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} != 1 ]]; then
    fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge privileged BPF attachment'
fi
if (( EUID != 0 )); then
    fail 'run with sudo after setting EBPF_LABS_ALLOW_PRIVILEGED=1'
fi

"$ROOT/scripts/preflight.sh" --runtime

for binary in day01/hello day02/count day03/parent; do
    [[ -x "$OUTPUT/$binary" ]] || fail "missing loader $OUTPUT/$binary; run make -C ebpf/labs check first"
done

WORKDIR=$(mktemp -d /tmp/practical-ebpf-smoke.XXXXXX)

start_loader() {
    local binary=$1
    local log=$2

    "$binary" >"$log" 2>"$log.stderr" &
    ACTIVE_PID=$!
    sleep 0.5
    if ! kill -0 "$ACTIVE_PID" 2>/dev/null; then
        wait "$ACTIVE_PID" || true
        fail "loader exited early: $binary (see $log.stderr)"
    fi
}

stop_loader() {
    local pid=$ACTIVE_PID
    local attempts=0

    kill -INT "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && (( attempts < 50 )); do
        attempts=$((attempts + 1))
        sleep 0.1
    done

    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        attempts=0
        while kill -0 "$pid" 2>/dev/null && (( attempts < 20 )); do
            attempts=$((attempts + 1))
            sleep 0.1
        done
    fi

    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
    fi

    wait "$pid"
    ACTIVE_PID=
}

wait_for_pattern() {
    local pattern=$1
    local file=$2
    local attempts=0

    until grep -Eq "$pattern" "$file" 2>/dev/null; do
        attempts=$((attempts + 1))
        if (( attempts >= 50 )); then
            fail "timed out waiting for '$pattern' in $file"
        fi
        if ! kill -0 "$ACTIVE_PID" 2>/dev/null; then
            wait "$ACTIVE_PID" || true
            ACTIVE_PID=
            fail "loader exited while waiting for output (see $file.stderr)"
        fi
        sleep 0.1
    done
}

hello_log="$WORKDIR/hello.log"
start_loader "$OUTPUT/day01/hello" "$hello_log"
touch "$WORKDIR/hello-trigger"
rm "$WORKDIR/hello-trigger"
wait_for_pattern 'deleted a file' "$hello_log"
stop_loader
printf 'smoke: day01 hello OK\n'

count_log="$WORKDIR/count.log"
start_loader "$OUTPUT/day02/count" "$count_log"
for index in 1 2 3 4 5; do
    touch "$WORKDIR/count-$index"
done
rm "$WORKDIR"/count-*
wait_for_pattern 'PID [0-9]+: [0-9]+ unlinks' "$count_log"
stop_loader
printf 'smoke: day02 count OK\n'

parent_log="$WORKDIR/parent.log"
start_loader "$OUTPUT/day03/parent" "$parent_log"
touch "$WORKDIR/parent-trigger"
rm "$WORKDIR/parent-trigger"
wait_for_pattern 'ppid [0-9]+ .* deleted a file' "$parent_log"
stop_loader
printf 'smoke: day03 parent OK\n'

printf 'smoke: all privileged runtime checks passed\n'
