#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# ANCHOR: book
#
# Day 25 opt-in runner: load the exact upstream scx_simple, let it schedule the
# whole machine for a bounded interval, then eject it cleanly.
#
# sched_ext replaces the live CPU scheduler, so this is deliberate: it refuses
# to run without EBPF_LABS_ALLOW_PRIVILEGED=1 and root, bounds the run with a
# timeout, and a trap SIGINTs the scheduler on any exit so CFS is restored.
# Run it only on a disposable, sched_ext-capable VM.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
SCHED="$ROOT/.output/day25/build/bin/scx_simple"
DURATION=${DURATION:-10}
SCHED_PID=

fail() { printf 'day25 run: %s\n' "$*" >&2; exit 1; }

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if [[ -n $SCHED_PID ]] && kill -0 "$SCHED_PID" 2>/dev/null; then
		kill -INT "$SCHED_PID" 2>/dev/null || true
		wait "$SCHED_PID" 2>/dev/null || true
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

[[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} == 1 ]] ||
	fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge replacing the live scheduler'
[[ ${EBPF_LABS_ALLOW_SCHED_EXT:-0} == 1 ]] ||
	fail 'set EBPF_LABS_ALLOW_SCHED_EXT=1 to acknowledge replacing the live scheduler'
(( EUID == 0 )) || fail 'run with sudo after setting both acknowledgement variables'
[[ -x $SCHED ]] || fail "missing $SCHED; run scripts/build-day.sh day25 first"
[[ -r /sys/kernel/sched_ext/state ]] || fail 'kernel has no sched_ext support'

"$SCHED" &
SCHED_PID=$!
sleep 1
kill -0 "$SCHED_PID" 2>/dev/null || fail 'scheduler exited early (see its output above)'

printf 'day25 run: scx_simple active for %ss; state=%s\n' \
	"$DURATION" "$(cat /sys/kernel/sched_ext/state)"
sleep "$DURATION"
printf 'day25 run: stopping; sched_ext state should return to disabled\n'
# ANCHOR_END: book
