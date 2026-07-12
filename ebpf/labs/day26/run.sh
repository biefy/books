#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# ANCHOR: book
#
# Day 26 opt-in runner: load the scx_priority derivative against an OWNED,
# throwaway priority cgroup, run it for a bounded interval, then fully clean up.
#
# Safety contract (this replaces a live kernel scheduler, so it is deliberate):
#   * refuses to run without EBPF_LABS_ALLOW_PRIVILEGED=1 and root;
#   * creates ONE cgroup it owns (ebpf-day26-$$) and never touches any other;
#   * a single trap moves our children back to the root cgroup, ejects the
#     scheduler, and rmdir's the owned cgroup on any exit path;
#   * bounds the run with a timeout so a mistake cannot wedge the box.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
SCHED="$ROOT/.output/day26/build/bin/scx_priority"
CGROUP_ROOT=/sys/fs/cgroup
OWNED="$CGROUP_ROOT/ebpf-day26-$$"
DURATION=${DURATION:-10}
SCHED_PID=
WORK_PID=

fail() { printf 'day26 run: %s\n' "$*" >&2; exit 1; }

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	[[ -n $WORK_PID ]] && kill "$WORK_PID" 2>/dev/null || true
	if [[ -n $SCHED_PID ]] && kill -0 "$SCHED_PID" 2>/dev/null; then
		kill -INT "$SCHED_PID" 2>/dev/null || true
		wait "$SCHED_PID" 2>/dev/null || true
	fi
	# Move any survivors back to root and remove only the cgroup we created.
	if [[ -d $OWNED ]]; then
		if [[ -r $OWNED/cgroup.procs ]]; then
			while read -r pid; do
				[[ -n $pid ]] && echo "$pid" > "$CGROUP_ROOT/cgroup.procs" 2>/dev/null || true
			done < "$OWNED/cgroup.procs"
		fi
		rmdir "$OWNED" 2>/dev/null || true
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

[[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} == 1 ]] ||
	fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge loading a live BPF scheduler'
[[ ${EBPF_LABS_ALLOW_SCHED_EXT:-0} == 1 ]] ||
		fail 'set EBPF_LABS_ALLOW_SCHED_EXT=1 to acknowledge loading a live BPF scheduler'
(( EUID == 0 )) || fail 'run with sudo after setting both acknowledgement variables'
[[ -x $SCHED ]] || fail "missing $SCHED; run scripts/build-day.sh day26 first"
[[ -r /sys/kernel/sched_ext/state ]] || fail 'kernel has no sched_ext support'
[[ -w $CGROUP_ROOT/cgroup.procs ]] || fail "$CGROUP_ROOT is not a writable cgroup2 mount"
[[ -e $OWNED ]] && fail "owned cgroup $OWNED already exists"

# 1. Create the owned priority cgroup and start a small CPU workload inside it.
mkdir "$OWNED"
( exec sh -c 'echo $$ > "$1/cgroup.procs"; exec yes >/dev/null' _ "$OWNED" ) &
WORK_PID=$!

# 2. Start the scheduler pointed at the owned cgroup, bounded by a timeout.
"$SCHED" -c "$OWNED" &
SCHED_PID=$!
sleep 1
kill -0 "$SCHED_PID" 2>/dev/null || fail 'scheduler exited early (see its output above)'

printf 'day26 run: scx_priority active for %ss; state=%s\n' \
	"$DURATION" "$(cat /sys/kernel/sched_ext/state)"
sleep "$DURATION"

# 3. cleanup() ejects the scheduler and tears down the owned cgroup.
printf 'day26 run: stopping; sched_ext state should return to disabled\n'
# ANCHOR_END: book
