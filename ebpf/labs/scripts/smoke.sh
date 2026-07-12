#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# smoke.sh — manifest-aware, safe, per-day runtime smoke dispatcher.
#
# Unlike a "run everything" harness, this refuses to do anything by default:
# invoking it with no arguments prints the list of valid lab ids and exits.
# You name the day ids you want exercised, e.g.:
#
#   EBPF_LABS_ALLOW_PRIVILEGED=1 sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
#       ./scripts/smoke.sh day01 day14 day19
#   ... smoke.sh all           # explicit opt-in to every manifest lab
#
# Contract every case honours:
#   * requires EBPF_LABS_ALLOW_PRIVILEGED=1 and root before touching anything;
#   * validates each requested id against manifest.json;
#   * owns every piece of live state it creates — PID-suffixed temp dirs, net
#     namespaces, veth pairs, cgroups and bpffs pin dirs — and tears them down
#     in reverse creation order on ANY exit (success, error, or signal);
#   * tracks exact child PIDs and stops only those (never a broad pkill), and
#     never touches management interfaces or cgroups it did not create;
#   * struct_ops labs (day22/day23) additionally require
#     EBPF_LABS_ALLOW_STRUCT_OPS=1 and are delegated to their own run wrappers;
#   * sched_ext labs (day25-day27) additionally require
#     EBPF_LABS_ALLOW_SCHED_EXT=1 and are delegated to their own run wrappers;
#   * a case that cannot be exercised safely on this host fails with an explicit
#     requirement instead of silently passing.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT="$ROOT/.output"

# Owned addressing for the throwaway veth pairs; only ever used inside net
# namespaces and veth devices this script creates.
NET_HOST_IP=10.242.0.1
NET_PEER_IP=10.242.0.2
NET_PREFIX=24

# Per-day network globals, (re)set by setup_net.
NS=''
VETH=''
VPEER=''
LAST_PID=''

log()      { printf 'smoke: %s\n' "$*" >&2; }
log_warn() { printf 'smoke: WARNING: %s\n' "$*" >&2; }
ok()       { printf 'smoke: %s OK\n' "$*"; }
fail()     { printf 'smoke: %s\n' "$*" >&2; exit 1; }

# --- Resource registry -------------------------------------------------------
# Each entry is "type:value"; cleanup dispatches by type, newest first.
RESOURCES=()
register() { RESOURCES+=("$1:$2"); }

kill_pid() {
    local pid=$1 n=0
    kill -0 "$pid" 2>/dev/null || return 0
    kill -INT "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && (( n < 30 )); do n=$((n + 1)); sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; sleep 0.3; fi
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
    wait "$pid" 2>/dev/null || true
}

evacuate_cgroup() {
    local cg=$1 pid
    [[ -d $cg ]] || return 0
    # Move any stragglers back to the root cgroup, then remove only our dir.
    if [[ -r $cg/cgroup.procs ]]; then
        while read -r pid; do
            [[ -n $pid ]] && printf '%s\n' "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
        done < "$cg/cgroup.procs"
    fi
    rmdir "$cg" 2>/dev/null || true
}

cleanup_entry() {
    local type=${1%%:*} val=${1#*:}
    case $type in
        pid)    kill_pid "$val" ;;
        dir)    rm -rf -- "$val" 2>/dev/null || true ;;
        netns)  ip netns del "$val" 2>/dev/null || true ;;
        link)   ip link del "$val" 2>/dev/null || true ;;
        cgroup) evacuate_cgroup "$val" ;;
    esac
}

unwind_to() {
    local mark=$1 i
    for (( i=${#RESOURCES[@]} - 1; i >= mark; i-- )); do
        cleanup_entry "${RESOURCES[$i]}"
    done
    if (( mark == 0 )); then
        RESOURCES=()
    else
        RESOURCES=("${RESOURCES[@]:0:mark}")
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    unwind_to 0
    exit "$status"
}
trap cleanup EXIT INT TERM

# --- Small helpers -----------------------------------------------------------
require_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || fail "missing required command: $c"
    done
}

need_loader() {
    [[ -x $1 ]] ||
        fail "missing loader $1; run 'make -C ebpf/labs check' (or the day's make target) first"
}

make_workdir() {
    local day=$1
    local dir="$WORKROOT/$day"
    mkdir -p "$dir"
    printf 'ebpf-smoke-data\n' > "$dir/data"
    printf '%s' "$dir"
}

# launch LOGBASE CMD... — run CMD in the background, track its PID, and detect an
# early exit (a failed load/attach) instead of hanging.
launch() {
    local log=$1; shift
    "$@" >"$log" 2>"$log.stderr" &
    LAST_PID=$!
    register pid "$LAST_PID"
    sleep 0.5
    if ! kill -0 "$LAST_PID" 2>/dev/null; then
        wait "$LAST_PID" 2>/dev/null || true
        fail "loader exited early: $* :: $(tail -n 3 "$log.stderr" 2>/dev/null | tr '\n' ' ')"
    fi
}

# wait_output PID PATTERN FILE [TIMEOUT_SECONDS]
wait_output() {
    local pid=$1 pat=$2 file=$3 to=${4:-6} i=0 max
    max=$(( to * 10 ))
    until grep -Eq "$pat" "$file" 2>/dev/null; do
        i=$((i + 1))
        if (( i >= max )); then
            fail "timed out waiting for /$pat/ in $file :: $(tail -n 2 "$file.stderr" 2>/dev/null | tr '\n' ' ')"
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            fail "process exited before emitting /$pat/ :: $(tail -n 3 "$file.stderr" 2>/dev/null | tr '\n' ' ')"
        fi
        sleep 0.1
    done
}

expect_running() {
    kill -0 "$1" 2>/dev/null || fail "$2"
}

wait_exit() {
    local pid=$1 to=${2:-12} i=0 max
    max=$(( to * 10 ))
    while kill -0 "$pid" 2>/dev/null; do
        i=$((i + 1))
        if (( i >= max )); then
            return 1
        fi
        sleep 0.1
    done
    wait "$pid" 2>/dev/null || true
    return 0
}

# Owned, self-terminating syscall load: reads an owned file and creates/removes
# owned temp files (with yielding sleeps that also drive scheduler activity).
spawn_load() {
    local wd=$1
    (
        local f
        for i in $(seq 1 150); do
            head -c 64 "$wd/data" >/dev/null 2>&1 || true
            f="$wd/l.$i"
            : > "$f" 2>/dev/null || true
            rm -f "$f" 2>/dev/null || true
            sleep 0.1
        done
    ) &
    register pid "$!"
}

# One-shot owned trigger for trace_pipe-only loaders (unlink + read).
trigger_activity() {
    local wd=$1 f i
    head -c 8 "$wd/data" >/dev/null 2>&1 || true
    for i in 1 2 3; do
        f="$wd/a.$i"
        : > "$f"
        rm -f "$f"
    done
}

# setup_net TAG — owned netns + veth pair. Reverse cleanup deletes the veth
# (which removes its peer) and then the namespace.
setup_net() {
    local tag=$1
    require_cmd ip
    NS="ebpf-smoke-${tag}-$$"
    VETH="s${tag}a$$"; VETH=${VETH:0:15}
    VPEER="s${tag}b$$"; VPEER=${VPEER:0:15}
    ip netns del "$NS" 2>/dev/null || true
    ip netns add "$NS" || fail "cannot create net namespace (host lacks netns support?)"
    register netns "$NS"
    ip link add "$VETH" type veth peer name "$VPEER" || fail "cannot create owned veth pair"
    register link "$VETH"
    ip link set "$VPEER" netns "$NS"
    ip addr add "$NET_HOST_IP/$NET_PREFIX" dev "$VETH"
    ip link set "$VETH" up
    ip -n "$NS" addr add "$NET_PEER_IP/$NET_PREFIX" dev "$VPEER"
    ip -n "$NS" link set "$VPEER" up
    ip -n "$NS" link set lo up
}

setup_cgroup() {
    local tag=$1
    [[ -w /sys/fs/cgroup/cgroup.procs ]] ||
        fail "/sys/fs/cgroup is not a writable cgroup2 mount"
    CG="/sys/fs/cgroup/ebpf-smoke-${tag}-$$"
    [[ -e $CG ]] && fail "owned cgroup $CG already exists"
    mkdir "$CG" || fail "cannot create owned cgroup $CG"
    register cgroup "$CG"
}

# --- Privilege gates ---------------------------------------------------------
require_priv() {
    if [[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} != 1 ]]; then
        fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge privileged BPF attachment'
    fi
    (( EUID == 0 )) || fail 'run with sudo after setting EBPF_LABS_ALLOW_PRIVILEGED=1'
}

require_struct_ops() {
    [[ ${EBPF_LABS_ALLOW_STRUCT_OPS:-0} == 1 ]] ||
        fail 'set EBPF_LABS_ALLOW_STRUCT_OPS=1 to acknowledge TCP struct_ops registration'
}

require_sched_ext() {
    [[ ${EBPF_LABS_ALLOW_SCHED_EXT:-0} == 1 ]] ||
        fail 'set EBPF_LABS_ALLOW_SCHED_EXT=1 to acknowledge loading a live BPF scheduler'
}

# --- Per-day handlers --------------------------------------------------------
# Tracing loaders that print an owned per-event line on stdout.
smoke_unlink() {   # DAY APP PATTERN
    local day=$1 app=$2 pat=$3 wd log
    need_loader "$OUTPUT/$day/$app"
    wd=$(make_workdir "$day"); log="$wd/out.log"
    launch "$log" "$OUTPUT/$day/$app"
    local f i
    for i in 1 2 3 4 5; do f="$wd/u.$i"; : > "$f"; rm -f "$f"; done
    wait_output "$LAST_PID" "$pat" "$log"
    ok "$day $app (owned unlink trigger)"
}

smoke_stream() {   # DAY APP PATTERN [TIMEOUT]
    local day=$1 app=$2 pat=$3 to=${4:-6} wd log
    need_loader "$OUTPUT/$day/$app"
    wd=$(make_workdir "$day"); log="$wd/out.log"
    launch "$log" "$OUTPUT/$day/$app"
    spawn_load "$wd"
    wait_output "$LAST_PID" "$pat" "$log" "$to"
    ok "$day $app (owned syscall trigger)"
}

# Tracing loaders whose events go to trace_pipe: prove clean load+attach via the
# startup banner, drive an owned trigger, and confirm the loader stays attached.
smoke_attach() {   # DAY APP PATTERN
    local day=$1 app=$2 pat=$3 wd log
    need_loader "$OUTPUT/$day/$app"
    wd=$(make_workdir "$day"); log="$wd/out.log"
    launch "$log" "$OUTPUT/$day/$app"
    wait_output "$LAST_PID" "$pat" "$log"
    trigger_activity "$wd"
    expect_running "$LAST_PID" "$day $app detached unexpectedly after trigger"
    ok "$day $app (attached; events on trace_pipe)"
}

smoke_bashspy() {
    local wd log
    need_loader "$OUTPUT/day10/bashspy"
    require_cmd bash
    wd=$(make_workdir day10); log="$wd/out.log"
    launch "$log" "$OUTPUT/day10/bashspy"
    # Startup banner only prints after the uprobe attaches to bash's readline.
    wait_output "$LAST_PID" 'bash readline input' "$log"
    # Best-effort readline event; not required (needs a real interactive line).
    printf 'echo ebpf-smoke\nexit\n' | timeout 2 bash -i >/dev/null 2>&1 || true
    expect_running "$LAST_PID" "day10 bashspy detached unexpectedly"
    ok "day10 bashspy (uprobe attached; readline events need interactive bash)"
}

smoke_xdp_count() {
    local wd log
    need_loader "$OUTPUT/day14/xdp_count"
    require_cmd ip ping
    setup_net 14
    wd=$(make_workdir day14); log="$wd/out.log"
    launch "$log" "$OUTPUT/day14/xdp_count" "$VETH"
    wait_output "$LAST_PID" 'Counting packets' "$log"
    ping -c 5 -W 1 "$NET_PEER_IP" >/dev/null 2>&1 || true
    wait_output "$LAST_PID" 'proto[[:space:]]+1:[[:space:]]+[1-9]' "$log" 8
    ok "day14 xdp_count (owned netns/veth XDP)"
}

smoke_tcx() {
    local wd log
    need_loader "$OUTPUT/day17/tcx"
    require_cmd ip ping
    setup_net 17
    wd=$(make_workdir day17); log="$wd/out.log"
    launch "$log" "$OUTPUT/day17/tcx" "$VETH"
    wait_output "$LAST_PID" 'tcx counter\+firewall attached' "$log"
    ping -c 5 -W 1 "$NET_PEER_IP" >/dev/null 2>&1 || true
    wait_output "$LAST_PID" 'total:[[:space:]]+[1-9]' "$log" 8
    ok "day17 tcx (owned netns/veth tcx)"
}

smoke_block() {
    local wd log pin
    need_loader "$OUTPUT/day15/block"
    need_loader "$OUTPUT/day15/blockcli"
    require_cmd ip
    [[ -d /sys/fs/bpf ]] || fail 'day15 requires a bpffs mount at /sys/fs/bpf'
    setup_net 15
    pin="/sys/fs/bpf/ebpf-smoke-day15-$$"
    [[ -e $pin ]] && fail "owned pin dir $pin already exists"
    register dir "$pin"
    wd=$(make_workdir day15); log="$wd/out.log"
    launch "$log" "$OUTPUT/day15/block" "$VETH" "$pin"
    wait_output "$LAST_PID" 'Firewall attached' "$log"
    "$OUTPUT/day15/blockcli" "$pin" add "$NET_PEER_IP/32" >"$wd/cli.log" 2>&1 ||
        fail "blockcli add failed :: $(cat "$wd/cli.log")"
    "$OUTPUT/day15/blockcli" "$pin" stats >"$wd/stats.log" 2>&1 ||
        fail "blockcli stats failed :: $(cat "$wd/stats.log")"
    grep -Eq '.' "$wd/stats.log" || fail 'blockcli stats produced no output from owned pins'
    expect_running "$LAST_PID" 'day15 block detached unexpectedly'
    ok "day15 block (owned netns/veth XDP + owned pin dir)"
}

smoke_tc() {
    local wd obj
    require_cmd ip tc
    obj="$OUTPUT/day16/tc.bpf.o"
    [[ -r $obj ]] || fail "missing $obj; run 'make -C ebpf/labs day16' first"
    setup_net 16
    wd=$(make_workdir day16)
    tc qdisc add dev "$VETH" clsact || fail 'cannot add clsact qdisc to owned veth'
    tc filter add dev "$VETH" ingress bpf da obj "$obj" sec tc_ingress ||
        fail 'cannot load day16 tc_ingress object onto owned veth (host tc lacks BPF support?)'
    tc filter add dev "$VETH" egress bpf da obj "$obj" sec tc_egress ||
        fail 'cannot load day16 tc_egress object onto owned veth'
    tc filter show dev "$VETH" ingress > "$wd/filter.log" 2>&1
    grep -Eq 'tc_ingress|direct-action|bpf' "$wd/filter.log" ||
        fail "day16 tc filter did not attach :: $(cat "$wd/filter.log")"
    ping -c 3 -W 1 "$NET_PEER_IP" >/dev/null 2>&1 || true
    ok "day16 tc (owned netns/veth tc command)"
}

smoke_xsk() {
    local wd log
    need_loader "$OUTPUT/day18/xsk"
    require_cmd ip ping
    setup_net 18
    wd=$(make_workdir day18); log="$wd/out.log"
    # If UMEM/AF_XDP socket setup is unsupported the loader exits early and
    # launch/wait_output surface it as an explicit failure rather than a pass.
    launch "$log" "$OUTPUT/day18/xsk" "$VETH"
    wait_output "$LAST_PID" 'AF_XDP receiver up' "$log" 8
    ip netns exec "$NS" ping -c 5 -W 1 "$NET_HOST_IP" >/dev/null 2>&1 || true
    expect_running "$LAST_PID" 'day18 xsk detached unexpectedly after traffic'
    ok "day18 xsk (owned netns/veth AF_XDP)"
}

smoke_cgroup19() {
    local wd log
    need_loader "$OUTPUT/day19/fw"
    need_loader "$OUTPUT/day19/tune"
    setup_cgroup 19
    wd=$(make_workdir day19)
    launch "$wd/fw.log" "$OUTPUT/day19/fw" "$CG"
    wait_output "$LAST_PID" 'attached cgroup_skb/egress' "$wd/fw.log"
    expect_running "$LAST_PID" 'day19 fw detached unexpectedly'
    launch "$wd/tune.log" "$OUTPUT/day19/tune" "$CG"
    wait_output "$LAST_PID" 'attached sockops' "$wd/tune.log"
    expect_running "$LAST_PID" 'day19 tune detached unexpectedly'
    ok "day19 fw+tune (owned child cgroup)"
}

smoke_capstone() {
    local wd log
    need_loader "$OUTPUT/day28-30/capstone_latency"
    wd=$(make_workdir day28-30); log="$wd/out.log"
    # -t 0 makes every traced vfs_read an outlier; -d 3 self-terminates.
    launch "$log" "$OUTPUT/day28-30/capstone_latency" -t 0 -d 3
    wait_output "$LAST_PID" 'tracing vfs_read' "$log"
    spawn_load "$wd"
    wait_exit "$LAST_PID" 12 || fail 'day28-30 capstone_latency did not exit within its bounded duration'
    grep -Eq 'OUTLIER' "$log" ||
        fail "day28-30 captured no outliers despite owned read load :: $(tail -n 3 "$log" | tr '\n' ' ')"
    ok "day28-30 capstone_latency (controlled latency workload)"
}

smoke_delegate_struct_ops() {   # DAY
    local day=$1
    require_struct_ops
    [[ -x "$ROOT/$day/run.sh" ]] || fail "missing $ROOT/$day/run.sh"
    log "delegating to $day/run.sh (struct_ops; owns its own cleanup)"
    "$ROOT/$day/run.sh"
    ok "$day (delegated struct_ops run wrapper)"
}

smoke_delegate_sched_ext() {   # DAY
    local day=$1
    require_sched_ext
    [[ -x "$ROOT/$day/run.sh" ]] || fail "missing $ROOT/$day/run.sh"
    log "delegating to $day/run.sh (sched_ext; owns its own cleanup)"
    "$ROOT/$day/run.sh"
    ok "$day (delegated sched_ext run wrapper)"
}

dispatch() {
    case $1 in
        day01)    smoke_unlink day01 hello  'deleted a file' ;;
        day02)    smoke_unlink day02 count  'PID [0-9]+: [0-9]+ unlinks' ;;
        day03)    smoke_unlink day03 parent 'ppid [0-9]+ .* deleted a file' ;;
        day04)    smoke_attach day04 reject   'loaded clean' ;;
        day05)    smoke_attach day05 loops    'loaded and attached' ;;
        day06)    smoke_stream day06 latency  'PID [0-9]+ TID [0-9]+ vfs_read' 8 ;;
        day07)    smoke_attach day07 inspect  'three programs attached' ;;
        day08)    smoke_stream day08 schedlat 'waited' 8 ;;
        day09)    smoke_stream day09 stacks   'stack snapshot' 12 ;;
        day10)    smoke_bashspy ;;
        day11)    smoke_stream day11 multi    'hits ---' 8 ;;
        day12)    smoke_stream day12 openat_path 'opened /' 8 ;;
        day13)    smoke_stream day13 dropviz  'dur=' 8 ;;
        day14)    smoke_xdp_count ;;
        day15)    smoke_block ;;
        day16)    smoke_tc ;;
        day17)    smoke_tcx ;;
        day18)    smoke_xsk ;;
        day19)    smoke_cgroup19 ;;
        day20)    smoke_attach day20 kfunc_demo   'watch trace_pipe' ;;
        day21)    smoke_attach day21 task_assoc   'watch trace_pipe' ;;
        day22)    smoke_delegate_struct_ops day22 ;;
        day23)    smoke_delegate_struct_ops day23 ;;
        day24)    smoke_attach day24 cpumask_demo 'watch trace_pipe' ;;
        day25)    smoke_delegate_sched_ext day25 ;;
        day26)    smoke_delegate_sched_ext day26 ;;
        day27)    smoke_delegate_sched_ext day27 ;;
        day28-30) smoke_capstone ;;
        *)        fail "no smoke handler wired for $1" ;;
    esac
}

run_day() {
    local day=$1 mark=${#RESOURCES[@]}
    log "=== $day ==="
    dispatch "$day"
    # Release this day's owned state before the next one starts.
    unwind_to "$mark"
}

# --- Manifest / argument handling --------------------------------------------
require_cmd python3
mapfile -t MANIFEST_IDS < <(python3 - "$ROOT/manifest.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    for entry in json.load(stream)["labs"]:
        print(entry["id"])
PY
)
(( ${#MANIFEST_IDS[@]} > 0 )) || fail "could not read lab ids from $ROOT/manifest.json"

declare -A VALID_ID=()
for id in "${MANIFEST_IDS[@]}"; do VALID_ID[$id]=1; done
is_valid() { [[ -n ${VALID_ID[$1]:-} ]]; }

usage() {
    cat <<EOF
usage: EBPF_LABS_ALLOW_PRIVILEGED=1 sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \\
           $0 <day-id> [day-id ...]
       $0 all      run every manifest lab (explicit opt-in)

Naming no day ids just prints this help; nothing is executed.

Extra acknowledgements (checked per day):
  day22, day23        EBPF_LABS_ALLOW_STRUCT_OPS=1
  day25, day26, day27 EBPF_LABS_ALLOW_SCHED_EXT=1

Valid day ids (from manifest.json):
EOF
    printf '  %s\n' "${MANIFEST_IDS[@]}" >&2
}

if (( $# == 0 )); then
    usage
    exit 0
fi

REQUESTED=()
for arg in "$@"; do
    case $arg in
        -h|--help) usage; exit 0 ;;
        all)       REQUESTED+=("${MANIFEST_IDS[@]}") ;;
        *)
            is_valid "$arg" || fail "unknown lab id: $arg (run '$0' with no args for the list)"
            REQUESTED+=("$arg")
            ;;
    esac
done

require_priv
"$ROOT/scripts/preflight.sh" --runtime

WORKROOT=$(mktemp -d /tmp/ebpf-smoke.XXXXXX)
register dir "$WORKROOT"

for id in "${REQUESTED[@]}"; do
    run_day "$id"
done

ok "all requested privileged runtime checks passed (${REQUESTED[*]})"
