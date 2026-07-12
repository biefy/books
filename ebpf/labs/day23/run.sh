#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run.sh — safe, self-cleaning runner for the Day 23 telemetry DCTCP lab.
#
# It owns every piece of live state it creates and restores/destroys all of it
# on ANY exit (success, error, or signal), in reverse order of creation:
#
#   1. captures net.ipv4.tcp_allowed_congestion_control and restores it;
#   2. starts the logged_dctcp loader (which registers "bpf_dctcp_log") and
#      SIGTERMs it on exit, so the struct_ops link is destroyed and the CC is
#      unregistered deterministically;
#   3. (veth mode) creates a network namespace + veth pair + netem qdisc and
#      tears them down;
#   4. starts an iperf3 server and client it owns by PID and kills them.
#
# Like scripts/smoke.sh this is opt-in and refuses to run without an explicit
# acknowledgement and root. It never installs packages.
#
# Usage:
#   EBPF_LABS_ALLOW_PRIVILEGED=1 sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
#       ./run.sh [veth|loopback]
#
# Environment knobs (all optional):
#   DURATION   iperf3 transfer seconds           (default 10)
#   NETEM      netem parameters in veth mode      (default "delay 20ms loss 1%")
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
LOADER="$ROOT/.output/day23/logged_dctcp"

MODE=${1:-veth}
DURATION=${DURATION:-10}
NETEM=${NETEM:-delay 20ms loss 1%}

CC_NAME="bpf_dctcp_log"
SUFFIX=$$
OCTET=$((SUFFIX % 200 + 20))
NS="ebpf-day23-$SUFFIX"
VETH="d23h$SUFFIX"
VPEER="d23p$SUFFIX"
HOST_IP="10.223.$OCTET.1"
PEER_IP="10.223.$OCTET.2"
PREFIX=24

LOADER_PID=
IPERF_SERVER_PID=
ORIG_ALLOWED=
NS_CREATED=0
VETH_CREATED=0
ALLOWED_CHANGED=0

log() { printf 'day23: %s\n' "$*" >&2; }
fail() { printf 'day23: %s\n' "$*" >&2; exit 1; }

cleanup() {
    local status=$?
    trap - EXIT INT TERM

    if [[ -n $IPERF_SERVER_PID ]] && kill -0 "$IPERF_SERVER_PID" 2>/dev/null; then
        kill -TERM "$IPERF_SERVER_PID" 2>/dev/null || true
        wait "$IPERF_SERVER_PID" 2>/dev/null || true
    fi

    if [[ -n $LOADER_PID ]] && kill -0 "$LOADER_PID" 2>/dev/null; then
        # SIGTERM triggers the loader's deterministic detach + unregister.
        kill -TERM "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi

    if (( VETH_CREATED )); then
        ip link del "$VETH" 2>/dev/null || true
    fi
    if (( NS_CREATED )); then
        ip netns del "$NS" 2>/dev/null || true
    fi

    if (( ALLOWED_CHANGED )) && [[ -n $ORIG_ALLOWED ]]; then
        sysctl -q -w "net.ipv4.tcp_allowed_congestion_control=$ORIG_ALLOWED" \
            2>/dev/null || true
        log "restored tcp_allowed_congestion_control to: $ORIG_ALLOWED"
    fi

    exit "$status"
}
trap cleanup EXIT INT TERM

# --- Preconditions -----------------------------------------------------------
if [[ ${EBPF_LABS_ALLOW_PRIVILEGED:-0} != 1 ]]; then
    fail 'set EBPF_LABS_ALLOW_PRIVILEGED=1 to acknowledge privileged BPF attachment'
fi
if (( EUID != 0 )); then
    fail 'run with sudo after setting EBPF_LABS_ALLOW_PRIVILEGED=1'
fi
[[ ${EBPF_LABS_ALLOW_STRUCT_OPS:-0} == 1 ]] ||
    fail 'set EBPF_LABS_ALLOW_STRUCT_OPS=1 to acknowledge TCP struct_ops registration'
[[ -x $LOADER ]] || fail "missing loader $LOADER; build day23 first (see chapter)"
for tool in ip sysctl iperf3 ss; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done
case $MODE in veth|loopback) ;; *) fail "mode must be 'veth' or 'loopback'";; esac

# --- 1. Capture the CC allowed-list before touching anything -----------------
ORIG_ALLOWED=$(sysctl -n net.ipv4.tcp_allowed_congestion_control)
log "saved tcp_allowed_congestion_control: $ORIG_ALLOWED"

# --- 2. Start the loader; wait until bpf_dctcp_log is registered -------------
"$LOADER" &
LOADER_PID=$!
for _ in $(seq 1 50); do
    if ! kill -0 "$LOADER_PID" 2>/dev/null; then
        wait "$LOADER_PID" 2>/dev/null || true
        fail 'loader exited before registering (need root/CAP_BPF and a struct_ops-capable kernel)'
    fi
    if grep -qw "$CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control; then
        break
    fi
    sleep 0.1
done
grep -qw "$CC_NAME" /proc/sys/net/ipv4/tcp_available_congestion_control ||
    fail "timed out waiting for $CC_NAME in tcp_available_congestion_control"
log "$CC_NAME is registered and available"

# --- 3. Allow the algorithm for the client socket ----------------------------
sysctl -q -w "net.ipv4.tcp_allowed_congestion_control=$ORIG_ALLOWED $CC_NAME"
ALLOWED_CHANGED=1

# --- 4. Wire up the transfer path and run iperf3 -----------------------------
if [[ $MODE == veth ]]; then
    log "building netns/veth path with netem: $NETEM"
    ip netns add "$NS"; NS_CREATED=1
    ip link add "$VETH" type veth peer name "$VPEER"; VETH_CREATED=1
    ip link set "$VPEER" netns "$NS"
    ip addr add "$HOST_IP/$PREFIX" dev "$VETH"
    ip link set "$VETH" up
    ip -n "$NS" addr add "$PEER_IP/$PREFIX" dev "$VPEER"
    ip -n "$NS" link set "$VPEER" up
    ip -n "$NS" link set lo up
    # netem on both directions so loss/delay is symmetric.
    # shellcheck disable=SC2086
    tc qdisc add dev "$VETH" root netem $NETEM
    # shellcheck disable=SC2086
    ip netns exec "$NS" tc qdisc add dev "$VPEER" root netem $NETEM

    ip netns exec "$NS" iperf3 -s -1 -B "$PEER_IP" >/dev/null 2>&1 &
    IPERF_SERVER_PID=$!
    sleep 0.5
    log "running: iperf3 -c $PEER_IP -C $CC_NAME -t $DURATION"
    iperf3 -c "$PEER_IP" -C "$CC_NAME" -t "$DURATION" || true
    log "socket CC (should show $CC_NAME):"
    ss -ti "dst $PEER_IP" | grep -w "$CC_NAME" || log "(no live socket sampled)"
else
    log "running over loopback (no loss; expect a monotonic cwnd climb only)"
    iperf3 -s -1 >/dev/null 2>&1 &
    IPERF_SERVER_PID=$!
    sleep 0.5
    log "running: iperf3 -c 127.0.0.1 -C $CC_NAME -t $DURATION"
    iperf3 -c 127.0.0.1 -C "$CC_NAME" -t "$DURATION" || true
    log "socket CC (should show $CC_NAME):"
    ss -ti "dst 127.0.0.1" | grep -w "$CC_NAME" || log "(no live socket sampled)"
fi

log "transfer complete; telemetry above came from the loader on fd 1"
log "cleaning up (unregister $CC_NAME, restore allowed-list, delete netns/veth)"
