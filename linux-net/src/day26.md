# Day 26 — MPTCP: multipath TCP

> **Today's mission:** understand how a single TCP connection can use multiple paths simultaneously, and how Linux implements MPTCP via the "msk" socket holding multiple subflows. Total time: ~75 minutes. End of Phase 4.

## What MPTCP is

A TCP connection is normally one socket pair: one client IP, one server IP, one TCP stream. **MPTCP (RFC 8684)** lets one logical connection carry data over multiple TCP "subflows" simultaneously.

The motivation: mobile devices have both WiFi and cellular. Bulk-transfer hosts have multiple NICs. Today, switching networks requires a new TCP connection — losing in-flight data and sometimes upper-layer state. MPTCP lets the connection survive a network change *and* use multiple paths concurrently for higher throughput.

![MPTCP](diagrams/day26_mptcp.png)

## The protocol model

An MPTCP connection has:

- **One "msk" (master socket)** — what the application sees. From the application's perspective, it's a regular `SOCK_STREAM` socket.
- **One or more subflows** — each is an actual TCP connection over one path. The first subflow is the "primary"; additional subflows (`MP_JOIN`) are added later.

Each subflow is bidirectional. The MPTCP scheduler decides which subflow gets each segment (or, for redundancy, sends to both). Sequence numbers come in two layers: per-subflow (regular TCP), and per-msk (MPTCP-level), so the receiver can reconstruct the original byte stream regardless of which subflow each chunk came from.

## On-wire signaling

MPTCP uses **TCP options** (the variable-length header field) to carry its protocol:

- **MP_CAPABLE** in the SYN of the primary subflow: "I support MPTCP; do you?"
- **MP_JOIN** in the SYN of an additional subflow: "I want to join the MPTCP connection identified by token X."
- **DSS (Data Sequence Signal)**: per-segment metadata mapping the subflow's local sequence number to the msk-level sequence number.
- **ADD_ADDR / REMOVE_ADDR**: announce additional endpoints peer can use to join via MP_JOIN.

If a middlebox strips MP_* options (some old NATs do), MPTCP gracefully falls back to plain TCP.

## API

```c
int sk = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
```

That's it. The application sees a regular socket. The kernel handles all subflow management. (`IPPROTO_MPTCP = 262`.)

For applications that don't explicitly request MPTCP, the system can default to it via:

```bash
sudo sysctl -w net.mptcp.enabled=1
sudo sysctl -w net.ipv4.tcp_default_mptcp_protocol=1   # makes IPPROTO_TCP map to IPPROTO_MPTCP
```

## Endpoint configuration

Subflows aren't created automatically — you tell MPTCP which addresses can be used.

```bash
# Mark an address as an MPTCP endpoint
sudo ip mptcp endpoint add 192.168.2.10 dev eth1 signal
# 'signal' = announce this address to peers via ADD_ADDR

# Or 'subflow' = automatically initiate a subflow from this address
sudo ip mptcp endpoint add 192.168.99.5 dev eth0 subflow

# Inspect
sudo ip mptcp endpoint show
sudo ip mptcp limits show     # how many subflows max
```

Endpoint flags:
- **`signal`**: announce to peer (peer can join from this address).
- **`subflow`**: initiate a subflow from this address.
- **`backup`**: low-priority subflow (used only when others are unavailable).
- **`fullmesh`**: create subflows from this address to every peer endpoint.

## Schedulers

`net/mptcp/sched.c`. The scheduler decides which subflow gets the next segment:

- **default** (`tcp_default_scheduler`): pick the subflow with the lowest RTT that has window space.
- **redundant**: send on multiple subflows for reliability (loses bandwidth but survives single-path failures).
- **round-robin**: evenly distribute across subflows.
- **BPF-defined**: write a `struct_ops` BPF program implementing `mptcp_sched_ops` (eBPF Day 22 territory).

Configure:

```bash
sudo sysctl net.mptcp.scheduler=bpf  # or 'default', 'redundant'
```

## Path manager

`net/mptcp/pm_*.c` — decides *when* to add/remove subflows. Two flavors:

- **In-kernel**: the kernel's path manager uses the configured endpoints to add subflows on its own.
- **Userspace**: an application via netlink (`/proc/net/netlink`) drives subflow lifecycle. Used by tools like `mptcpd`.

## Reliability and recovery

Each subflow is a real TCP connection — it has its own RTT, cwnd, retransmit logic. The msk-level adds:

- **Reinjection on failure**: if a subflow's RTO fires and it can't deliver, the msk reinjects the data on another subflow (so peer receives it via a different path).
- **DSN-based deduplication**: receiver sees msk-level sequence numbers; even if data arrives twice (once on each subflow), the receiver delivers it to the application only once.
- **Connection migration**: if all current subflows fail (e.g., WiFi + cellular both lose coverage briefly), the msk waits; new subflows can join when connectivity returns. The application's connection is preserved.

## Performance characteristics

MPTCP is at its best when:
- **Multiple paths exist** with similar RTTs and bandwidths.
- **Single-path failure rate is non-trivial** (mobile, lossy paths).
- **The bulk transfer is large enough** that the per-subflow setup cost is amortized.

It's worse than plain TCP when:
- Only one path is available (overhead of MPTCP options, slower handshake).
- Paths have very asymmetric RTTs (head-of-line blocking on the slow path).
- Buffer is too small to coordinate (msk-level reordering needs receive buffer ≥ BDP × N).

## Today's experiment

```bash
# Verify MPTCP support
sudo sysctl net.mptcp.enabled
modprobe mptcp_pm 2>/dev/null

# Use ip mptcp tooling
sudo ip mptcp endpoint show

# Quick test (need a partner system or use loopback)
# Server:
nc -l --mptcp 9999 &      # need recent nc with --mptcp support, or a custom binary

# Client (with IPPROTO_MPTCP):
cat << 'EOF' > /tmp/mptcp_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define IPPROTO_MPTCP 262
int main() {
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_in a = { AF_INET, htons(9999) };
    inet_aton("127.0.0.1", &a.sin_addr);
    if (connect(s, (struct sockaddr*)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "hello\n", 6);
    char buf[64]; int n = read(s, buf, sizeof buf);
    if (n > 0) write(1, buf, n);
    return 0;
}
EOF
cc /tmp/mptcp_client.c -o /tmp/mptcp_client && /tmp/mptcp_client

# Watch with ss
ss -M | head      # 'M' = MPTCP. Shows msk and subflows.
```

Verify via tcpdump:

```bash
sudo tcpdump -i lo -n -X 'tcp port 9999' | grep -E "MPC|MP_CAPABLE|MP_JOIN|DSS"
```

## What to read in the kernel

- **`net/mptcp/protocol.c`** — main file. Read `__mptcp_socket_create` to see how an msk is built. The msk owns a list of subflows.

- **`net/mptcp/subflow.c`** — subflow lifecycle. `subflow_finish_connect`, `subflow_create_socket`. How a TCP subflow becomes part of an MPTCP connection.

- **`net/mptcp/sched.c:130`** — `mptcp_init_sched`. The scheduler entry. Read the default scheduler path to see how the kernel picks "best" subflow per send.

- **`net/mptcp/pm_kernel.c`** — in-kernel path manager. Reads MPTCP endpoint config, opens new subflows when announced.

- **`net/mptcp/pm_userspace.c`** — userspace path-manager hooks via netlink.

- **`net/mptcp/options.c`** — TCP-option encoding/decoding for MPTCP. Read `mptcp_write_options` to see how MP_CAPABLE, MP_JOIN, DSS are emitted.

- **`Documentation/networking/mptcp.rst`** — official guide. Has examples and a compatibility matrix.

- **`mptcpd`** (userspace daemon) — a reference path-manager implementation; useful to study real-world configuration patterns.

## Bullet Points

- **MPTCP** = one TCP connection, multiple TCP subflows on different paths.
- API: `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`. Application code rarely needs to change.
- **Subflows** are real TCP connections; the **msk** (master) coordinates them.
- Key TCP options: **MP_CAPABLE** (handshake), **MP_JOIN** (add subflow), **DSS** (msk-level seq), **ADD_ADDR** (announce endpoints).
- **Endpoints** configured via `ip mptcp endpoint`. Flags: `signal`, `subflow`, `backup`, `fullmesh`.
- **Schedulers**: default (lowest-RTT), redundant, round-robin, BPF-driven.
- **Mobile / multi-NIC** workloads benefit; single-path low-latency workloads see MPTCP overhead.
- In-tree since 5.6 (2020); substantial improvements every release through 7.x.

## Check question

If one subflow's RTT spikes severely (e.g., cellular degrades during a transfer), what does MPTCP do, and what's the limit of how gracefully it recovers?

<details>
<summary>Click to reveal answer</summary>

**Answer:** The default scheduler steers new segments to the better subflow — its decision per segment is "lowest-RTT subflow with window space," so the slow subflow naturally gets less traffic. Already-in-flight segments on the slow subflow stay there until ACKed or retransmitted; MPTCP-level retransmit can also reinject them on the better subflow if the slow one's RTO fires.

**The limit is buffering.** The msk reassembles data in order at the receiver. If subflow A is fast (low RTT, current data) and subflow B is slow (high RTT, older data), the receiver has to buffer A's data while waiting for B's older data to arrive. If the receive buffer is too small (`tcp_rmem`), MPTCP can't take advantage of the path diversity — head-of-line blocking on the slow path stalls the application. Tuning: bump `tcp_rmem` to at least the sum of the BDPs across subflows.

**For sudden complete failure** (a subflow's RTO breaks): MPTCP can mark it `backup` and reinject; the application sees a brief stall but no error.

</details>

---

## End of Phase 4

You've covered the kernel's network subsystems: netfilter for packet filtering, conntrack for state tracking, traffic control for queueing, SO_REUSEPORT for socket scaling, kTLS for transport crypto, MPTCP for multipath. That's the bulk of "kernel networking infrastructure beyond the basic stack."

Phase 5 (Days 27–30) covers modern features and the capstone.
