# Day 26 — MPTCP: multipath TCP in 2026

> **Today's mission:** create an MPTCP socket, watch it use two interfaces simultaneously. Total time: ~60 minutes.

![MPTCP](diagrams/day26_mptcp.png)

## What MPTCP is

A TCP option (RFC 8684) that lets a connection use multiple subflows over different paths. Mobile devices switch between WiFi and cellular without breaking connections. Multi-homed servers can spread one logical connection across two NICs.

Linux has MPTCP support since 5.6 (2020), with substantial improvements in 6.x and 7.x.

## API

```c
int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
```

That's it from the API side. To the application, it looks like a regular TCP socket. Under the hood, it's a "msk" (MPTCP socket) that owns one or more subflows (regular TCP sockets).

## Subflow management

The first subflow is the primary, established with the `MP_CAPABLE` option in the SYN. Additional subflows can be added via `MP_JOIN`. Configuration:

```bash
# Add a server-side endpoint:
sudo ip mptcp endpoint add 192.168.2.10 dev eth1 signal

# Add a client-side endpoint that joins automatically:
sudo ip mptcp endpoint add 192.168.2.5 dev eth1 subflow

# Inspect:
sudo ip mptcp endpoint show
sudo ss -M
```

## Scheduling

The MPTCP scheduler decides which subflow gets each segment. Strategies:
- Default — use the lowest-RTT subflow that has window space.
- Redundant — send on multiple subflows for reliability.
- Round-robin — split equally.

Configurable via sysctl `net.mptcp.scheduler`.

## What to read in the kernel

- **`net/mptcp/`** — entire subsystem (~30 files).
- `net/mptcp/protocol.c` — main entry points.
- `net/mptcp/subflow.c` — subflow lifecycle.
- `net/mptcp/sched.c` — scheduler.
- **`Documentation/networking/mptcp.rst`**.

## Bullet Points

- **MPTCP** = one connection, multiple TCP subflows over different paths.
- API: `IPPROTO_MPTCP` instead of `IPPROTO_TCP`.
- Subflow endpoints configured via `ip mptcp endpoint`.
- Default scheduler picks lowest-RTT subflow per segment.
- Linux MPTCP has been improving rapidly (still adding features in 7.x).

## Check question

If one subflow's RTT spikes (e.g., cellular degrades), what does MPTCP do?

.  
.  
.

**Answer:** The default scheduler steers new segments to the better subflow. Already-in-flight segments remain on the slow subflow until ACKed or retransmitted. The MPTCP-level retransmit can recover via the other subflow if needed. Result: applications see a connection that gracefully shifts traffic to the fast path without breaking. Tunable: how aggressively to shift (some schedulers are sticky, others reactive).

## End of Phase 4

You've covered the kernel's network subsystems: netfilter for packet filtering, conntrack for state tracking, traffic control for queueing, SO_REUSEPORT for socket scaling, kTLS for transport crypto, MPTCP for multipath. That's the bulk of "kernel networking infrastructure beyond the basic stack."

Phase 5 (Days 27–30) covers modern features and the capstone.
