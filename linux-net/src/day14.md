# Day 14 — UDP: the simple protocol

> **Today's mission:** trace a UDP packet end to end. See why "connectionless" simplifies the kernel-side code dramatically. Total time: ~75 minutes.

## Why UDP first

UDP has no state machine, no retransmissions, no congestion control. One `sendmsg` produces one wire packet (or one fragmented packet, if size > path MTU). One `recvmsg` returns one datagram. Everything else — packet loss recovery, in-order delivery, flow control — is the application's problem.

Understanding UDP gives you the *baseline* L4 path. TCP (Days 15–17) is "UDP plus a state machine plus retransmission plus congestion control" — knowing where the simple version ends helps you see where TCP's complexity goes.

## The TX side

![UDP path](diagrams/day14_udp.png)

```c
sendmsg(fd, msg, flags)
  → sock_sendmsg
    → udp_sendmsg                       // net/ipv4/udp.c:1233
      → ip_make_skb / ip_append_data    // net/ipv4/ip_output.c:1553, 1359
      → udp_send_skb
        → ip_send_skb                    // net/ipv4/ip_output.c:1506
          → ip_local_out → ip_output → ... (Day 3's TX path)
```

`udp_sendmsg` is roughly **274 lines** of code — most of it option handling (MSG_CONFIRM, MSG_MORE, GSO_BY_FRAGS, control-message processing) and the route lookup for the destination. The actual datagram construction is a single call to `ip_make_skb` or, for cork mode, `ip_append_data`.

### Why two paths (`ip_make_skb` and `ip_append_data`)?

- **`ip_make_skb`**: build one skb directly from one userspace buffer. Fast path; one syscall, one packet.
- **`ip_append_data`** (corked): used when `MSG_MORE` or `UDP_CORK` is set. The kernel accumulates writes into a partial skb; the next `sendmsg` (or `UDP_CORK off`) finalizes it as one datagram. Useful when an application has multiple sources of data for one packet (header + payload built separately).

### No socket-level send queue

Unlike TCP, UDP doesn't keep an `sk_write_queue` of unsent skbs. As soon as `udp_sendmsg` builds the datagram, it's handed to IP and gone. Why? Because UDP has no notion of retransmission — there's no reason to keep the bytes around. The socket buffer (`sk_sndbuf`) only matters for back-pressure on `sendmsg` itself: if the IP stack can't accept the packet right now (e.g., qdisc is full), `sendmsg` blocks or returns `EAGAIN`.

## The RX side

```c
ip_rcv → ip_local_deliver → ip_local_deliver_finish
  → udp_rcv(skb)                         // net/ipv4/udp.c:2588
    → __udp4_lib_lookup                   // net/ipv4/udp.c:667 — find sock by 4-tuple
    → udp_queue_rcv_skb                  // net/ipv4/udp.c:2422
      → __udp_queue_rcv_skb               // net/ipv4/udp.c:2307
        → sock_queue_rcv_skb_reason       // append to sk->sk_receive_queue
        → sk->sk_data_ready(sk)           // wake any recvmsg waiters
```

### The lookup: `__udp4_lib_lookup`

Given an incoming datagram with `(saddr, sport, daddr, dport)`, find the listening socket. UDP supports two kinds of bind:

- **Unconnected** (default): bound to `(local_addr, local_port)`. Receives datagrams addressed to that port regardless of source.
- **Connected** (after `connect()` on a SOCK_DGRAM): bound to a specific 4-tuple. Receives only from the matching peer.

The lookup walks the UDP hash table (`udp_table`, with its addr+port `hslot2` buckets — not the TCP/`inet_hashinfo` bind hash) and prefers more-specific matches (4-tuple beats 2-tuple). Per-netns, of course. With SO_REUSEPORT, multiple sockets share the bind slot; the kernel hashes the 4-tuple to pick one (Day 24).

### Queueing

`udp_queue_rcv_skb` appends the skb to the socket's `sk_receive_queue` — a doubly-linked list of skbs. The wake (`sk_data_ready`) tells any `recvmsg` waiter (or epoll/io_uring) that data is available.

If the queue is full (>= `sk_rcvbuf`), the packet is dropped — UDP doesn't push back on the sender (no ACK mechanism). The drop is counted in `/proc/net/snmp` `Udp/InErrors` and (if `kfree_skb_reason` was used) attributed in `dropwatch`.

## The recvmsg path

```c
recvmsg(fd, msg, flags)
  → sock_recvmsg
    → udp_recvmsg                         // net/ipv4/udp.c:2031
      → __skb_recv_udp                    // dequeue from sk_receive_queue
      → skb_copy_datagram_msg              // copy into user buffer
      → skb_consume_udp                    // free the skb (UDP-specific wrapper)
```

Each `recvmsg` returns *exactly one* datagram. If the user buffer is smaller than the datagram, the rest is silently truncated and `MSG_TRUNC` is set in `msg->msg_flags`. (TCP doesn't do this — TCP gives you bytes, UDP gives you packets.)

`MSG_PEEK` returns the data without dequeueing — useful for fixed-header protocols where you peek to learn the length, then read for real. Costs more CPU because the skb stays in the queue.

## UDP-Lite, GSO, and other variations

- **UDP-Lite (RFC 3828)**: same wire format, partial checksum (only first N bytes covered). Useful for video/audio streams where corrupted-but-late frames are better than retransmits. Linux supports it via `IPPROTO_UDPLITE`. Code path is the same `udp_sendmsg/recv` logic with a flag.
- **UDP GSO** (`UDP_SEGMENT` sockopt): the application sends one large buffer, kernel fragments it into MTU-sized datagrams in software. This is how QUIC/HTTP3 implementations achieve high throughput from userspace — one syscall delivers many packets.
- **UDP-encap** (IPsec, VXLAN, GENEVE, FoU): UDP socket on a special port; instead of queueing on `sk_receive_queue`, calls a registered `encap_rcv` handler. Day 12 covered VXLAN's use of this.

## Today's experiment

```bash
# Server side:
nc -ul 9999 &

# Client side:
echo "hello" | nc -u 127.0.0.1 9999
echo "world" | nc -u 127.0.0.1 9999

# Trace
sudo bpftrace -e '
fentry:udp_sendmsg { printf("send %d bytes from sk=%p\n", args->len, args->sk); }
fentry:udp_rcv     { printf("recv at sk-lookup\n"); }
fentry:__udp_queue_rcv_skb { printf("queue to sk=%p\n", args->sk); }
'
```

You'll see one send → one rcv → one queue per datagram. No state-machine churn.

### Watch UDP drops

```bash
# UDP receive errors (queue full, no socket, csum bad):
nstat | grep -i Udp
cat /proc/net/snmp | grep -A1 ^Udp

# Per-socket drops:
ss -uam   # u=UDP, a=all, m=memory
```

A common cause of UDP drops on busy servers: **too small sk_rcvbuf**. The default is `net.core.rmem_default` (often 212KB). For a high-throughput UDP receiver:
```bash
sudo sysctl -w net.core.rmem_max=33554432
# Then in app: setsockopt(fd, SOL_SOCKET, SO_RCVBUF, ..., 16MB)
```

## What to read in the kernel

- **`net/ipv4/udp.c:1233`** — `udp_sendmsg`. The TX side. Read top to bottom (~274 lines). Notice three sections: control-message parsing (cmsg loop), route lookup, and skb construction (the `ip_make_skb` vs `ip_append_data` branch). If you ever wonder "what does MSG_CONFIRM do?" — search this file.

- **`net/ipv4/udp.c:2588`** — `udp_rcv`. The RX entry. Short (~107 lines). Performs the basic checks (length, checksum), looks up the destination socket via `__udp4_lib_lookup`, dispatches to multicast/unicast paths.

- **`net/ipv4/udp.c:667`** — `__udp4_lib_lookup`. The 4-tuple → socket lookup. Note the two-pass strategy: first check the 4-tuple-keyed (connected) hash, then fall back to the 2-tuple (port-only) hash. Reading this clarifies what "connected UDP" actually means kernel-side.

- **`net/ipv4/udp.c:2422`** — `udp_queue_rcv_skb`. The queueing path. It's a thin (~21-line) wrapper; the work — the SO_FILTER / sk_filter check (BPF socket filters), the multicast membership check, and the back-pressure handling — lives in the call chain it heads (`udp_queue_rcv_one_skb` → `__udp_queue_rcv_skb` → `__udp_enqueue_schedule_skb`), which runs ~200 lines total including that slow path.

- **`net/ipv4/udp.c:2031`** — `udp_recvmsg`. The dequeue side. Read the MSG_PEEK handling — it's surprisingly subtle (locks the socket, walks the queue without removing).

- **`net/ipv4/ip_output.c:1553`** — `ip_make_skb`. How a single-shot UDP packet is built. Compare against the corked `ip_append_data` to understand the trade-off.

- **`net/ipv4/udp_offload.c`** — UDP GSO/GRO. Search `udp4_ufo_fragment` for the segmentation function and `udp_gro_receive` for the receive-side coalescing. Read this if you're pushing high-rate UDP (QUIC) and want to understand why GSO matters.

- **`net/ipv4/udp.c`** UDP_GRO / UDP_SEGMENT sockopt handlers — there is no dedicated `udp.rst`; UDP GSO/GRO and error queues are documented mainly in the code and the original commit logs. (`Documentation/networking/udplite.rst` covers the UDP-Lite variant.)

## Bullet Points

- UDP code lives in **`net/ipv4/udp.c`** (~3900 lines), `udp_offload.c`, and IPv6 mirror.
- TX: `udp_sendmsg → ip_make_skb → ip_send_skb → ...`. **No send queue** — datagrams hand off to IP immediately.
- RX: `udp_rcv → __udp4_lib_lookup → udp_queue_rcv_skb → enqueue + wake`.
- Lookups: 4-tuple for connected UDP, 2-tuple (port-only) for unconnected.
- **MSG_PEEK** reads without dequeueing; **MSG_TRUNC** flags truncated reads.
- **UDP GSO** (`UDP_SEGMENT` sockopt) gives one syscall → many MTU-sized datagrams. Used by QUIC.
- Drops happen when `sk_rcvbuf` is exhausted; tune via `net.core.rmem_max` + `SO_RCVBUF`.

## Check question

Why does UDP have a per-socket receive queue (`sk_receive_queue`) but no send queue?

<details>
<summary>Click to reveal answer</summary>

**Answer:** UDP doesn't *retransmit* — there are no ACKs, no reason to remember a sent datagram once it's handed to IP. The send path builds an skb in `udp_sendmsg` and immediately enters the IP output path; nothing is held back. TCP, by contrast, *must* keep sent skbs in `sk_write_queue` because it may need to retransmit them when ACKs don't arrive (Day 17). The receive queue *is* needed because the kernel arrives with a datagram before the application has called `recvmsg` to consume it; the queue holds it until the app shows up. Both protocols have receive queues; only TCP needs a send queue.

</details>

---

## Tomorrow

Day 15: TCP state machine — eleven states, ~7,700 lines of state-handling code in `tcp_input.c`.
