# Day 3 — The TX path: from `sendmsg` to the wire

> **Today's mission:** trace a TCP packet from a userspace `send()` to the moment it leaves the NIC. Total time: ~75 minutes.

## The journey, mirrored

Yesterday's RX path went wire → driver → IP → socket. Today's TX path goes the other direction:

![TX path](diagrams/day03_tx_path.png)

Six layers of work between your `send()` syscall and the bytes hitting the wire. Each one has a job and a place to fail.

## Stage 1: syscall to socket

When userspace calls `send(fd, buf, len, 0)` (or `write(fd, ...)` on a socket), the kernel walks:

```
sys_sendto / sys_write
  → sock_sendmsg
    → inet_sendmsg
      → sk->sk_prot->sendmsg     // dispatch by protocol
```

For TCP that's **`tcp_sendmsg`** at `net/ipv4/tcp.c:1447`. The function locks the socket, then calls `tcp_sendmsg_locked` (line 1117) which is where the real work happens.

## Stage 2: copy and queue

![socket write](diagrams/day03_socket_write.png)

`tcp_sendmsg_locked` does **two distinct things**:

1. **Copy bytes from userspace into kernel skbs.** Allocate skbs via `tcp_stream_alloc_skb`, copy data via `copy_from_iter` or zero-copy if MSG_ZEROCOPY. Append to `sk->sk_write_queue`.

2. **Maybe trigger transmission.** Calls `tcp_push` which eventually invokes `tcp_write_xmit` (line 2962 in `tcp_output.c`).

The split matters: queueing is cheap. Actually sending requires the congestion window to be open, the receive window to permit it, Nagle constraints to be satisfied, etc. So one `send()` may queue 1MB of bytes but only transmit 64KB right now.

The socket has a **send buffer** (`sk->sk_sndbuf`); if `sk_wmem_queued >= sk_sndbuf`, the socket goes to sleep until ACKs free up space (or returns `EAGAIN` for non-blocking sockets). Tunable: `net.ipv4.tcp_wmem` (min, default, max).

## Stage 3: TCP header and IP layer

`tcp_transmit_skb` builds the TCP header (sequence number, ACK, flags, window, checksum if not offloaded). Then calls into IP via:

```c
icsk->icsk_af_ops->queue_xmit(...)
  → ip_queue_xmit                  // net/ipv4/ip_output.c:546
```

`ip_queue_xmit` builds the IP header (after route lookup if needed), sets TTL/DSCP, then:

```c
ip_local_out
  → __ip_local_out
    → NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT, ...)
  → dst_output
    → ip_output
      → NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, ...)
      → ip_finish_output
        → ip_finish_output2
```

That's where **two netfilter hooks** fire: `NF_INET_LOCAL_OUT` (just after IP header is set, before routing decision is final) and `NF_INET_POST_ROUTING` (after routing, just before the device).

`ip_finish_output2` does **neighbour resolution** — if the next-hop's MAC isn't cached, queues the skb and triggers ARP. If cached, calls `neigh_output` which builds the Ethernet header and continues.

## Stage 4: device queue

`dev_queue_xmit` (a wrapper for **`__dev_queue_xmit` at `net/core/dev.c:4766`**) is the boundary between L3 and the device layer.

![qdisc](diagrams/day03_qdisc.png)

Steps inside `__dev_queue_xmit`:

1. **tcx/tc-bpf egress hook** runs first (before TX queue selection and the qdisc lookup).
2. **Pick a TX queue.** `netdev_pick_tx` uses `skb->queue_mapping`, RFS hints, or hash. Modern NICs have many TX queues for parallelism.
3. **Find the root qdisc** on that queue (`txq->qdisc`).
4. **Enqueue**: `q->enqueue(skb, q, &to_free)`.
5. **Pump**: `qdisc_run` → `__qdisc_run` → `q->dequeue` → `sch_direct_xmit` → `netdev_start_xmit` → driver's `ndo_start_xmit`.

Default qdisc on most modern systems is `fq_codel` (selected via the `net.core.default_qdisc` sysctl; the kernel's built-in default is still `pfifo_fast`). Day 23 covers qdiscs in detail.

## Stage 5: driver and hardware

`netdev_start_xmit(skb, dev, txq, more)` calls `dev->netdev_ops->ndo_start_xmit(skb, dev)`. Each driver implements this differently — fundamentally: build a DMA descriptor, write it to the TX ring, ring the doorbell. The NIC then DMAs and puts bytes on the wire.

Return value:
- `NETDEV_TX_OK` — submitted to NIC.
- `NETDEV_TX_BUSY` — TX ring full; reschedule. The qdisc holds the skb and tries again.

> ### There are no Dumb Questions
>
> **Q: Where does TSO/GSO fit into this?**
>
> A: Day 4. Briefly: TSO (TCP Segmentation Offload) lets the kernel hand a 64KB skb to the NIC, and the NIC chops it into MSS-sized packets. GSO (Generic Segmentation Offload) does the same in software when the NIC doesn't support TSO. Both happen *late* — at the qdisc/driver boundary, not during `tcp_sendmsg`.
>
> **Q: Why does the kernel sometimes block sendmsg vs return EAGAIN?**
>
> A: Socket flag. Default sockets block (sleep until space). Non-blocking sockets (`O_NONBLOCK`) return `EAGAIN`. `epoll`-based servers use non-blocking + `EPOLLOUT` notifications to know when to retry.
>
> **Q: What about MSG_ZEROCOPY?**
>
> A: A flag for `send()`. The kernel pins the user pages, points skb fragments at them directly (no copy), and notifies userspace via the error queue when transmission completes. Useful for very large transfers; userspace must hold the buffers until the notification.

## Today's experiment

### Trace a TCP send all the way through

Run the trigger **inside** the recorded command so the send is guaranteed to fire during the capture window — no second terminal, no race against `sleep`:

```bash
sudo trace-cmd record -p function_graph \
    -g tcp_sendmsg \
    -O nofuncgraph-overhead \
    -O funcgraph-tail \
    bash -c 'echo hello | nc -q 1 example.com 80; sleep 1'

sudo trace-cmd report | head -200
```

> **Prerequisite:** this needs outbound TCP reachability and a completed handshake during the capture — any host you can actually reach works. `example.com:80` reliably accepts the connection; `8.8.8.8:80` is filtered on many networks, so the handshake never completes and the payload `tcp_sendmsg` never fires. `-q 1` is a BSD/traditional `nc` flag — on nmap's `ncat`, drop it (use `nc example.com 80`).

You'll see the call tree from `tcp_sendmsg` down through `tcp_write_xmit`, `tcp_transmit_skb`, `ip_queue_xmit`, eventually `dev_hard_start_xmit`, then the driver's xmit. `trace-cmd` is global, so unrelated sends (e.g. background sshd) may appear too — your `nc` send is the one that ends in the full `ip_queue_xmit → ... → dev_hard_start_xmit` chain.

### Watch socket buffer accounting

On an idle box `ss -tim` shows only your SSH session, with the buffer/window counters static and near zero — the send-buffer accounting from Stage 2 is invisible until something is actively transmitting. So generate a sustained send first, then snapshot:

```bash
# Sustained upload so the send buffer actually has bytes in flight:
curl -s -o /dev/null -T /dev/zero --max-time 4 https://speed.cloudflare.com/__up &
ss -tim                      # watch the uploading socket while curl runs
```

Per-socket you get: send buffer used, congestion window, RTO, retransmits. `ss` does not print a field literally named `wmem_queued`; it surfaces send-buffer bytes as the `w` value inside `skmem:(...)` and in `Send-Q`. While `curl` runs, the **uploading** socket (to `:https`, not your idle SSH session) shows a large `Send-Q`/`skmem` `w`, plus `cwnd`, `unacked`, and `pacing_rate`:

```
ESTAB  0  2765014  10.0.0.4:36872  162.159.140.220:https
  skmem:(r0,rb131072,t0,tb4194304,f2858,w2811094,o0,bl0,d0) cubic wscale:13,10
  ... cwnd:1950 ... unacked:266 ... pacing_rate 1.42Gbps delivery_rate 120Mbps
```

`unacked` is segments sent but not yet ACKed (in flight); the `skmem` `w` value is bytes copied into `sk_write_queue` but not yet freed — directly the Stage 2 quantities the check question asks you to compare. If you have no internet egress, a local sink works but won't fully exercise the buffer cap (loopback has no bottleneck, so it drains as fast as it fills).

### Inspect qdisc statistics

```bash
tc -s qdisc show dev eth0
```

Drops, requeues, current backlog. On an idle box every one of these reads 0 — that is expected, not a failure:

```
qdisc mq 0: root
 Sent 1279377437 bytes 1467116 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
qdisc fq_codel 0: parent :1 limit 10240p flows 1024 quantum 1514 ...
 Sent 895133146 bytes 775553 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
```

(On a multi-queue NIC the root is `mq` with one `fq_codel` leaf per hardware TX queue, so you'll see several stanzas.) The next experiment forces `backlog` non-zero so you can actually watch it move.

### Force a backlog and watch

> **Warning:** this throttles **all** egress on `eth0`. If you are connected over that interface, your SSH/management traffic competes with the test transfer for the same 1mbit and the session may stall — run this on a throwaway VM or a non-management NIC.

First capture the qdisc that is actually there so you can restore it exactly (the live default here is `mq`, not `fq_codel`), then apply the rate limit:

```bash
ORIG=$(tc qdisc show dev eth0 | awk 'NR==1{print $2}')   # remember the real default
sudo tc qdisc replace dev eth0 root tbf rate 1mbit burst 32kbit latency 50ms
# now egress is rate-limited; large transfers back up at the qdisc
```

Drive traffic that actually leaves `eth0`. The backlog only grows for traffic egressing this device — a `127.0.0.1` transfer goes through the `lo` qdisc and shows backlog `0b 0p`, so loopback is *not* a substitute. On a second machine run `iperf3 -s`, then here:

```bash
iperf3 -c <that-host-IP> -t 30 &
watch -n1 'tc -s qdisc show dev eth0'   # the `backlog ...b ...p` line climbs
```

No second machine or `iperf3`? Any sustained upload over `eth0` backs up the qdisc the same way:

```bash
curl -s -o /dev/null -T /dev/zero --max-time 20 https://speed.cloudflare.com/__up &
watch -n1 'tc -s qdisc show dev eth0'
```

Restore (drop back to whatever was really there, and stop the transfer):
```bash
kill %1 2>/dev/null                       # stop the backgrounded transfer
sudo tc qdisc del dev eth0 root           # restores the kernel/runtime default
# or, to put back exactly what you captured: sudo tc qdisc replace dev eth0 root "$ORIG"
```

---

## What to read in the kernel

- **`net/ipv4/tcp.c`** — `tcp_sendmsg` (line 1447), `tcp_sendmsg_locked` (line 1117). The core of TCP user-side semantics.
- **`net/ipv4/tcp_output.c`** — `tcp_write_xmit` (line 2962), `tcp_transmit_skb`. Decides what to send when.
- **`net/ipv4/ip_output.c`** — `ip_queue_xmit` (line 546), `ip_local_out` (line 125), `ip_finish_output2`.
- **`net/core/dev.c`** — `__dev_queue_xmit` (line 4766), the qdisc dance.
- **`net/sched/sch_generic.c`** — `__qdisc_run`, `sch_direct_xmit`, the qdisc pump.
- **`include/linux/netdevice.h`** — `struct net_device_ops` with `ndo_start_xmit` (line 1441).
- **`Documentation/networking/scaling.rst`** — how multi-queue TX works.

---

## Bullet Points

- TX path: `sendmsg → tcp_sendmsg → tcp_write_xmit → tcp_transmit_skb → ip_queue_xmit → dev_queue_xmit → qdisc → driver → wire`.
- **`sk_write_queue`** holds queued-but-not-yet-transmitted skbs; `sk_sndbuf` caps it.
- **`tcp_write_xmit`** decides what to send *now* based on cwnd, snd_wnd, Nagle, TSO size.
- **Two netfilter hooks** on TX: `NF_INET_LOCAL_OUT` and `NF_INET_POST_ROUTING`.
- **Neighbour resolution** (ARP/NDP) happens in `ip_finish_output2`.
- **`__dev_queue_xmit`** runs tcx/tc-bpf egress, picks a TX queue, enqueues to qdisc.
- Default qdisc on modern Linux is **`fq_codel`**.
- Driver's **`ndo_start_xmit`** is the final hand-off to hardware.

---

## Check question

You call `send(fd, buf, 1MB, 0)` on a TCP socket whose RTT is 100ms and BDP is much smaller than 1MB. The send returns immediately with the full 1MB written. Where are those bytes physically right now?

<details>
<summary>Click to reveal answer</summary>

**Answer:** In the kernel's `sk_write_queue` — copied from userspace into a chain of skbs hanging off the socket. The send returned because `sk_sndbuf` was big enough to accept the queueing; it doesn't mean the bytes left the box. They'll trickle out as the receiver ACKs and the congestion window opens. If you read `/proc/<pid>/status` you'd see them counted against the kernel's TCP memory accounting, not against your process's RSS. To know how much is actually on the wire vs queued, run `ss -tim` and look at `unacked` (sent but not ACKed) vs `wmem_queued` (queued).

</details>

---

## Tomorrow

Day 4: GRO, GSO, TSO. Why a 64KB packet enters `ip_rcv` even though Ethernet's MTU is 1500.
