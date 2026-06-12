# Day 30 — Capstone: trace one packet end to end

> **Mission:** pick one real packet from your system. Trace it through every kernel layer you've learned over the last 29 days. Write up what you saw, with kernel function names and rough timings. ~3–4 hours.

## Why this exercise

Twenty-nine days have given you a vocabulary: sk_buff, NAPI, qdisc, fib_lookup, conntrack, netfilter hook, sk_prot, congestion control, retransmit timer, MPTCP, kTLS. Each in isolation. The capstone is to see them *cooperate* on one real, observable packet.

When you can describe a single ping or HTTP request as a sequence of kernel operations with names, you've internalized the model. That's the goal.

## The exercise

Pick a packet — your choice of:

- **A TCP request/response over a real network**: `curl https://example.com`, watching the SYN go out and the response come back.
- **A simple ICMP exchange**: `ping -c 1 8.8.8.8`.
- **A UDP service interaction**: `dig @8.8.8.8 example.com`.
- **A bridged packet**: traffic between two namespaces over a Linux bridge.
- **A NAT'd packet**: outgoing traffic via a masquerade rule, tracking conntrack state.

Trace it through, identify each kernel layer it traverses, and write up the journey.

![packet path overview](diagrams/day30_capstone.png)

## Tools you'll use

- **`trace-cmd record -p function_graph`**: full function-call tree.
- **`perf trace`**: event-level visibility across syscalls and tracepoints.
- **`bpftrace` one-liners**: targeted measurements for specific functions.
- **`tcpdump`/`tshark`**: wire-level view (what actually went out vs what kernel state thinks).
- **`ss -tipsm`**: socket-level state at any moment.
- **`/proc/net/*`** and `/proc/sys/net/*`: kernel state and tunables.
- **`bpftool`**: BPF program inspection if you've got any attached.

## A worked example: `curl http://example.com`

Let's pre-walk what your trace might look like.

### Step 1: DNS lookup (UDP)

`curl` calls `getaddrinfo("example.com")` → glibc → DNS query.

- Userspace: `socket(AF_INET, SOCK_DGRAM, 0)` → `sendto(...)` to your DNS server's port 53.
- Kernel: **`udp_sendmsg`** (`net/ipv4/udp.c:1233`) builds an skb, hands to IP.
- Outbound: `ip_send_skb` → routing → `dev_queue_xmit` → qdisc (`fq_codel`) → driver → wire.
- Wait for response.
- Inbound: NIC RX → NAPI poll → driver allocates skb → GRO → `__netif_receive_skb_core` → `ip_rcv` → routing → `udp_rcv` (`net/ipv4/udp.c:2588`) → 4-tuple lookup → enqueue on `sk_receive_queue` → wake `recvfrom`.
- Userspace: `recvfrom` returns the DNS response.

### Step 2: TCP connect (SYN)

`curl` calls `socket(AF_INET, SOCK_STREAM)` → `connect(example.com:80)`.

- Userspace: connect syscall.
- Kernel: `tcp_v4_connect` (`net/ipv4/tcp_ipv4.c:221`).
  - Route lookup → fib_lookup → `fib_table_lookup` (`net/ipv4/fib_trie.c`).
  - Pick source port → `inet_csk_get_port` → ehash insert.
  - Build SYN segment → `tcp_transmit_skb` (`net/ipv4/tcp_output.c`).
- IP layer: `ip_queue_xmit` → `ip_local_out` → `NF_INET_LOCAL_OUT` netfilter hook → conntrack creates NEW entry → `dst_output` → `ip_output` → `NF_INET_POST_ROUTING` hook → conntrack possibly NATs → `ip_finish_output2` → neighbor resolution (ARP if not cached) → `dev_queue_xmit` → qdisc → driver.
- Sock state: `TCP_SYN_SENT`.

### Step 3: TCP handshake completion (SYN-ACK + ACK)

Inbound SYN-ACK:
- NIC → NAPI → driver → skb → GRO (probably no coalesce for 1 packet) → `ip_rcv` → `NF_INET_PRE_ROUTING` → conntrack matches → `ip_rcv_finish` → routing → `ip_local_deliver` → `NF_INET_LOCAL_IN` hook → `tcp_v4_rcv` (`net/ipv4/tcp_ipv4.c:2068`) → ehash lookup finds our sock in SYN_SENT → `tcp_rcv_state_process` (`net/ipv4/tcp_input.c:7119`) sees SYN+ACK → calls `tcp_set_state(sk, TCP_ESTABLISHED)` and queues outgoing ACK.

Outbound ACK: same path as the SYN, just smaller and through a now-EST sock.

### Step 4: HTTP request (TCP send)

`curl` calls `send(fd, "GET / HTTP/1.1\r\n...", n, 0)`.

- `tcp_sendmsg` (`net/ipv4/tcp.c:1447`) → `tcp_sendmsg_locked` → copy to skb → append to `sk_write_queue` → `tcp_push` → `tcp_write_xmit` decides to send (cwnd open, snd_wnd open, Nagle satisfied) → `tcp_transmit_skb` → IP → ... → wire.

### Step 5: HTTP response (TCP recv)

Inbound packets arrive: NIC → NAPI → driver → skb → GRO (coalesce up to 64 KB!) → `ip_rcv` → `tcp_v4_rcv` → tcp state machine:
- ACKs advance `snd_una`, free skbs from `sk_write_queue`, possibly grow cwnd via the CC algorithm's `cong_avoid`.
- DATA segments append to `sk_receive_queue`, wake `recvmsg`.

`curl` calls `recv(fd, buf, n, 0)` → `tcp_recvmsg` → copies from `sk_receive_queue` to user buffer.

### Step 6: TCP close

`curl` finishes, calls `close(fd)`. `tcp_close` (`net/ipv4/tcp.c:3310`) builds FIN, sends it, transitions to `TCP_FIN_WAIT_1`, waits for peer's ACK, transitions to `TCP_FIN_WAIT_2`, waits for peer's FIN, transitions to `TCP_TIME_WAIT`. ~60s later: state CLOSED, sock freed.

### What you saw

A single web fetch involves: 2 DNS packets (UDP), 7 TCP packets minimum (SYN, SYN-ACK, ACK, request, response, FIN, FIN-ACK), routing lookups, neighbor resolution, GRO coalescing, congestion control, the netfilter PREROUTING/LOCAL_IN/LOCAL_OUT/POSTROUTING hooks ×N, conntrack state, qdisc scheduling. That's the kernel networking stack in action.

## Suggested concrete experiment

```bash
# 0. Remove any stale trace.dat. trace-cmd writes it as root, and a leftover
#    file from a prior run makes `report` silently read OLD data instead of
#    erroring.
sudo rm -f trace.dat

# 1. Set up tracing — records for 8s as a background job in THIS shell
sudo trace-cmd record -p function_graph \
    -g tcp_sendmsg \
    -g tcp_v4_rcv \
    -e net:* \
    -e tcp:* \
    -e skb:kfree_skb \
    sleep 8 &

# 2. Generate one packet exchange in this same shell
nc -l 9999 >/dev/null &
sleep 0.5
echo "test" | nc -q 1 localhost 9999

# 3. Wait for the background trace-cmd recorder (sleep 8) to exit, so
#    trace.dat is fully finalized before we read it. `wait` (no args) blocks
#    on the recorder; it also reaps the nc listener, which has already exited
#    once the client closed the connection.
wait

# 4. Generate the report
sudo trace-cmd report > /tmp/packet_trace.txt

# 5. Walk through the report
less /tmp/packet_trace.txt

# 6. Clean up — trace-cmd dropped a (potentially large) trace.dat here
rm -f trace.dat
pkill -f 'nc -l 9999' 2>/dev/null  # usually already gone after the single connection
```

> **Why loopback, and what it skips.** This experiment uses `nc localhost` for reproducibility — no external network needed. Be aware that loopback is a degenerate path: it uses the `noqueue` qdisc (no `fq_codel`), has no driver/NAPI, no GRO coalescing, no ARP/neighbor resolution, and no routing to a gateway — i.e. most of the layers the worked example above emphasizes. Its receive side is also delivered via the backlog (`loopback_xmit` → `__netif_rx` → `process_backlog` → `__netif_receive_skb`), which never calls the *exported* `netif_receive_skb` symbol, so a `-g netif_receive_skb` subtree comes up empty on loopback — that is why step 1 graphs `-g tcp_v4_rcv` (a dependable TCP receive entry on both loopback and real NICs) instead. To see the full stack — qdisc, GRO, neighbor, routing, driver — re-run while driving real off-box traffic, e.g. `curl -s http://example.com >/dev/null` or `ping -c1 8.8.8.8`, on a real interface.

The send side comes out looking like this (function_graph nesting; CPU/timestamp columns trimmed for width):

```
  nc-506899 [001] ...1. 245526.239429: funcgraph_entry: |  tcp_sendmsg() {
  nc-506899 [001] ...1. 245526.239432: funcgraph_entry: |    tcp_sendmsg_locked() {
  nc-506899 [001] ...1. 245526.239452: funcgraph_entry: |      tcp_push() {
  nc-506899 [001] ...1. 245526.239453: funcgraph_entry: |        tcp_write_xmit() {
  nc-506899 [001] ...1. 245526.239456: funcgraph_entry: |          __tcp_transmit_skb() {
  nc-506899 [001] ...1. 245526.239498: funcgraph_entry: |            ip_queue_xmit() {
  nc-506899 [001] ...2. 245526.239500: funcgraph_entry: |              ip_local_out() {
  nc-506899 [001] ...2. 245526.239512: funcgraph_entry: |                ip_output() {
  nc-506899 [001] ...3. 245526.239515: funcgraph_entry: |                  ip_finish_output2() {
```

The receive side opens with `tcp_v4_rcv() { → tcp_inbound_hash() { ...`. The *indented nesting* above is the raw `trace-cmd report` format — it maps onto the arrow chain you'll write below. Confirm your `trace.dat` actually contains this `tcp_sendmsg`/`tcp_v4_rcv` subtree before you invest 1–2 hours on the write-up.

The report will be long — hundreds to thousands of lines. Pick **one TCP segment** (the SYN you sent, or the response you received) and follow it through the kernel:

- Find the entry point (e.g., `tcp_sendmsg` for an outgoing segment, `tcp_v4_rcv` for incoming).
- Note every function called in sequence.
- For each, look up which file/line it's at (click any `path:N` reference to open that file/line on GitHub at the pinned kernel tag).
- Write the sequence as: "tcp_sendmsg → tcp_sendmsg_locked → ip_queue_xmit → ip_local_out → ...".

## Annotated walk-through deliverable

Your final write-up should be ~1–2 pages covering:

- The packet you traced and its purpose.
- Each kernel function it touched, in order.
- For each function: the file/line, what it did, what data structure it touched.
- Total time elapsed (tracecmd has ns timestamps; you can compute this).
- One surprise you found ("I didn't realize netfilter ran *twice* for forwarded traffic").

That document is the artifact that proves you understood the system. Save it; use it as a reference.

## What's not covered

In 30 days you skipped:

- **rxrpc** (AFS-style transport — `net/rxrpc/`).
- **SCTP** — interesting alternate transport (`net/sctp/`).
- **DCCP** — mostly historical; the in-tree implementation was removed in 6.16, so there's no longer a `net/dccp/`.
- **RDS, TIPC, Sun RPC** — niche transports.
- **Bluetooth** (`net/bluetooth/`) — entirely different stack with its own protocols.
- **CAN bus** (`net/can/`) — automotive networking.
- **NFC** (`net/nfc/`).
- **L2TP, PPP, X.25** — legacy/specialized protocols.
- **Phonet, QRTR**, etc. — single-application stacks.

If your work touches one of these, apply the same methodology — read source, trace with tools, observe — to learn it. The patterns repeat.

## After Day 30

Real fluency comes from working on the stack, not just reading it. Pick one of:

- **Submit a fix.** Look at the netdev mailing list, find a `Reported-by` you can verify, propose a fix.
- **Write a tool.** Build a tracer for something you want to know — a kerne-side per-flow latency histogram, a custom drop-categorizer, a cgroup-aware bandwidth tracker.
- **Optimize a workload.** Take a real performance problem you face — high latency, drops, packet reordering — and use what you learned to diagnose and fix.
- **Read the eBPF book** (the companion to this one). It builds on the kernel-networking foundation laid here, showing you how to *write* the BPF programs that hook into all these places.

You now know the Linux kernel network stack from first principles. That's a durable skill. Welcome to the community.
