# Day 15 — TCP state machine

> **Today's mission:** trace a TCP connection through every state. Understand why TIME_WAIT exists, why FIN_WAIT_2 sometimes hangs, and how the kernel implements the state transitions. Total time: ~75 minutes.

## What "state machine" really means here

TCP is a connection-oriented protocol — every connection has *state* that both ends maintain through its lifetime. The states encode "what's the next legal thing this connection can do?" The state transitions happen in response to:

- Application calls (`connect`, `listen`, `accept`, `close`).
- Received segments (SYN, SYN-ACK, ACK, FIN, RST).
- Timer events (RTO firing, 2MSL elapsed).

The whole apparatus is in `tcp_rcv_state_process` (`net/ipv4/tcp_input.c:7119`) for incoming-segment-driven transitions, and in `tcp_set_state` (`net/ipv4/tcp.c:2964`) for explicit state changes from anywhere. Reading those two functions teaches you 80% of TCP control flow.

## The eleven states

![TCP states](diagrams/day15_tcp_states.png)

Defined in `include/net/tcp_states.h:13`:

```c
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NEW_SYN_RECV,
    TCP_BOUND_INACTIVE,
};
```

(The last two are internal sub-states — NEW_SYN_RECV is a half-open SYN entry on the listener; BOUND_INACTIVE is a recently-bound socket with no listen yet.)

### The connection-establishment states

- **CLOSED** — no connection. Initial and final state.
- **LISTEN** — passive open: the server's listening socket. Waits for incoming SYNs.
- **SYN_SENT** — active open: client sent SYN, waiting for SYN-ACK.
- **SYN_RECV** — server received SYN, sent SYN-ACK, waiting for the ACK that completes the 3-way handshake.
- **ESTABLISHED** — handshake complete, data flowing.

### The graceful-close states

TCP's connection close is *bidirectional*: each direction can shut down independently (a "half-close"). This produces the messy diamond of close states.

The side that calls `close()` first goes:

- **FIN_WAIT_1** — sent FIN, waiting for ACK or peer's FIN.
- **FIN_WAIT_2** — peer ACKed our FIN; waiting for peer's FIN.
- **TIME_WAIT** — peer's FIN received; ACKed; we wait 2*MSL before fully closing.

The side that receives the close goes:

- **CLOSE_WAIT** — received FIN; app hasn't called `close()` yet.
- **LAST_ACK** — app called `close()`; we sent our FIN; waiting for ACK.

If both sides close simultaneously, you can hit:

- **CLOSING** — sent FIN, peer's FIN arrived before our ACK; both sides are now closing.

## Drivers of state changes

### Application-initiated

| Call | Effect |
|------|--------|
| `socket()` + `listen()` | CLOSED → LISTEN |
| `connect()` | CLOSED → SYN_SENT (sends SYN) |
| `close()` from ESTABLISHED | ESTABLISHED → FIN_WAIT_1 (sends FIN) |
| `close()` from CLOSE_WAIT | CLOSE_WAIT → LAST_ACK (sends FIN) |
| `shutdown(SHUT_WR)` | half-close: same as close but socket stays open for reads |

### Segment-driven

The big function is `tcp_rcv_state_process` (`net/ipv4/tcp_input.c:7119`). It dispatches by current state, then handles flags. Pseudocode:

```c
switch (sk->sk_state) {
case TCP_LISTEN:    handle SYN -> create child sock in NEW_SYN_RECV
case TCP_SYN_SENT:  handle SYN-ACK -> ESTABLISHED, send ACK
case TCP_SYN_RECV:  handle ACK -> ESTABLISHED
default:            handle FIN, RST, ACKs that drive close states
}
```

For non-trivial states (ESTABLISHED, FIN_WAIT_*) it falls through to `tcp_data_queue` for normal data delivery and runs the close-state transitions when FIN arrives.

### Timer-driven

- **SYN-ACK retransmit timer**: in SYN_SENT and SYN_RECV, the SYN/SYN-ACK is retransmitted with exponential backoff if no progress.
- **Retransmit timer (RTO)**: in ESTABLISHED, fires when an ACK is overdue (Day 17).
- **TIME_WAIT timer (2*MSL)**: ~60s on Linux; controlled by `net.ipv4.tcp_fin_timeout` (which is misleadingly named — it actually controls FIN_WAIT_2, but is widely used).
- **Keepalive timer** (if `SO_KEEPALIVE`): probes idle connections.

## Why TIME_WAIT exists

TIME_WAIT is the most-asked-about TCP state. Two reasons:

1. **Make sure our last ACK reaches the peer.** If our final ACK is lost, the peer's `LAST_ACK` retransmits its FIN. We need to be in TIME_WAIT — still able to send an ACK — to handle that retransmit. If we'd already moved to CLOSED, we'd reply with RST, which the peer would interpret as an error.
2. **Prevent old packets from a previous incarnation of the 4-tuple from being delivered to a new connection.** Without TIME_WAIT, a freshly-opened connection on the same 4-tuple might receive late-arriving packets from the old connection. 2*MSL = ~60 seconds is the maximum lifetime of an in-flight IP packet (TTL plus router queueing). After that, old packets have certainly been discarded.

### TIME_WAIT cost

Each TIME_WAIT socket consumes a small amount of kernel memory and one entry in the tcp_hashinfo.ehash. On a busy server with many short connections (HTTP, microservices), TIME_WAIT count can grow to tens of thousands.

Mitigations:

- **`SO_REUSEADDR`** lets a new socket bind even if a recent connection's TIME_WAIT entry occupies the 4-tuple.
- **`net.ipv4.tcp_max_tw_buckets`** caps the global TIME_WAIT count; older entries get RST'd. Default 262144.
- **`net.ipv4.tcp_tw_reuse=1`** lets the kernel reuse TIME_WAIT sockets for new outgoing connections (uses TCP timestamps to ensure no overlap). Safe for client-side; doesn't affect listening sockets.
- (~~`tcp_tw_recycle`~~ was removed in 4.12 — was unsafe behind NAT.)

### FIN_WAIT_2 and the 60-second timeout

If a peer ACKs our FIN but never sends its own FIN (perhaps the application is hung), we sit in FIN_WAIT_2. To avoid leaking, the kernel times out after `net.ipv4.tcp_fin_timeout` seconds (default 60) and force-closes. This is why "broken peers" don't break us forever.

## Today's experiment

```bash
# Watch state in real time
watch -n 0.5 'ss -tan'

# In another terminal
nc -l 9999 &
sleep 0.5
nc localhost 9999      # both ends in ESTAB
# In each: Ctrl-D to close

# You'll see:
# initial:   LISTEN (server)
# connect:   ESTAB (both)
# nc client closes:  FIN_WAIT_2 (client) / CLOSE_WAIT (server) briefly
# nc server closes:  TIME_WAIT (client) / CLOSED (server)
# 60s later: TIME_WAIT entry expires
```

Trace state transitions:
```bash
sudo bpftrace -e '
fentry:tcp_set_state {
  printf("sk=%p state=%d -> %d\n", args->sk, args->sk->__sk_common.skc_state, args->state);
}'
```

You'll see every transition with the kernel's view of `sk` pointer.

### Force-close to see TIME_WAIT

```bash
# Server keeps listening; client connects then disconnects
nc -l 9999 &
sleep 0.1
echo q | nc -q 0 localhost 9999

# Immediately:
ss -tan | grep 9999
# tcp  TIME-WAIT  0  0  127.0.0.1:9999  127.0.0.1:NNNN
```

Observe: the closing side sits in TIME_WAIT for ~60s. The other side returns to CLOSED immediately.

## What to break

- **Set `tcp_fin_timeout=5`**, then close a connection where the server doesn't reciprocate. You'll see the FIN_WAIT_2 expire after ~5s. Useful for diagnosing connection leaks.
- **Hammer `tcp_max_tw_buckets`**: reduce it to 100 (`sudo sysctl -w net.ipv4.tcp_max_tw_buckets=100`), run a load test that opens many short connections. After 100 TIME_WAITs, new closes get RST'd; you'll see `tcpext.tw_bucket_overflow` increment.
- **Try `tcp_tw_reuse=1`** for outgoing-only workloads: relieves the bucket pressure for clients that connect frequently to the same servers (test client + benchmarking tools).

## What to read in the kernel

- **`include/net/tcp_states.h:13`** — the state enum. Tiny file (~50 lines). Read it to know the canonical names.

- **`net/ipv4/tcp_input.c:7119`** — `tcp_rcv_state_process`. The big state-machine function (~300 lines including all branches). Read it once with the diagram open. Notice: it dispatches by current state (`switch (sk->sk_state)`) and handles each state's possible incoming events. The bulk is the SYN_SENT and SYN_RECV cases (handshake completion); the other states share a fall-through to data processing plus close-flag handling.

- **`net/ipv4/tcp.c:2964`** — `tcp_set_state`. The explicit state change function. Note the per-state SNMP counter increments (`TCP_INC_STATS`); this is how `nstat` reports `Tcp.CurrEstab`, etc. Also note the ehash insert/remove on transitions to/from ESTABLISHED.

- **`net/ipv4/tcp.c:3313`** — `tcp_close`. What happens when the application calls `close()`. Read this end-to-end (~150 lines). Notice the LINGER handling, the multi-step state transitions (ESTABLISHED → FIN_WAIT_1, etc.), and the `tcp_close_pending_data` cleanup.

- **`net/ipv4/tcp_ipv4.c:2072`** — `tcp_v4_rcv`. The IP-layer entry. Looks up the sock via the ehash (4-tuple match) and dispatches into the state machine. Read this to see how a packet arrives, gets associated with a sock, and proceeds.

- **`net/ipv4/tcp_minisocks.c`** — minisockets (TIME_WAIT, NEW_SYN_RECV). TIME_WAIT sockets are *reduced* sock objects (no full state, just enough to ACK retransmitted FINs). Look at `tcp_time_wait` for the conversion.

- **`net/ipv4/tcp_timer.c`** — all TCP timers. `tcp_keepalive_timer`, `tcp_compressed_ack_kick`, etc. Useful when a state is stuck and you wonder which timer should be advancing it.

- **`Documentation/networking/tcp.rst`** — overview. Brief.

## Bullet Points

- **11 TCP states** in `include/net/tcp_states.h`. ESTABLISHED is the steady state; rest are open or close transitions.
- **`tcp_rcv_state_process`** drives segment-driven transitions; **`tcp_set_state`** does explicit changes.
- **TIME_WAIT** holds for `2*MSL` (~60 s). Two purposes: (1) ACK retransmitted FIN, (2) prevent reincarnation overlap.
- **`tcp_fin_timeout`** controls FIN_WAIT_2 timeout (default 60).
- **`tcp_max_tw_buckets`** caps global TIME_WAIT count.
- **`tcp_tw_reuse=1`** lets clients reuse TIME_WAIT slots for new connects (safe).
- **Inspect** with `ss -tan`. Trace transitions with `bpftrace fentry:tcp_set_state`.

## Check question

Why does TIME_WAIT exist? What problem does it solve, and why specifically 2*MSL seconds?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Two distinct problems. **(1) Final-ACK reliability.** When we close, our final ACK might be lost; the peer (in LAST_ACK) will retransmit its FIN. To respond with another ACK we must still exist as a TCP entity — TIME_WAIT keeps us responsive. If we'd already moved to CLOSED, we'd send RST, which the peer would interpret as an error. **(2) Reincarnation safety.** A new connection on the same 4-tuple could be created shortly after the old one closes. If old packets are still in flight in the network, they could be misdelivered to the new connection. **2*MSL** (~60s on Linux, where MSL is "Maximum Segment Lifetime") is the worst-case time an IP packet can be in flight (TTL × max router queueing). After 2*MSL, old packets have certainly been discarded by routers; the 4-tuple is safe to reuse.

</details>

---

## Tomorrow

Day 16: TCP congestion control. CUBIC, BBR, and the framework that lets you swap algorithms.
