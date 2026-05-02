# Day 17 — TCP retransmission, RACK, FACK, recovery

> **Today's mission:** see Linux's loss detection and recovery in action. Total time: ~75 minutes.

## Detection signals

![retrans flow](diagrams/day17_retrans.png)

TCP detects loss via three signals:

1. **RTO** — Retransmission Timeout. If no ACK within ~RTT*4, retransmit.
2. **Duplicate ACKs** — three or more dup ACKs trigger fast retransmit.
3. **RACK** (Recent ACK; default since 4.4) — uses ACK timing to infer loss; SACK-aware.

## The recovery state

When loss is detected, the kernel transitions into Fast Recovery:
- Halve `cwnd`, set `ssthresh = cwnd/2`.
- Retransmit the missing segments.
- For each new ACK, possibly retransmit the next loss.
- Exit recovery when `snd_una` advances past where loss was detected.

## RACK in detail

Older detection (FACK, NewReno) was bag-of-tricks. RACK is cleaner: a segment is considered lost if a *later* segment (by time, not sequence) has been ACKed and the gap is large enough.

```c
sysctl net.ipv4.tcp_recovery   # 1 = RACK enabled (default)
```

## Today's experiment

```bash
# Force packet loss with netem:
sudo tc qdisc add dev lo root netem loss 5%
iperf3 -s &
iperf3 -c 127.0.0.1 -t 30

# Watch retrans counter:
nstat -a | grep -i Retrans

# Per-socket:
ss -tin | grep -A 1 ESTAB

# Restore:
sudo tc qdisc del dev lo root
```

Trace recovery:
```bash
sudo bpftrace -e 'fentry:tcp_enter_recovery { @ = count(); } interval:s:10 { print(@) }'
```

## What to read in the kernel

- **`net/ipv4/tcp_recovery.c`** — RACK.
- **`net/ipv4/tcp_input.c`** — `tcp_fastretrans_alert`, `tcp_enter_recovery`, `tcp_clean_rtx_queue`.
- **`net/ipv4/tcp_timer.c`** — RTO timer.
- **RFC 5681 / 6675 / 8985** — Reno, SACK, RACK algorithms.

## Bullet Points

- TCP detects loss via RTO, dup ACKs, or RACK.
- Recovery halves cwnd and retransmits missing segments.
- **RACK** is the modern default (since 4.4); time-based, SACK-aware.
- Retransmits visible in `ss -tin` and `/proc/net/netstat`.
- Use `tc netem` to inject loss for testing.

## Check question

Why does losing 1% of packets cause much more than 1% throughput loss on a long-RTT path?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Each loss causes Reno/CUBIC to halve cwnd. On a 100ms RTT path, recovery (growing cwnd back) takes seconds. A 1% loss rate translates to one halving every ~100 packets, meaning cwnd never converges to its ideal value. The Mathis formula approximates: throughput ≈ MSS / (RTT * sqrt(loss)). 1% loss on 100ms RTT caps you at about 100 Mbps regardless of path bandwidth. BBR partially fixes this because it doesn't depend on loss as a signal.

</details>

## Tomorrow

Day 18: socket options.
