# Day 17 — TCP retransmission, RACK, FACK, recovery

> **Today's mission:** understand how TCP detects packet loss and recovers without breaking ordering. Three detection mechanisms, one recovery state, lots of timers. Total time: ~75 minutes.

## What "loss" means to TCP

TCP guarantees in-order, reliable delivery. The internet is neither in-order nor reliable. TCP's job is to detect loss/reorder and retransmit, while telling the application "all good, here's your bytes in order."

The sender keeps every transmitted-but-unacked segment in the **retransmit queue** (`tp->packets_out`, hanging off `sk_write_queue`). It listens to ACKs to learn what got through. When it suspects a segment is lost, it sends another copy.

The hard part is *suspecting loss* without overreacting to mere reordering.

## Three detection mechanisms

![retrans flow](diagrams/day17_retrans.png)

### 1. RTO — Retransmission Timeout

The classical mechanism. The sender maintains a smoothed RTT estimate (`srtt_us`) and an RTT variance (`rttvar_us`). The RTO is approximately:

```
RTO = srtt + rttvar    (clamped to [200ms, 120s])
```

If no ACK arrives within RTO of the *first* unacked segment, the timer fires:

- The first unacked segment is retransmitted.
- The kernel enters CA_Loss state.
- `cwnd` is reset to `tcp_packets_in_flight(tp) + 1` — effectively ~1 MSS after a timeout (slow start from scratch).
- RTO is doubled (exponential backoff).

Implementation: **`tcp_retransmit_timer`** at `net/ipv4/tcp_timer.c:535`. Read this once — it's the canonical loss-recovery entry point.

RTO is the most pessimistic detection: it waits hundreds of ms before declaring loss. Useful as a backstop but expensive in latency. The other two mechanisms react faster.

### 2. Duplicate ACKs / Fast Retransmit

If a segment is lost but later ones arrived, the receiver keeps ACKing the highest *contiguous* sequence — producing duplicate ACKs ("dupacks").

Classic Reno rule: **3 dupacks → fast retransmit**. The sender retransmits the missing segment immediately, without waiting for RTO.

This works for single-segment losses. For burst losses (multiple gaps), Reno needs SACK to keep going.

### 3. RACK — Recent ACK (the modern default since 4.4)

`net/ipv4/tcp_recovery.c`. RACK uses ACK *timing* instead of duplicate-ACK counts. The intuition:

> "If a segment Y was sent before X, and X has been acknowledged, then Y is probably lost."

Specifically: if some segment with a *later* send time has been SACKed, and the gap is >= reordering window, the unacked earlier segment is declared lost. This catches loss faster than Reno's 3-dupack rule, especially with reordering.

RACK is the current default (`net.ipv4.tcp_recovery=1`). If you ever set `tcp_recovery=0`, you fall back to legacy 3-dupack detection — slower and more conservative.

## SACK — Selective Acknowledgments (RFC 2018)

By default, ACKs are cumulative: "I have everything up to seq N." This is enough for Reno but limits parallelism. With **SACK**, ACKs include up to 4 ranges: "I have up to N, and also blocks A-B, C-D, E-F." The sender uses this to avoid retransmitting segments the receiver already has.

SACK is on by default. The state structures: `tcp_sock->sacked_out`, `tp->lost_out`, `tp->retrans_out` track per-segment status. Each skb in the retransmit queue has a `tcb->sacked` bitfield (`TCPCB_SACKED_ACKED`, `TCPCB_LOST`, `TCPCB_SACKED_RETRANS`).

## The recovery state

When loss is detected (any of the three mechanisms above), the kernel calls **`tcp_enter_recovery`** (`net/ipv4/tcp_input.c:3177`):

1. Sets `icsk->icsk_ca_state = TCP_CA_Recovery`.
2. Halves `cwnd` (PRR — Proportional Rate Reduction; reduces gracefully across RTT).
3. Calls the CC algorithm's `set_state(CA_Recovery)` — most algorithms record the loss event.

While in Recovery, the kernel transmits new segments at the reduced rate and selectively retransmits the lost ones. Recovery ends when `snd_una` advances past where the loss was detected (the "recovery point") — the kernel calls `tcp_complete_cwr` and returns to CA_Open.

For RTO-driven loss, the kernel uses **`tcp_enter_loss`** (`net/ipv4/tcp_input.c:2554`) instead — much more punitive (cwnd=1, slow start).

## The recovery state machine: `tcp_fastretrans_alert`

`net/ipv4/tcp_input.c:3328` — entered on every ACK that might require recovery action. Walks the state machine:

```
Open      → Disorder    (first dupack or SACK)
Disorder  → Recovery    (loss confirmed; start retransmits)
Recovery  → Open        (recovery point reached)
Open      → Loss        (RTO fired)
Loss      → Open        (after RTO recovery)
```

Each state has its own logic for what to send and how to count cwnd. ~114 lines; read it once.

## ACK clocking and PRR

When the sender enters Recovery, the question is "how fast should I retransmit?"

- Naïve answer: blast all the missing segments immediately. Bad — overshoots and causes more loss.
- PRR answer: pace retransmits at exactly the rate of returning ACKs, gradually working cwnd down to half.

PRR (RFC 6937) is the kernel's recovery rate-control strategy. The `prr_out`, `prr_delivered` fields in `tcp_sock` track its state.

## Today's experiment

Use `tc netem` to inject loss and watch recovery happen:

```bash
# Inject 5% loss on loopback
sudo tc qdisc add dev lo root netem loss 5%

# Run a transfer
iperf3 -s -p 5201 &
iperf3 -c 127.0.0.1 -p 5201 -t 30

# See retransmit counters
nstat | grep -i Retrans
ss -tin | grep retrans

# Restore
sudo tc qdisc del dev lo root
```

Trace recovery entry:

```bash
sudo bpftrace -e '
fentry:tcp_enter_recovery { @rec = count(); }
fentry:tcp_enter_loss { @loss = count(); }
fentry:tcp_retransmit_skb { @retx = count(); }
interval:s:10 { print(@rec); print(@loss); print(@retx); clear(@rec); clear(@loss); clear(@retx); }'
```

Expect: many retransmits, several Recovery entries (each loss event), occasional Loss entries (when RTOs fire).

### Per-connection retransmit info

```bash
ss -tin | grep -A 1 ESTAB
# look for: cwnd:N retrans:RX/TX
```

Where `RX` is total retransmits (cumulative) and `TX` is unacked retransmits in flight.

## What to read in the kernel

- **`net/ipv4/tcp_input.c:3328`** — `tcp_fastretrans_alert`. The state-machine entry called per ACK. Read top to bottom. Notice how it uses `prior_snd_una` (the ACK before this one) to detect new acknowledgments and dispatch into the right action.

- **`net/ipv4/tcp_input.c:3177`** — `tcp_enter_recovery`. The "we're in trouble" entry point. ~25 lines. Walk through: cwnd reduction, calling `set_state` on the CC algorithm, setting up PRR.

- **`net/ipv4/tcp_input.c:2554`** — `tcp_enter_loss`. The RTO-driven recovery. Much more punitive than `tcp_enter_recovery` — used only for RTO. Notice cwnd resets to `tcp_packets_in_flight(tp) + 1` (≈1 MSS).

- **`net/ipv4/tcp_input.c:3602`** — `tcp_clean_rtx_queue`. The function that walks `sk_write_queue` and removes ACKed segments. The complexity here is computing RTT samples for each ACKed segment (many SACK edge cases).

- **`net/ipv4/tcp_recovery.c`** — RACK implementation. Short (~160 lines). Read all of it. The key function is `tcp_rack_detect_loss` — given the latest ACK time and SACK info, decide which earlier segments are now considered lost.

- **`net/ipv4/tcp_timer.c:535`** — `tcp_retransmit_timer`. The RTO-fires entry. Read top to bottom (~150 lines). Notice the "user timeout" handling (gives up after `TCP_USER_TIMEOUT` even if RTO would keep retrying), and the explicit congestion exit if too many retries.

- **`net/ipv4/tcp_output.c:3693`** — `tcp_retransmit_skb`. How a single skb gets resent. Notice the GSO/TSO splitting if the skb represents multiple segments — only the lost portion is retransmitted.

- **`net/ipv4/tcp_output.c:3723`** — `tcp_xmit_retransmit_queue`. Drives retransmits during recovery: walks the queue, picks segments marked LOST, sends them at the PRR-paced rate.

- **`include/linux/tcp.h:197`** — `struct tcp_sock`. The retransmit-related fields are clustered: `packets_out`, `lost_out`, `sacked_out`, `retrans_out`, `prr_out`, `prr_delivered`, `rack`. Skim them once to know what each tracks.

- **RFCs to skim if curious:** 5681 (Reno + congestion avoidance), 6675 (SACK-based recovery), 6937 (PRR), 8985 (RACK).

## Bullet Points

- TCP keeps every unacked segment in `sk_write_queue` until ACKed.
- **Three loss-detection mechanisms**: RTO (slow, backstop), 3 dupacks (Reno), RACK (modern default).
- **`tcp_recovery=1`** enables RACK; the default since 4.4.
- **SACK** lets ACKs include non-contiguous ranges; on by default.
- **Recovery state**: cwnd halved (via PRR), retransmit lost segments at ACK-paced rate, exit when `snd_una` reaches the recovery point.
- **`tcp_retransmit_timer`** at `net/ipv4/tcp_timer.c:535` is the RTO entry.
- **`tcp_fastretrans_alert`** at `net/ipv4/tcp_input.c:3328` is the per-ACK recovery state machine.
- Inspect: `ss -tin` (cwnd, retrans), `nstat` (TCPRetrans, TCPSackRecovery, etc.).
- **Use `tc netem loss N%`** to test loss recovery in a controlled environment.

## Check question

Why does losing 1% of packets on a 100 ms RTT path cause throughput to drop *much* more than 1%?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Because each loss causes the CC algorithm to halve cwnd. CUBIC needs many RTTs of growth to recover. The Mathis formula approximates achievable throughput:

> throughput ≈ MSS / (RTT × √loss_rate)

Plug in: MSS=1448, RTT=0.1s, loss=0.01 → ≈ 14.48 Mbps. Even on a 10 Gbps path, you cap at ~14 Mbps. CUBIC is loss-based — it interprets loss as congestion and backs off by ~50%. With one halving per ~100 packets, cwnd never reaches what the path could actually support.

**BBR partially fixes this** because it doesn't use loss as the signal — it uses bandwidth and RTT directly. On the same lossy path, BBR can sustain throughput much closer to the path's actual capacity.

</details>

---

## Tomorrow

Day 18: socket options. The pile of per-socket tuning knobs and what each one actually does.
