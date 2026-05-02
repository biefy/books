# Day 23 — Modify BPF DCTCP and instrument it

> **Today's mission:** take yesterday's BPF DCTCP, add per-ACK telemetry to a ringbuf, run a real `iperf3` and watch TCP's internal state in real time. Total time: ~75 minutes.

## Why this exercise

Yesterday loaded a stranger's BPF DCTCP. Today changes one and observes the effect. This is the most important struct_ops skill: **small, surgical modifications to working code**.

Goal: emit one event per ACK to a ringbuf, with the connection's current `cwnd`, `in_flight`, and `srtt`. Watch a transfer; correlate transfer events to internal TCP state.

This pattern — instrument an existing struct_ops module without changing its policy — is invaluable. You can debug a misbehaving CC algorithm, study how an unfamiliar one works, or feed real-time TCP state into your own monitoring system.

## What's in `bpf_dctcp.c` already

Open `tools/testing/selftests/bpf/progs/bpf_dctcp.c`. Take a minute to skim. Key callbacks DCTCP overrides:

- **`init`** — set up per-socket DCTCP state (`alpha`, EWMA params).
- **`ssthresh`** — slow-start threshold computation (uses ECN ratio).
- **`pkts_acked`** — called when ACKs come in; updates ECN counters.
- **`cwnd_event`** — handle congestion-window events.
- **`in_ack_event`** — fires per ACK; *this is where we'll add our telemetry*.

The full vtable is in `SEC(".struct_ops") struct tcp_congestion_ops dctcp = { ... }` near the bottom.

The `in_ack_event` callback is ideal for our purpose: it fires per incoming ACK, which is roughly per outgoing-data segment ACKed. The argument is `struct sock *sk` plus a flags bitmap.

## The instrumentation

### Step 1: declare a ringbuf

Add near the top of `bpf_dctcp.c`:

```c
struct tcp_event {
    __u64 ts_ns;
    __u32 srtt_us;
    __u32 cwnd;
    __u32 in_flight;
    __u64 sk_cookie;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

### Step 2: add telemetry without replacing the policy

Do **not** replace `.in_ack_event` with a logging-only callback. DCTCP's alpha update depends on that callback. Instead, insert the telemetry at the top of the existing `dctcp_in_ack_event` function and leave the original logic below it unchanged:

```c
SEC("struct_ops/dctcp_in_ack_event")
void BPF_PROG(dctcp_in_ack_event, struct sock *sk, __u32 flags)
{
    struct tcp_sock *tp = (void *)sk;

    struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->ts_ns     = bpf_ktime_get_ns();
        e->srtt_us   = tp->srtt_us >> 3;          /* srtt is stored in eighths of a us */
        e->cwnd      = tp->snd_cwnd;
        e->in_flight = tp->packets_out - (tp->sacked_out + tp->lost_out);
        e->sk_cookie = bpf_get_socket_cookie(sk);
        bpf_ringbuf_submit(e, 0);
    }

    /* Keep the original DCTCP alpha-update logic here. */
}
```

If you prefer a wrapper, rename the original body to a helper and call it from the wrapper after emitting the event. Either way, the original alpha update must still run.

### Step 3: keep the callback slot, change only the algorithm name

Find the `SEC(".struct_ops") struct tcp_congestion_ops dctcp = { ... }` block. Keep the `.in_ack_event` slot pointed at the DCTCP implementation and change the name to avoid colliding with the original:

```c
SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    /* existing entries... */
    .in_ack_event = (void *)dctcp_in_ack_event,
    .name = "bpf_dctcp_logged",
};
```

## Userspace consumer

Standard ringbuf consumer + skeleton load + struct_ops attach. Print per event:

```c
printf("[sk=%llu t=%lluns] cwnd=%u in_flight=%u srtt=%uus\n",
       e->sk_cookie, e->ts_ns, e->cwnd, e->in_flight, e->srtt_us);
```

## Run

```bash
make
sudo ./logged_dctcp &

# Server
iperf3 -s &

# Client (in another terminal)
iperf3 -c 127.0.0.1 -C bpf_dctcp_logged
```

Output:

```
[sk=11234 t=12345...] cwnd=10  in_flight=0   srtt=0us
[sk=11234 t=12346...] cwnd=11  in_flight=10  srtt=152us
[sk=11234 t=12348...] cwnd=22  in_flight=21  srtt=148us
...
```

You're now seeing TCP's internal CC decisions in real-time, per ACK, in a flow that runs through your custom BPF-defined algorithm. Cwnd grows, RTT changes are visible, in_flight tracks how full the pipe is.

## What to do with this data

A few things you couldn't do before:

- **Per-flow performance graphs:** export to a TSDB, plot cwnd over time per `sk_cookie`.
- **Anomaly detection:** alert when `in_flight` collapses (loss event), correlated with RTT spikes.
- **Verify CC behavior:** see whether your tuning is actually changing TCP's reaction.
- **Capacity planning:** understand the cwnd distribution of your real workload, not synthetic benchmarks.

## What to break

### Wrong field semantics

```c
e->srtt_us = tp->srtt_us;  /* without >> 3 */
```

`tp->srtt_us` is stored in eighths of a microsecond (gives sub-µs precision without floats). Reading it directly produces values 8× too large. Symptom: latency reports look like RTT is hundreds of ms when it's actually tens. Lesson: **kernel field semantics matter** — read the field's docstring (or `include/linux/tcp.h`) before assuming.

### Forget to release

```c
struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e) return;
e->ts_ns = ...;
/* forgot bpf_ringbuf_submit */
return;
```

Verifier rejects: `unreleased reference id=N`. The ringbuf-reserve return is a refcounted resource, exactly like a kfunc acquire. Same rules: every path must submit or discard.

### Run with high concurrency

Run `100` parallel iperf3 streams. Watch ringbuf drops via the percpu drop counter (Day 13 pattern). At ~100K events/sec, you'll start dropping. Fix:

- Filter (only emit when cwnd changes by > N).
- Size up the ringbuf.
- Aggregate per-sk in a map; emit summary periodically.

### Add another callback

Override `pkts_acked` to capture ECN counters per ACK:

```c
SEC("struct_ops/dctcp_pkts_acked_logged")
void BPF_PROG(my_pkts_acked, struct sock *sk, const struct ack_sample *sample)
{
    /* emit ECN data, packet count, etc. */
}
```

Add `.pkts_acked = (void *)my_pkts_acked` to the vtable. Now you have two BPF programs in the same struct_ops module, both fed real-time data.

## What to read in the kernel

- **`net/ipv4/tcp_input.c`** — search `in_ack_event`. The C call site that invokes your BPF callback per incoming ACK. Trace the call path from `tcp_v4_rcv` down to `in_ack_event` invocation. Notice how the kernel calls *every* registered callback: yours runs alongside any other CC's `in_ack_event`.

- **`include/uapi/linux/tcp.h`** — `struct tcp_info`. The fields available via `bpf_get_socket_cookie` and similar are also in this struct (used by `getsockopt(TCP_INFO)`). When you wonder "what other state can I expose?" — this is the catalog.

- **`include/linux/tcp.h`** — the kernel-internal `struct tcp_sock`. ~150 fields. Read once. The relationship: `struct tcp_info` (UAPI) is a curated subset of `struct tcp_sock` (internal); BPF programs can read either by casting `struct sock *sk → struct tcp_sock * = (void *)sk`.

- **`tools/testing/selftests/bpf/progs/bpf_cubic.c`** — another struct_ops example, full Cubic implementation. Compare against `bpf_dctcp.c` for stylistic differences.

- **`net/ipv4/tcp_cong.c`** — CC framework. `tcp_register_congestion_control`. How your `bpf_dctcp_logged` ends up callable. Day 16 (network book) covered this in detail.

## Bullet Points

- struct_ops modules are ordinary BPF programs you can edit, instrument, and test.
- **Add a ringbuf to one callback** to get per-event telemetry without modifying the kernel.
- The verifier still applies; standard ringbuf reserve/submit and reference rules.
- The pattern works for **any struct_ops vtable**: TCP CC, sched_ext, future ones.
- For high-rate observability, drop counters and rate-limiting filters in BPF are essential.

## Check question

You add `bpf_ringbuf_reserve` to a struct_ops callback that fires per ACK at line rate. What's the worst-case impact on TCP performance?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Each callback adds ~50–100 ns. At 1 Mpps (a high-rate flow on a fast link), that's 5–10% extra CPU just for the BPF reserve+submit cost. If the ringbuf fills (consumer can't keep up), `bpf_ringbuf_reserve` returns NULL and your code skips the emit entirely; **TCP itself is unaffected** — the original CC logic still runs.

The bigger risk is if your BPF logic *blocks* somehow. It can't — non-sleepable struct_ops can't sleep, take regular mutexes, or do anything that schedules. It also can't *modify TCP state* in a way the algorithm wasn't expecting (you can — be careful). Pure observation (read fields, emit to ringbuf) is safe up to whatever overhead you can tolerate; **mutation needs explicit care** because you're now changing what the CC algorithm does, not just watching it.

For 99% of telemetry use cases, the worst case is: (a) some events get dropped under load (handle via drop counter); (b) ~5% extra CPU on hot connections. Both manageable.

</details>

---

## Tomorrow

Day 24: BTF spelunking. Find a kfunc on your kernel that you've never used, read its signature, write a program that calls it.
