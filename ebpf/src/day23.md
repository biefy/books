# Day 23 — Modify BPF DCTCP and instrument it

> **Today's mission:** take yesterday's BPF DCTCP, add a ringbuf that emits an event per ACK with `cwnd`, `in_flight`, and `srtt`. Run iperf3 and watch real-time TCP behavior. Total time: ~75 minutes.

## The exercise

Today is hands-on. Goal: prove that struct_ops modules are normal BPF programs by adding observability to one.

Start from `tools/testing/selftests/bpf/progs/bpf_dctcp.c`. We'll add:

1. A ringbuf for events.
2. A per-ACK callback that emits `(sk, cwnd, in_flight, srtt)`.
3. A small userspace consumer that prints what we see.

## What's already there

DCTCP overrides these callbacks in `bpf_dctcp.c`:

- `init` — set up per-socket state (DCTCP `alpha`, `dctcp_alpha_on_init`).
- `ssthresh` — slow-start threshold computation.
- `pkts_acked` — called when ACKs come in; updates ECN counters.
- `cwnd_event` — congestion window event.
- `in_ack_event` — fires per ACK; this is where we'll add our hook.

The full vtable is in `SEC(".struct_ops") struct tcp_congestion_ops dctcp = { ... }` at the bottom.

## The instrumentation

### Add a ringbuf

Append to `bpf_dctcp.c`:

```c
struct tcp_event {
    __u64 ts_ns;
    __u32 srtt_us;
    __u32 cwnd;
    __u32 in_flight;
    __u32 sk_cookie;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

### Hook `in_ack_event`

The kernel's `struct tcp_congestion_ops.in_ack_event` has signature:
```c
void in_ack_event(struct sock *sk, u32 flags);
```

Add:

```c
SEC("struct_ops/dctcp_in_ack_event")
void BPF_PROG(dctcp_in_ack_event_logged, struct sock *sk, __u32 flags)
{
    /* keep the original DCTCP logic by calling the inline function the
       reference uses; for brevity we omit and just log */

    struct tcp_sock *tp = (void *)sk;
    struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;
    e->ts_ns = bpf_ktime_get_ns();
    e->srtt_us = tp->srtt_us >> 3;       /* srtt in 8ths */
    e->cwnd = tp->snd_cwnd;
    e->in_flight = tp->packets_out - (tp->sacked_out + tp->lost_out);
    e->sk_cookie = bpf_get_socket_cookie(sk);
    bpf_ringbuf_submit(e, 0);
}
```

Replace the existing `.in_ack_event` slot in the vtable:

```c
SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    /* existing entries... */
    .in_ack_event = (void *)dctcp_in_ack_event_logged,
    .name = "bpf_dctcp_logged",   /* new name so we don't collide */
};
```

### Userspace consumer

Standard ringbuf consumer + skeleton load. Print:

```c
printf("[sk=%u t=%lluns] cwnd=%u in_flight=%u srtt=%uus\n",
       e->sk_cookie, e->ts_ns, e->cwnd, e->in_flight, e->srtt_us);
```

### Run

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
[sk=11234 t=...] cwnd=10  in_flight=0   srtt=0us
[sk=11234 t=...] cwnd=11  in_flight=10  srtt=152us
[sk=11234 t=...] cwnd=22  in_flight=21  srtt=148us
...
```

You're now seeing TCP CC decisions in real-time, per ACK, in a flow that runs through your custom BPF-defined algorithm.

---

## What to break, in order

### Break 1 — Wrong field type

```c
e->srtt_us = tp->srtt_us;  /* without >> 3 */
```

Reading `srtt_us` directly gives "8 × srtt" because that's how Linux stores it (saves a shift on update). Symptom: latency reports look 8× higher than reality. Lesson: **kernel field semantics matter**, not just types.

### Break 2 — Forget to release the ringbuf event

```c
struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e) return;
e->ts_ns = ...;
/* forget submit */
```

Verifier rejects: `unreleased reference id=N`. Same as kfunc acquire/release — ringbuf reserve is a refcounted resource until you submit or discard.

### Break 3 — Run with high concurrency

Run 100 parallel iperf3 streams. Watch ringbuf drops via the percpu drop counter (Day 13 pattern). At rates approaching 100K events/sec, you'll start dropping. Fix: filter (only emit when `cwnd` changes), or size up the ringbuf, or aggregate per-sk in a map.

### Break 4 — Add another callback

Override `pkts_acked` to capture ECN counters per ACK:

```c
SEC("struct_ops/dctcp_pkts_acked")
void BPF_PROG(my_pkts_acked, struct sock *sk, ...)
{
    /* emit counts */
}
```

Add `.pkts_acked = (void *)my_pkts_acked,` to the vtable. Now you have two BPF programs in the same struct_ops module.

---

## What to read in the kernel

- **`net/ipv4/tcp_input.c`** — search `in_ack_event`. The C call site that invokes your BPF callback per ACK.
- **`include/uapi/linux/tcp.h`** — `struct tcp_info` for the fields available via `bpf_get_socket_cookie` and friends.
- **`tools/testing/selftests/bpf/progs/bpf_cubic.c`** — another struct_ops example, full Cubic implementation.

---

## Bullet Points

- struct_ops modules are ordinary BPF programs you can edit, instrument, and test like any other.
- Add a ringbuf to one callback to get per-event telemetry without modifying the kernel.
- The verifier still applies; standard reserve/submit and reference rules.
- This pattern works for any struct_ops vtable: TCP CC, sched_ext, future ones.

---

## Check question

You add `bpf_ringbuf_reserve` to a struct_ops callback that fires per ACK at line rate. What's the worst-case impact on TCP performance?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Each callback adds ~50–100ns. At 1Mpps (high-rate flow), that's 5–10% extra CPU. If the ringbuf fills (consumer slow), `bpf_ringbuf_reserve` returns NULL and you skip the emit; TCP itself is unaffected. The bigger risk is if your BPF logic *blocks* somehow (it can't — non-sleepable struct_ops can't sleep) or modifies TCP state (it can — be careful). Pure observation is safe; mutation needs caution.

</details>

---

## Tomorrow

Day 24: BTF spelunking. Find a kfunc you've never used, read its signature, write a program that calls it. End of Phase 4.
