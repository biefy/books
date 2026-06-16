# Day 23 — Modify BPF DCTCP and instrument it

> **Today's mission:** take yesterday's BPF DCTCP, add per-ACK telemetry to a ringbuf, run a real `iperf3` and watch TCP's internal state in real time. Total time: ~75 minutes.

## Why this exercise

Yesterday loaded a stranger's BPF DCTCP. Today changes one and observes the effect. This is the most important struct_ops skill: **small, surgical modifications to working code**.

Goal: emit one event per ACK to a ringbuf, with the connection's current `cwnd`, `in_flight`, and `srtt`. Watch a transfer; correlate transfer events to internal TCP state.

This pattern — instrument an existing struct_ops module without changing its policy — is invaluable. You can debug a misbehaving CC algorithm, study how an unfamiliar one works, or feed real-time TCP state into your own monitoring system.

## What's in `bpf_dctcp.c` already

Open `tools/testing/selftests/bpf/progs/bpf_dctcp.c`. Take a minute to skim. Key callbacks DCTCP overrides:

- **`init`** (`bpf_dctcp_init`) — set up per-socket DCTCP state (`alpha`, EWMA params).
- **`ssthresh`** (`bpf_dctcp_ssthresh`) — slow-start threshold computation (uses ECN ratio).
- **`in_ack_event`** (`bpf_dctcp_update_alpha`) — fires per ACK; updates the ECN/alpha EWMA. *This is where we'll add our telemetry.*
- **`cwnd_event`** (`bpf_dctcp_cwnd_event`) — handle congestion-window events.
- **`cong_avoid` / `undo_cwnd` / `set_state`** — Reno-style cwnd growth, loss recovery, and CA-state transitions.

(Note: DCTCP does **not** implement `pkts_acked`. Its per-ACK accounting lives entirely in `in_ack_event` / `bpf_dctcp_update_alpha`.)

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

Do **not** replace `.in_ack_event` with a logging-only callback. DCTCP's alpha update depends on that callback. Instead, insert the telemetry at the top of the existing `bpf_dctcp_update_alpha` function (the BPF program bound to the `.in_ack_event` slot) and leave the original logic below it unchanged:

```c
SEC("struct_ops/bpf_dctcp_update_alpha")
void BPF_PROG(bpf_dctcp_update_alpha, struct sock *sk, __u32 flags)
{
    struct tcp_sock *tp = (void *)sk;

    struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->ts_ns     = bpf_ktime_get_ns();
        e->srtt_us   = tp->srtt_us >> 3;          /* srtt is stored in eighths of a us */
        e->cwnd      = tp->snd_cwnd;              /* see note: kernel C uses tcp_snd_cwnd(tp) */
        e->in_flight = tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out;
        e->sk_cookie = (__u64)(unsigned long)sk;  /* per-flow id; see note below */
        bpf_ringbuf_submit(e, 0);
    }

    /* Keep the original DCTCP alpha-update logic here. */
}
```

If you prefer a wrapper, rename the original body to a helper and call it from the wrapper after emitting the event. Either way, the original alpha update must still run.

> **Why not `bpf_get_socket_cookie(sk)`?** It is **not** available to `tcp_congestion_ops` programs. The helper set for this program type is whatever `bpf_tcp_ca_get_func_proto()` (`net/ipv4/bpf_tcp_ca.c`) exposes — `tcp_send_ack`, `bpf_sk_storage_get`/`_delete`, `bpf_{set,get}sockopt`, `ktime_get_coarse_ns` — plus the base helpers; `get_socket_cookie` is only offered to skb/sock_ops/sock_addr program types. The verifier rejects it at load (`program of this type cannot use helper bpf_get_socket_cookie`), so the program never attaches. We instead cast the trusted `struct sock *sk` to a scalar: under root/CAP_PERFMON (`allow_ptr_leaks` is on, the normal case for loading struct_ops) the trusted `PTR_TO_BTF_ID` casts cleanly, giving a stable per-flow id for the life of the connection. `sk_cookie` then prints the kernel socket address rather than an SO_COOKIE id. If you need a true SO_COOKIE-style identity, stash one in a `BPF_MAP_TYPE_SK_STORAGE` via `bpf_sk_storage_get(&map, sk, &init, BPF_SK_STORAGE_GET_F_CREATE)` — that helper *is* in the tcp_ca set.

### Step 3: keep the callback slot, change only the algorithm name

Find the `SEC(".struct_ops") struct tcp_congestion_ops dctcp = { ... }` block. Keep the `.in_ack_event` slot pointed at the DCTCP implementation and change the name to avoid colliding with the original:

```c
SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    /* existing entries... */
    .in_ack_event = (void *)bpf_dctcp_update_alpha,
    .name = "bpf_dctcp_log",
};
```

> **Name length matters.** Congestion-control names are capped at `TCP_CA_NAME_MAX - 1` = **15 usable characters**. The struct field is `char name[16]`, and the `setsockopt(TCP_CONGESTION)` path copies at most 15 bytes plus a NUL. A 16-character name like `bpf_dctcp_logged` registers fine but can never be *selected* — the client's request is silently truncated to `bpf_dctcp_logge` (15 chars), the lookup fails, and you get `ENOENT` ("No such file or directory"). Keep the name short: `bpf_dctcp_log` is 13 characters.

> **Two field-access notes.** (1) We read `tp->snd_cwnd` directly, which works in BPF (the real `bpf_dctcp.c` does the same). Kernel C convention, however, is the `tcp_snd_cwnd(tp)` accessor (`include/net/tcp.h`) — don't be surprised when the C source uses the helper instead of the bare field. (2) The full kernel formula is `tcp_packets_in_flight(tp) = packets_out - (sacked_out + lost_out) + retrans_out`; we include `retrans_out` above. Omitting it (as a simplification) undercounts in-flight bytes during loss recovery.

## Userspace consumer

`logged_dctcp` is a **new, out-of-tree libbpf program** — not something `make` inside `selftests/bpf` produces (that builds `test_progs`). Copy your edited `bpf_dctcp.c` into your own project, generate the skeleton with `bpftool gen skeleton bpf_dctcp.bpf.o > bpf_dctcp.skel.h`, and build the loader against `libbpf` (reuse the Day 22 struct_ops loader and the Day 13 ringbuf consumer — this is just those two stitched together).

The load is a struct_ops attach (distinct from a normal program attach), then a standard ringbuf poll loop:

```c
struct bpf_dctcp *skel = bpf_dctcp__open_and_load();
/* struct_ops-specific attach — registers the CC in the kernel */
struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.dctcp);

struct ring_buffer *rb =
    ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
while (!stop)
    ring_buffer__poll(rb, 100 /* ms */);
```

In `handle_event`, print per event:

```c
printf("[sk=%llu t=%lluns] cwnd=%u in_flight=%u srtt=%uus\n",
       e->sk_cookie, e->ts_ns, e->cwnd, e->in_flight, e->srtt_us);
```

Build it with your project's libbpf `Makefile` so `make` produces the `logged_dctcp` binary the Run section uses.

## Run

```bash
sudo ./logged_dctcp &              # loads + attaches the struct_ops CC (job %1)

# Verify it registered
cat /proc/sys/net/ipv4/tcp_available_congestion_control   # should now list bpf_dctcp_log

# Selecting a non-default CC needs CAP_NET_ADMIN or membership in the allowed list.
# A freshly registered struct_ops CC is added to *available* but NOT *allowed*, so an
# unprivileged client gets EPERM ("Operation not permitted"). Either run the client with
# sudo, or add the algorithm to the allowed list (keep cubic so other sockets still work):
sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="cubic bpf_dctcp_log"

# Server
iperf3 -s &                        # job %2

# Client (in another terminal)
iperf3 -c 127.0.0.1 -C bpf_dctcp_log
```

Output (the `sk=` value is now the kernel socket address — a stable per-flow id for the life of the connection, not an SO_COOKIE id):

```
[sk=18446612345678900 t=12345...] cwnd=10 in_flight=0  srtt=24us
[sk=18446612345678900 t=12346...] cwnd=11 in_flight=10 srtt=31us
[sk=18446612345678900 t=12348...] cwnd=14 in_flight=12 srtt=29us
...
```

You're now seeing TCP's internal CC decisions in real time, per ACK, in a flow that runs through your custom BPF-defined algorithm. `cwnd` grows, `srtt` updates per ACK, and `in_flight` tracks how full the pipe is.

> **Loopback caveat.** Over `127.0.0.1` there is no packet loss and the RTT is microseconds, so you only ever see `cwnd` grow monotonically — you will **not** see the loss-driven `cwnd` collapse and RTT spikes that the anomaly-detection use case below depends on. To make those dynamics observable, run the transfer across a `netem`-delayed `veth` pair: create a `veth` pair in a separate netns and apply `sudo tc qdisc add dev <veth> root netem delay 20ms loss 1%`, then `iperf3 -c <veth-peer-ip> -C bpf_dctcp_log`.

### Cleanup

```bash
kill %2 2>/dev/null              # iperf3 -s
sudo pkill -f logged_dctcp       # exiting the loader detaches the struct_ops link
                                 # and unregisters bpf_dctcp_log from the CC framework
# restore the default allowed list (the sysctl change is not persistent across reboot anyway)
sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="reno cubic"
```

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

Verifier rejects: `Unreleased reference id=N alloc_insn=M`. The ringbuf-reserve return is a refcounted resource, exactly like a kfunc acquire. Same rules: every path must submit or discard.

### Run with high concurrency

Run `100` parallel iperf3 streams. Watch ringbuf drops via the percpu drop counter (Day 13 pattern). At ~100K events/sec, you'll start dropping. Fix:

- Filter (only emit when cwnd changes by > N).
- Size up the ringbuf.
- Aggregate per-sk in a map; emit summary periodically.

### Add another callback

DCTCP itself doesn't use `pkts_acked`, but `tcp_congestion_ops` has the slot — so you can add it as a *new* callback in your module to capture per-ACK packet/ECN accounting:

```c
SEC("struct_ops/dctcp_pkts_acked_logged")
void BPF_PROG(my_pkts_acked, struct sock *sk, const struct ack_sample *sample)
{
    /* emit packet count, RTT sample, etc. */
}
```

Add `.pkts_acked = (void *)my_pkts_acked` to the vtable. Now you have two BPF programs in the same struct_ops module, both fed real-time data. (This is a *new* slot you're populating, not a DCTCP callback you're overriding — the upstream DCTCP leaves `pkts_acked` NULL.)

## What to read in the kernel

- **`net/ipv4/tcp_input.c`** — search `in_ack_event`. The C call site that invokes your BPF callback per incoming ACK. Trace the call path from `tcp_v4_rcv` down to the `in_ack_event` invocation. Note that the kernel calls *only the socket's selected* CC's callback — a single indirect call through `icsk->icsk_ca_ops->in_ack_event` — so your callback runs only for connections actually using your algorithm, not for every registered CC.

- **`include/uapi/linux/tcp.h`** — `struct tcp_info`. The same per-connection fields you read off the BTF `struct tcp_sock` pointer are also surfaced to userspace here via `getsockopt(TCP_INFO)`. When you wonder "what other state can I expose?" — this is the catalog. (`bpf_get_socket_cookie` is unrelated: it returns a `u64` SO_COOKIE id, not a `tcp_info`, and as noted in the instrumentation step it isn't even available to `tcp_congestion_ops` programs.)

- **`include/linux/tcp.h`** — the kernel-internal `struct tcp_sock`. ~170 fields. Read once. The relationship: `struct tcp_info` (UAPI) is a curated subset of `struct tcp_sock` (internal); BPF programs can read either by casting `struct sock *sk → struct tcp_sock * = (void *)sk`.

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
