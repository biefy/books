# Day 22 — struct_ops: BPF replaces kernel vtables

> **Today's mission:** load a BPF-implemented TCP congestion control algorithm and use it on a real connection. Understand how struct_ops turns BPF from "tracing hooks" into "kernel extension language." Total time: ~75 minutes.

## What changed in BPF around 2022

For most of BPF's history, BPF programs were **hooks** — fire on event, observe or modify, return. Useful but reactive. Tracing programs read state. Networking programs decide pass/drop. None of them *implemented kernel functionality* — the kernel did its work; BPF watched.

Around 2022, the pattern flipped. BPF programs can now **provide implementations** for kernel function-pointer tables — the same vtables the kernel itself uses internally for pluggable algorithms.

![struct_ops](diagrams/day22_struct_ops.png)

The classic example is **TCP congestion control**. The kernel has a vtable:

```c
/* include/net/tcp.h:1316 — fields reordered/trimmed for readability;
 * the real layout puts fast-path callbacks first and init/release LAST */
struct tcp_congestion_ops {
    u32   (*ssthresh)(struct sock *sk);
    void  (*cong_avoid)(struct sock *sk, u32 ack, u32 acked);
    void  (*set_state)(struct sock *sk, u8 new_state);
    void  (*cwnd_event)(struct sock *sk, enum tcp_ca_event ev);
    void  (*in_ack_event)(struct sock *sk, u32 flags);
    void  (*pkts_acked)(struct sock *sk, const struct ack_sample *sample);
    u32   (*undo_cwnd)(struct sock *sk);
    /* ... ~10 callbacks ... */
    char name[TCP_CA_NAME_MAX];
    /* ... */
    void  (*init)(struct sock *sk);     /* private-data setup, called last */
    void  (*release)(struct sock *sk);  /* private-data teardown */
};
```

CUBIC, BBR, Reno, DCTCP — all implementations of this vtable in C, registered via `tcp_register_congestion_control()`. Now you can write one in **BPF**.

## How struct_ops works

A struct_ops module has three parts in BPF source:

1. **Each callback is a separate BPF program** with `SEC("struct_ops/<callback_name>")`.
2. **The vtable instance** is declared in `SEC(".struct_ops")` (or `SEC(".struct_ops.link")` for the modern link-based variant) — a struct of the right type with function pointers pointing at the BPF programs.
3. **The kernel reads the BTF** at load time, validates each callback's signature against the vtable's expected types, and calls `register_${subsystem}` (e.g., `tcp_register_congestion_control`) automatically.

Example skeleton:

```c
SEC("struct_ops/dctcp_init")
void BPF_PROG(my_init, struct sock *sk) { /* ... */ }

SEC("struct_ops/dctcp_ssthresh")
u32 BPF_PROG(my_ssthresh, struct sock *sk) { return /* ... */; }

/* ... other callbacks ... */

SEC(".struct_ops.link")
struct tcp_congestion_ops my_dctcp = {
    .init       = (void *)my_init,
    .ssthresh   = (void *)my_ssthresh,
    .cong_avoid = (void *)tcp_reno_cong_avoid,  /* explicit Reno C callback */
    .name       = "my_dctcp",
};
```

Notice the `.cong_avoid = tcp_reno_cong_avoid` line — **you can mix BPF callbacks with the kernel's existing C callbacks** by assigning them explicitly. Required and optional slots are subsystem-specific. For TCP congestion control, the kernel requires `ssthresh`, `undo_cwnd`, and either `cong_avoid` or `cong_control`; other callbacks may be left NULL only if the TCP CC framework defines that as optional.

> **A note on the `SEC` suffix.** We write `SEC("struct_ops/dctcp_init")` with a named suffix, but the suffix is **optional** — the kernel's own `bpf_dctcp.c` selftest uses a bare `SEC("struct_ops")` on every callback and lets the assignment in the `.struct_ops` vtable bind each program to its slot. Both work; libbpf resolves the binding from the vtable struct, not the section name. Don't be confused if the source you're comparing against omits the suffix.

## The lifecycle

![struct_ops lifecycle](diagrams/day22_struct_ops_lifecycle.png)

When you load a struct_ops object via libbpf:

1. **Each callback** is loaded as a separate BPF program (separate prog FD).
2. **A struct_ops map** is created — keyed by function-pointer slot, valued by the BPF program FDs that implement each.
3. **The kernel calls the registration function** of the relevant subsystem. For TCP CC: `tcp_register_congestion_control(my_dctcp)`. The new algorithm name appears in `/proc/sys/net/ipv4/tcp_available_congestion_control`.
4. **Userspace selects it** via `setsockopt(TCP_CONGESTION, "my_dctcp")` per socket, or `sysctl tcp_congestion_control=my_dctcp` system-wide.

When the BPF object is unloaded, the registration is reversed and the algorithm goes away.

## What's verified

The verifier does extensive checking on struct_ops modules:

- **Each callback's signature must match** the kernel's vtable definition. Mismatches are rejected at load time.
- **Each callback's BPF program follows normal verifier rules** (no unbounded loops, all pointers checked, etc.).
- **Helper allowance** is per-callback-context. A `struct_ops/dctcp_init` callback runs in TCP slow-path; certain helpers are allowed; XDP-only helpers aren't.
- **Sleepable / non-sleepable** is per-callback. TCP CC callbacks aren't sleepable (run in softirq); some struct_ops vtables (sched_ext) have sleepable subsets.

The **type matching** uses BTF: the kernel knows `struct tcp_congestion_ops` from its own BTF, the BPF object's BTF describes its callbacks' signatures, and the verifier (in `bpf_struct_ops.c`) walks the field-by-field comparison.

## Why this is huge

It's how **sched_ext** works. Sched_ext exposes `struct sched_ext_ops` — `enqueue`, `dispatch`, `init`, `select_cpu`, etc. A sched_ext BPF scheduler is just a struct_ops module against that vtable. Same plumbing as TCP CC, different vtable.

It's how **Cilium** plans to do certain bits of advanced policy (still evolving). It's how you'd implement a custom HMAC or compression algorithm. Anywhere the kernel has a function-pointer table, struct_ops can let BPF supply implementations.

The general structure of the kernel was already vtable-heavy (file_operations, net_device_ops, sched_class, ...). struct_ops makes most of those *potentially* BPF-pluggable, given suitable kernel-side enabling and verifier rules.

## The lab — load BPF DCTCP

The kernel ships `tools/testing/selftests/bpf/progs/bpf_dctcp.c` — a BPF reimplementation of DCTCP that you can load directly.

### Build and load

```bash
cd ~/code/linux/tools/testing/selftests/bpf
make -j$(nproc)
sudo ./test_progs -t bpf_tcp_ca/dctcp
```

You should see `#NN/1 bpf_tcp_ca/dctcp:OK`. (The DCTCP case lives under the `bpf_tcp_ca` test now; `-t dctcp` on its own matches nothing.) The test loaded the BPF struct_ops, attached it, ran a connection through it, and verified the behavior — but then **tore it down on exit**. `test_progs` only proves the module loads, verifies, and works; it does *not* leave `bpf_dctcp` registered. Check and you'll see no `bpf_dctcp`:

```bash
cat /proc/sys/net/ipv4/tcp_available_congestion_control
# reno cubic dctcp bbr htcp
```

The `dctcp` you see there is the kernel's **native C** implementation (`net/ipv4/tcp_dctcp.c`), not our BPF one — don't mistake it for proof the lab worked.

To make the BPF version persist so the next steps have something to use, register the prebuilt object yourself. `register` installs the struct_ops map in the kernel, which is what keeps the algorithm alive after `bpftool` exits (this object's vtable uses the map-based `SEC(".struct_ops")`, so nothing is actually pinned into the directory — it stays empty):

```bash
# the selftest build above produced bpf_dctcp.bpf.o in this dir
sudo mkdir -p /sys/fs/bpf/dctcp
sudo bpftool struct_ops register bpf_dctcp.bpf.o /sys/fs/bpf/dctcp
```

`bpf_dctcp.bpf.o` carries **two** vtables (`dctcp` → name `bpf_dctcp`, and `dctcp_nouse` → name `bpf_dctcp_nouse`). On v7.1 only `bpf_dctcp` registers — `dctcp_nouse` is intentionally incomplete (it defines only `init`/`set_state`, not the required `ssthresh`/`undo_cwnd`/`cong_avoid`), so the kernel rejects it and `bpftool` prints a non-fatal error while still registering the valid one:

```bash
sudo bpftool struct_ops register bpf_dctcp.bpf.o /sys/fs/bpf/dctcp
# Error: can't register struct_ops dctcp_nouse: Invalid argument
# Registered tcp_congestion_ops dctcp id <id>

cat /proc/sys/net/ipv4/tcp_available_congestion_control
# reno cubic bbr bpf_dctcp
# (exact set/order varies with kernel config)
```

When you're done with the whole lab, unregister the algorithm. Because `bpf_dctcp.c` uses the map-based `SEC(".struct_ops")` (not `.struct_ops.link`), `register` does not pin a link into the directory — so removing the directory alone does **not** unregister it. Use `unregister`, then clean up the (empty) pin dir:

```bash
sudo bpftool struct_ops unregister name dctcp
sudo rm -rf /sys/fs/bpf/dctcp
```

### Use it on a connection

In a small C program:
```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
setsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, "bpf_dctcp", 9);
/* now this connection uses BPF-provided DCTCP */
```

Or via iperf3 against a local loopback server (install iperf3 if it's missing). This needs `bpf_dctcp` registered from the step above. An unprivileged `setsockopt(TCP_CONGESTION)` only accepts algorithms in `tcp_allowed_congestion_control`, which by default is a subset of the *available* list — so add `bpf_dctcp` to it first (save the original to restore later):

```bash
ORIG=$(cat /proc/sys/net/ipv4/tcp_allowed_congestion_control)
sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="$ORIG bpf_dctcp"
```

In terminal 1:

```bash
iperf3 -s
```

In terminal 2, run a transfer long enough to inspect mid-flight, asking for the BPF CC:

```bash
iperf3 -c 127.0.0.1 -C bpf_dctcp -t 30
```

In terminal 3, while the transfer runs, confirm the socket actually negotiated it. `ss -ti` prints the congestion-control name at the **start** of each connection's TCP-info line, so a substring match is enough:

```bash
ss -ti dst 127.0.0.1 | grep bpf_dctcp
#	 bpf_dctcp wscale:7,7 rto:204 rtt:0.05/0.02 ... cwnd:10 ...
```

A hit proves this connection is running BPF-provided DCTCP. (Don't use `grep -A1` — the CC name is inline on the info line, not the line after.) If `iperf3 -c` fails with `unable to set TCP_CONGESTION: Supplied congestion control algorithm not supported on this host`, the algorithm isn't registered or isn't in the *allowed* list — go back and run the `bpftool struct_ops register` and `sysctl ... tcp_allowed_congestion_control` steps. When you're done, restore the allowed list: `sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="$ORIG"`.

### Inspect

These need the struct_ops live, so run them only after the `bpftool struct_ops register` step above (after `test_progs` exits, nothing is loaded and `list` prints nothing while `dump` returns `[]`). Note the registered map is named after the C variable — **`dctcp`**, not `bpf_dctcp` (`bpf_dctcp` is the CC *algorithm* name; `dump name bpf_dctcp` matches no map and prints `[]`). Only the valid `dctcp` vtable registers; `dctcp_nouse` was rejected at register time:

```bash
sudo bpftool struct_ops list
# <id>: dctcp            tcp_congestion_ops

sudo bpftool struct_ops dump name dctcp
```

`dump` shows the vtable field-by-field, with each implemented function-pointer slot (`ssthresh`, `cong_avoid`, `init`, `undo_cwnd`, ...) resolved to the BPF prog id that serves it. That's the payoff: a kernel function-pointer table whose entries are BPF programs.

## What to read in the kernel

- **`kernel/bpf/bpf_struct_ops.c`** — the framework. ~1500 lines. Read top to bottom (it's surprisingly readable). Key entry points:
  - `bpf_struct_ops_map_alloc_check` — validates a struct_ops map type.
  - `bpf_struct_ops_map_alloc` — creates the map and binds BPF prog FDs to vtable slots.
  - `bpf_struct_ops_link_create` (line 1360) — for `SEC(".struct_ops.link")`, creates a bpf_link.
  - `bpf_struct_ops_test_run` — used by selftests to invoke a callback in a controlled environment.

- **`include/net/tcp.h:1316`** — `struct tcp_congestion_ops`. The vtable shape that BPF DCTCP implements. Read each callback's docstring; that's what your BPF program is expected to do.

- **`net/ipv4/tcp_dctcp.c`** — the **C** reference implementation of DCTCP. Compare against `tools/testing/selftests/bpf/progs/bpf_dctcp.c` field-by-field. The BPF version is a near-mechanical port; reading both side-by-side teaches the conversion idiom.

- **`tools/testing/selftests/bpf/progs/bpf_dctcp.c`** — the canonical BPF struct_ops example. Read end to end. Notice the `SEC("struct_ops/...")` per callback and the `SEC(".struct_ops")` containing the assembled vtable.

- **`kernel/sched/ext.c`** — sched_ext. ~10000 lines. The other big struct_ops user. Same pattern: a vtable (`struct sched_ext_ops`), per-callback BPF programs.

- **`Documentation/bpf/struct_ops.rst`** — official guide. Brief but pointed. (Not present in the v7.1 tree; check the in-tree `Documentation/bpf/` index for the current struct_ops write-up.)

## Bullet Points

- **struct_ops** lets BPF supply implementations for kernel function-pointer tables (vtables).
- Each callback is a separate BPF program (`SEC("struct_ops/X")`); the vtable struct lives in `SEC(".struct_ops")` or `.struct_ops.link`.
- Loading the map auto-registers the implementation with the kernel subsystem (TCP CC, sched_ext, etc.).
- The **verifier checks each callback's signature** against the kernel's BTF for the vtable struct — mismatches caught at load time.
- **Partial implementations are subsystem-specific**: TCP CC requires `ssthresh`, `undo_cwnd`, and either `cong_avoid` or `cong_control`; optional slots may remain NULL or be explicitly assigned to existing C callbacks.
- **Used by:** TCP CC, sched_ext, congestion-control modules, struct_ops growing per release.
- Inspect: `bpftool struct_ops list/dump`.

## Check question

If you load a BPF struct_ops module that defines only some callbacks (e.g., `init` and `ssthresh` but not `cong_avoid`), what happens to TCP connections using your CC?

<details>
<summary>Click to reveal answer</summary>

**Answer:** For TCP congestion control, that object is rejected unless the required callbacks are present. TCP CC requires `ssthresh`, `undo_cwnd`, and either `cong_avoid` or `cong_control`. If you want Reno behavior for `cong_avoid`, assign `.cong_avoid = (void *)tcp_reno_cong_avoid` explicitly.

Struct_ops does not have a universal "unset slots fall back" rule. Each subsystem decides which callbacks are required, which are optional, and what a NULL optional callback means. sched_ext, TCP CC, and future struct_ops users have different contracts.

</details>

---

## Tomorrow

Day 23: actually modify BPF DCTCP. Add ringbuf logging that emits per-ACK telemetry, and watch a real iperf3 run produce per-segment data.
