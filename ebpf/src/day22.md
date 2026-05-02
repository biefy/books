# Day 22 — struct_ops: BPF replaces kernel vtables

> **Today's mission:** load a BPF-implemented TCP congestion control module and use it on a connection. See how struct_ops turns BPF from "hooks" into "kernel extension." Total time: ~75 minutes.

## What changed in BPF around 2022

Before struct_ops, BPF was a **hook** mechanism — fire on event, observe or modify, return. Useful but reactive.

After struct_ops, BPF can **provide implementations** for kernel function-pointer tables — the same vtables the kernel uses internally for pluggable algorithms.

![struct_ops](diagrams/day22_struct_ops.png)

The classic example: TCP congestion control. The kernel has `struct tcp_congestion_ops` with callbacks like `init`, `cong_avoid`, `pkts_acked`. CUBIC, BBR, Reno, Vegas — all C implementations of this vtable, registered via `tcp_register_congestion_control()`. Now you can write one in BPF.

## The full lifecycle

![struct_ops lifecycle](diagrams/day22_struct_ops_lifecycle.png)

When you load a struct_ops object:

1. Each callback is a separate BPF program, loaded individually.
2. The struct_ops *map* is created — keyed by function-pointer slot, valued by program FDs.
3. The kernel calls the registration function (`tcp_register_congestion_control` for CC) automatically.
4. The new algorithm name appears in `/proc/sys/net/ipv4/tcp_available_congestion_control`.
5. Userspace selects it via `setsockopt(..., TCP_CONGESTION, ...)`.

Detach is the reverse — closing the map FD unregisters the algorithm.

## Why this is huge

It's how **sched_ext** (Day 25) works. Sched_ext exposes `struct sched_ext_ops` — `enqueue`, `dispatch`, `init`, etc. A sched_ext BPF scheduler is just a struct_ops module against that interface. Same plumbing as TCP CC, different vtable.

It's how Cilium plans to do certain bits of network policy. It's how you'd implement a custom IPSec algorithm. Anywhere the kernel has a function-pointer table, struct_ops can let BPF supply implementations.

> ### There are no Dumb Questions
>
> **Q: Is this safe? An arbitrary BPF program is now part of TCP?**
>
> A: It's verifier-checked like any BPF. The verifier knows each callback's signature from BTF and rejects programs that don't match. The callbacks run in the same contexts as the C versions (mostly softirq for TCP CC), with the same helper restrictions.
>
> **Q: How does the kernel know which struct to bind to?**
>
> A: BTF. The struct_ops map type has a typename associated; the kernel looks up the type in vmlinux BTF, finds the struct definition, validates that your BPF program's callback signatures match each field's function-pointer type.
>
> **Q: Can my BPF CC perform worse than the C version?**
>
> A: Yes — there's a per-callback BPF runtime cost (~ns each call). For CC, callbacks fire per ACK; the cost is real but absorbed by the network stack's overall budget. sched_ext is more sensitive because callbacks fire on every scheduling decision.

## The lab

The kernel ships test programs. The simplest is `tools/testing/selftests/bpf/progs/bpf_dctcp.c` — a BPF reimplementation of DCTCP.

### Build the selftests

```bash
cd ~/code/linux/tools/testing/selftests/bpf
make -j$(nproc)
```

### Load the BPF DCTCP

```bash
sudo ./test_progs -t dctcp
```

You'll see:
```
#46/1 dctcp:OK
```

The test loads the BPF struct_ops, registers it as `bpf_dctcp`, and verifies that a connection using it behaves correctly.

After the test, the algorithm stays registered (until detach):
```bash
cat /proc/sys/net/ipv4/tcp_available_congestion_control
# cubic reno bbr bpf_dctcp
```

### Use it on your own connection

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
setsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, "bpf_dctcp", 9);
```

Or via `iperf3 -C bpf_dctcp`.

### Inspect it

```bash
sudo bpftool struct_ops list
sudo bpftool struct_ops dump name dctcp
```

Shows the callbacks bound and which BPF programs serve them.

---

## What to break, in order

### Break 1 — Read the source

Open `tools/testing/selftests/bpf/progs/bpf_dctcp.c`. Notice:

```c
SEC("struct_ops/dctcp_init")
void BPF_PROG(dctcp_init, struct sock *sk) { ... }

SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    .init = (void *)dctcp_init,
    .ssthresh = (void *)dctcp_ssthresh,
    .cong_avoid = (void *)tcp_reno_cong_avoid,
    .name = "bpf_dctcp",
    /* ... */
};
```

Each callback is a `SEC("struct_ops/X")` BPF program. The struct itself is in `SEC(".struct_ops")` — that's how libbpf knows to create a struct_ops map with these bindings.

### Break 2 — Modify a callback

Change `dctcp_ssthresh` to print something:

```c
SEC("struct_ops/dctcp_ssthresh")
__u32 BPF_PROG(dctcp_ssthresh, struct sock *sk)
{
    bpf_printk("ssthresh called for sk %p", sk);
    return /* original logic */;
}
```

Rebuild, reload, generate TCP traffic with `iperf3 -C bpf_dctcp`, watch `/sys/kernel/debug/tracing/trace_pipe`.

### Break 3 — Wrong callback signature

Change `dctcp_init` to take an extra arg:

```c
void BPF_PROG(dctcp_init, struct sock *sk, int extra)
```

Verifier rejects at load:

```
struct_ops register init: arg count mismatch
```

The struct_ops verifier checks each callback's signature against the kernel's BTF for `struct tcp_congestion_ops`.

### Break 4 — Add a new callback

Try `SEC("struct_ops/dctcp_cong_avoid")` with custom logic. As long as the signature matches, you're free to define any subset of the vtable's functions. Unset slots use the kernel's defaults.

---

## What to read in the kernel

- **`kernel/bpf/bpf_struct_ops.c`** — the registration framework. ~700 lines. Read top to bottom.
- **`net/ipv4/tcp_dctcp.c`** — the C reference implementation of DCTCP. Compare to the BPF version field-by-field.
- **`include/net/tcp.h`** — `struct tcp_congestion_ops` definition. The vtable shape.
- **`tools/testing/selftests/bpf/progs/bpf_dctcp.c`** — the canonical BPF struct_ops example.
- **`Documentation/bpf/struct_ops.rst`** — the official guide.

---

## Bullet Points

- **struct_ops** lets BPF supply implementations for kernel function-pointer tables (vtables).
- Each callback is a separate BPF program; the vtable struct lives in `SEC(".struct_ops")`.
- Loading the map auto-registers the implementation with the relevant kernel subsystem.
- Verifier checks each callback signature against the kernel's BTF for the vtable struct.
- Used by: TCP CC, sched_ext, congestion-control modules, and (eventually) more vtable-shaped subsystems.

---

## Check question

If you load a BPF struct_ops module that defines only some callbacks (e.g., `init` and `ssthresh` but not `cong_avoid`), what happens to connections using your CC?

.  
.  
.

**Answer:** Unset slots fall back to default implementations defined in the kernel. For TCP CC, `cong_avoid` defaults to `tcp_reno_cong_avoid`. So your CC behaves like Reno-with-custom-ssthresh. This is *partial implementation* — useful when you only want to override one or two policies and inherit the rest.

---

## Tomorrow

Day 23: actually modify the BPF DCTCP — add ringbuf logging, watch a real iperf3 run with your changes producing per-packet telemetry.
