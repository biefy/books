# Linux Network Subsystem in 30 Days

A hands-on, experiment-driven path through the Linux kernel network stack. Read kernel source, instrument with ftrace/perf/bpftrace, change sysctls, observe behavior. Verified against kernel 7.1.

## What you'll know by Day 30

- How a packet flows from wire to userspace, and back, through every kernel layer.
- The data structures (`sk_buff`, `net_device`, `sock`, `dst_entry`, `fib_table`, `nf_conntrack`) by name and by line number.
- The TCP state machine and how Linux's CC algorithms (CUBIC, BBR, etc.) plug in.
- Netfilter, nftables, and conntrack — the modern packet-filter trio.
- Traffic control: qdiscs, classes, fq_codel.
- Modern features: kTLS, MPTCP, io_uring networking, drop_monitor.

## Phases

| Phase | Days | Focus |
|-------|------|-------|
| **1: Foundation** | 1–5 | sk_buff, RX/TX paths, NAPI, segmentation offloads, namespaces |
| **2: L2/L3** | 6–12 | Ethernet, ARP, IP routing, neighbours, IPv6, bridges, tunnels |
| **3: L4** | 13–19 | Sockets, UDP, TCP state machine, congestion control, retransmit, sockopts, epoll |
| **4: Subsystems** | 20–26 | Netfilter, nftables, conntrack, tc/qdiscs, SO_REUSEPORT, kTLS, MPTCP |
| **5: Modern + capstone** | 27–30 | XDP integration, io_uring net, recent features, capstone |

## How to use this

Each day is ~75–90 minutes. Most days follow this shape (loosely — not every section appears every day):

1. **Concepts introduced today** — what the new structures and paths are.
2. **What to read in the kernel** — specific files and functions in your kernel source checkout. Line numbers verified against kernel 7.1.
3. **Today's experiment** — what to trace/modify/observe to see the structures running.
4. **What to break** — sysctls or configurations that demonstrate the effect (sometimes folded into the experiment).
5. **Bullet Points**.
6. **Check question**.

The labs lean on ftrace, perf, and bpftrace as observability tools. You don't need to know how to *write* BPF programs to follow these labs — you'll use one-liners and existing tools.

## Tip: snapshot your sysctls

Some experiments adjust sysctls. Snapshot before:

```bash
sudo sysctl -a > sysctl.snapshot.$(date +%Y%m%d)
```

So you can `diff` back to a known-good state at the end of each day.

## Companion book

After this, the [Practical eBPF book](../ebpf/) builds on the kernel-internals foundation laid here. The plans are intentionally sequenced: kernel internals first, BPF as the application of that knowledge.
