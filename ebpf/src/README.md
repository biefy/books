# Practical eBPF in 30 Days

A hands-on, experiment-driven path through modern eBPF on Linux 7.1. Written in Head First style with rendered diagrams.

## What you'll know by Day 30

- How BPF programs are compiled, verified, JITed, and attached.
- The verifier's type system and how to read its rejection messages fluently.
- CO-RE, BTF, and how libbpf relocates field offsets at load time.
- Tracing with fentry/fexit/tracepoints/uprobes; capturing stacks; building flame graphs.
- Networking BPF: XDP, tc/tcx, AF_XDP, cgroup_skb, sockops.
- Modern primitives: kfuncs, kptrs, struct_ops, BTF spelunking.
- The frontier: sched_ext (BPF-defined kernel schedulers).

## Phases

| Phase | Days | Focus |
|-------|------|-------|
| **1: Foundation** | 1–5 | libbpf workflow, CO-RE, verifier intuition |
| **2: Tracing** | 6–13 | fentry/fexit, tracepoints, stacks, uprobes, sleepable |
| **3: Networking** | 14–19 | XDP, tc, tcx, AF_XDP, cgroup/sockops |
| **4: Modern primitives** | 20–24 | kfuncs, kptrs, struct_ops, BTF |
| **5: Frontier + capstone** | 25–30 | sched_ext, capstone project |

## How to use this

Each day is ~75–90 minutes. Format:

1. **Concepts introduced today** — what the new primitives are, before any code uses them.
2. **The lab** — runnable code with line-by-line walkthrough.
3. **What to break, in order** — deliberate mistakes that teach the most.
4. **What to read in the kernel** — specific files and functions in your kernel checkout.
5. **Bullet Points** — terse summary you can review before bed.
6. **Check question** — single recall prompt for tomorrow morning.

The most important step is **the deliberate breakage**. Don't skip it. Five minutes of pain per lab; saves you weeks of confusion later.

## Lab source and prerequisites

Start with the [Lab environment](lab-environment.md) page. It defines the Linux toolchain, the pinned recursive dependencies, the privilege boundary, and the exact coverage of repository-owned labs.

Days 1–3 use buildable source under `ebpf/labs/`; their chapter listings are included from the same files compiled in CI. Days 4–21 and Day 24 still contain copyable snippets, Days 22–23 use the Linux kernel's BPF selftests, and Days 25–30 use `tools/sched_ext`. A green lab build therefore proves Days 1–3 only.

## Style notes

- **Head First voice.** Conversational, second-person, with the Verifier as a recurring character.
- **Real diagrams.** Every concept that benefits from visualization gets a rendered PNG.
- **No bcc.** Modern libbpf + CO-RE only.

## Companion book

This book assumes you already know the kernel network stack. If you don't, read the [Linux Network Subsystem book](../linux-net/) first — it covers `sk_buff`, the RX/TX paths, netfilter, and other pieces that BPF programs hook into.
