# Day 27 — XDP and the rest of the stack

> **Today's mission:** see how XDP cooperates with the rest of the kernel network stack. Total time: ~60 minutes.

> **Phase 5 starts here.** The last four days cover modern features and a capstone.

![XDP position](diagrams/day27_xdp_position.png)

## What XDP is, kernel-side

XDP runs in the NIC driver's NAPI poll, before any skb allocation. It's the earliest hook on the RX path. Returns one of:

- `XDP_DROP` — packet freed.
- `XDP_PASS` — continue into the normal stack.
- `XDP_TX` — send back out same iface.
- `XDP_REDIRECT` — paired with `bpf_redirect_map()`, send to other iface or AF_XDP socket.
- `XDP_ABORTED` — drop + tracepoint (for debugging).

For the kernel network stack, XDP is "fast-path bypass." Decisions made there save the cost of skb alloc + the rest of the stack.

## Three modes

- **Native XDP** — driver-supported, fastest. ~10ns + program.
- **Generic XDP** (`XDP_FLAGS_SKB_MODE`) — works on any driver, slower (about half of native).
- **Hardware-offloaded XDP** — JITs program to NIC firmware (Netronome, some Mellanox).

## Cooperating with the stack

XDP and tc-bpf compose: XDP for raw-frame fast drops, tc-bpf for skb-aware logic. Many production systems use both.

Cilium does this extensively: XDP for L3 load balancing on a few hot tuples; tc-bpf for everything else.

## What to read in the kernel

- **`net/core/dev.c`** — `bpf_prog_run_xdp` dispatch.
- **`include/net/xdp.h`** — `struct xdp_md`, action constants.
- **`include/linux/filter.h`** — `bpf_redirect_map` and friends.
- **`kernel/bpf/devmap.c`** — `BPF_MAP_TYPE_DEVMAP` for redirect.

## Bullet Points

- XDP is the earliest BPF hook; runs before skb alloc.
- Five actions: PASS, DROP, TX, REDIRECT, ABORTED.
- Three modes: native, generic, offloaded.
- Cooperates with tc-bpf and the rest of the stack via PASS.

## Check question

You attach XDP that returns DROP for some packets and PASS for others. Does iptables/nftables see the dropped ones?

<details>
<summary>Click to reveal answer</summary>

**Answer:** No. XDP runs *before* skb allocation. Dropped packets never reach netfilter, never reach the stack at all. iptables sees only the ones XDP passed. This is why XDP is preferred for high-rate DDoS drop — it's the cheapest place to drop, and netfilter overhead is avoided.

</details>

## Tomorrow

Day 28: io_uring networking.
