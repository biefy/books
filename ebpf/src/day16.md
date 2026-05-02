# Day 16 — tc-bpf: BPF in the kernel network stack

> **Today's mission:** attach BPF to a network interface's ingress *and* egress with classic tc, see why XDP can't do everything, and feel the pain of `tc qdisc` lifecycle that motivated tcx (tomorrow). Total time: ~75 minutes.

## Why tc, when XDP exists

XDP runs before skb allocation — fastest place. But that's also its limit: there's *no skb* yet. No connection-tracking metadata, no socket lookup, no routing decision, no skb cb. For programs that need that information (e.g., "tag packets belonging to flows my conntrack already saw"), XDP isn't enough.

**tc-bpf** runs *after* skb allocation. You see `struct __sk_buff` — a typed view of the kernel's `struct sk_buff` with all metadata visible.

![XDP vs tc](diagrams/day16_xdp_vs_tc.png)

The other big difference: **tc has both ingress and egress hooks**. XDP is ingress-only. If you want to drop or modify packets *on their way out* (e.g., adding tunnel encapsulation, marking based on cgroup), you need tc.

## The tc context: `struct __sk_buff`

A read-mostly typed view of `struct sk_buff`:

```c
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;        /* PACKET_HOST, PACKET_BROADCAST, ... */
    __u32 mark;            /* socket/skb mark */
    __u32 queue_mapping;
    __u32 protocol;        /* L3 protocol */
    __u32 ifindex;
    __u32 cb[5];           /* skb control block — pass data between progs */
    __u32 hash;            /* skb hash */
    __u32 tc_index;        /* tc classification slot */
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_classid;
    __u32 data;            /* same idea as xdp_md */
    __u32 data_end;
    /* and more — including socket cookie, tstamp, etc. */
};
```

Use `data` and `data_end` for direct packet access (same bounds-checking discipline as XDP). Use `mark`, `cb`, etc. to coordinate with kernel state.

## Action constants for tc

```c
#define TC_ACT_OK         0   /* let the packet through */
#define TC_ACT_RECLASSIFY 1   /* reclassify */
#define TC_ACT_SHOT       2   /* drop */
#define TC_ACT_PIPE       3   /* pass to next filter */
#define TC_ACT_STOLEN     4   /* steal: don't free, prog took it */
#define TC_ACT_QUEUED     5
#define TC_ACT_REPEAT     6
#define TC_ACT_REDIRECT   7   /* paired with bpf_redirect() */
```

Most programs return `TC_ACT_OK` (allow), `TC_ACT_SHOT` (drop), or `TC_ACT_REDIRECT`.

> ### There are no Dumb Questions
>
> **Q: Does tc see GRO-coalesced packets or individual packets?**
>
> A: tc on ingress sees what NAPI/GRO produced — coalesced superpackets if GRO is enabled. tc on egress sees skbs as the kernel built them. Tools like Cilium often disable GRO when the BPF program needs per-packet visibility.
>
> **Q: Why is the attach mechanism so awkward (`tc qdisc add` + `tc filter add`)?**
>
> A: tc predates BPF. It was originally a packet-classifier system for QoS (queueing disciplines), and BPF programs got bolted on as a "filter" type. The qdisc gives you a hook point; the filter is your BPF. Hence two commands. tcx (tomorrow) ditches this entirely.

## The lab: tc on ingress and egress

### `tc.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end) return TC_ACT_OK;
    /* Mark packets so userspace iptables can pick them up */
    skb->mark = 0xCAFE;
    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    /* Drop every UDP packet outbound to demonstrate egress */
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end) return TC_ACT_OK;
    if (ip->protocol == IPPROTO_UDP) return TC_ACT_SHOT;
    return TC_ACT_OK;
}
```

### Attach the classic way

```bash
sudo tc qdisc add dev veth1 clsact

sudo tc filter add dev veth1 ingress \
     bpf da obj tc.bpf.o sec tc_ingress

sudo tc filter add dev veth1 egress \
     bpf da obj tc.bpf.o sec tc_egress

# verify:
sudo tc filter show dev veth1 ingress
sudo tc filter show dev veth1 egress
```

`clsact` is a special qdisc that exists solely to provide ingress and egress hook points for tc-bpf. It doesn't shape traffic; it's a scaffold.

### Run

```bash
ping -c 3 10.0.0.2
nc -u 10.0.0.2 9999 <<< "hi"   # should fail — egress UDP dropped
```

Verify the mark in iptables:
```bash
sudo iptables -A INPUT -m mark --mark 0xCAFE -j LOG
dmesg | tail
```

You'll see TCP/ICMP marked but UDP dropped on egress.

### Detach

```bash
sudo tc filter del dev veth1 ingress
sudo tc filter del dev veth1 egress
sudo tc qdisc del dev veth1 clsact
```

Three commands to undo. If your test process crashes mid-test, you have to remember to clean up. **No FD-based ownership.** This is the pain point tcx fixes.

---

## What to break, in order

### Break 1 — Forget `clsact`

```bash
sudo tc filter add dev veth1 ingress bpf da obj ...
# error: Cannot find device "ingress"
```

Without `clsact`, there are no ingress/egress slots. Add it first.

### Break 2 — Try a BPF helper that doesn't work in tc

Try `bpf_xdp_adjust_head` from a tc program. Verifier rejects — that helper is XDP-only. Each program type has its own helper allowance table.

### Break 3 — Set `skb->len`

```c
skb->len = 100;
```

Verifier rejects — `__sk_buff` is read-only for most fields. The few writable ones (mark, priority, cb[]) are listed explicitly in `bpf_skb_is_valid_access`.

### Break 4 — Multiple programs at one priority

```bash
sudo tc filter add dev veth1 ingress pref 100 bpf da obj p1.o sec tc
sudo tc filter add dev veth1 ingress pref 100 bpf da obj p2.o sec tc  # FAIL
```

Two filters at the same priority fail. You'd use distinct prefs (`pref 100`, `pref 200`). Replacing requires del+add. **This is exactly what tcx fixes.**

---

## What to read in the kernel

- **`net/sched/cls_bpf.c`** — the classic tc-bpf classifier. Ages ~10 years old.
- **`net/sched/sch_ingress.c`** — `clsact_init` and the ingress hook plumbing.
- **`tools/lib/bpf/libbpf.c`** — search `bpf_program__attach_tc`. The libbpf wrapper for the legacy interface.

---

## Bullet Points

- **tc-bpf** runs after skb allocation; sees `__sk_buff` with full kernel metadata.
- Has both **ingress and egress** hooks (XDP is ingress only).
- Action constants: `TC_ACT_OK`, `TC_ACT_SHOT`, `TC_ACT_REDIRECT`.
- Classic attach: `tc qdisc add ... clsact` + `tc filter add ... bpf`. **Three commands to set up, three to tear down.**
- No FD-based ownership; cleanup on crash is fragile.
- **Use tcx (Day 17)** for new code. tc-bpf classic is legacy.

---

## Check question

You attach the same BPF program to both XDP and tc-ingress on the same interface. Both run on every incoming packet. Will you see them invoked in a deterministic order?

.  
.  
.

**Answer:** Yes. **XDP runs first** (in the driver, before skb alloc). If XDP returns `XDP_PASS`, the packet flows on; the kernel allocates skb and calls tc-ingress. If XDP returns `XDP_DROP`, tc-ingress never sees the packet. They're sequential, not concurrent — XDP's decision gates whether tc even runs.

---

## Tomorrow

Day 17: tcx — same hook position as tc-bpf but with `bpf_link` lifecycle, multi-program ordering via `mprog`, and zero `tc qdisc` ceremony.
