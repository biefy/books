# Day 17 — tcx: link-based multi-program networking

> **Today's mission:** rewrite yesterday's program with tcx, attach two programs to the same hook in a defined order, and feel why this replaces classic tc-bpf for new code. Total time: ~75 minutes.

## What tcx fixes

Yesterday's tc-bpf had three friction points:
1. **Three commands to attach** (qdisc, filter, program) and three to detach.
2. **No `bpf_link` ownership** — if your loader process crashes, the BPF stays attached, and you have to manually clean up.
3. **Multiple programs at one hook** is awkward — you juggle filter priorities by hand.

tcx (Linux 6.6+, commit `e420bed02507`) addresses all three.

![tcx vs classic](diagrams/day17_tcx_vs_classic.png)

One syscall to attach. Returns a `bpf_link` FD. Closing the FD detaches. And ordering between multiple programs uses **mprog**, the same multi-program abstraction that powers `kprobe.multi`.

## mprog: ordered chains of BPF programs

Multiple BPF programs can attach to the same hook (one tcx-ingress on `eth0` can have N programs). `mprog` defines deterministic ordering with attach-time flags:

![mprog](diagrams/day17_mprog.png)

- `BPF_F_BEFORE` — attach before existing programs.
- `BPF_F_AFTER` — attach after existing programs.
- `BPF_F_REPLACE` — replace a specific link.
- `BPF_F_LINK` — attach via `bpf_link`.

Each program in the chain returns a verdict:
- `TC_ACT_OK` — let the next program in the chain run.
- `TC_ACT_SHOT` — drop, end the chain.
- `TC_ACT_REDIRECT` — redirect, end the chain.

This is composable: a counter program, a firewall, a tracer can each be installed independently and their ordering controlled at attach time.

> ### There are no Dumb Questions
>
> **Q: If I close the link FD, does the BPF object get unloaded?**
>
> A: Only if there are no other references. The link is one ref to the program; closing it drops that ref. If userspace still holds a `bpf_program__fd` or the program is pinned in `/sys/fs/bpf`, it stays loaded but unattached.
>
> **Q: Does `tcx` work alongside legacy `tc filter add ... bpf`?**
>
> A: Yes. They share the same hook point; multiple attach mechanisms can coexist. But you generally don't want to mix — pick one for a given system.
>
> **Q: Does mprog also exist for XDP?**
>
> A: There's `xdp_multi`-attach but the abstraction is slightly different (XDP doesn't use mprog the same way). For XDP, multi-program is typically done with a "dispatcher" program in front and `BPF_PROG_RUN` tail calls. We won't cover that today.

## The lab

### `tcx.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c) (*c)++;
}

SEC("tc")
int counter(struct __sk_buff *skb)
{
    bump(0);  /* count all */
    return TC_ACT_OK;
}

SEC("tc")
int firewall(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end) return TC_ACT_OK;
    if (ip->protocol == IPPROTO_UDP) {
        bump(1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}
```

### Attach via tcx, ordered

```c
#include <bpf/libbpf.h>
#include <net/if.h>

int main(int argc, char **argv) {
    int ifindex = if_nametoindex(argv[1]);
    struct tcx_bpf *skel = tcx_bpf__open_and_load();

    /* counter goes first */
    LIBBPF_OPTS(bpf_tcx_opts, opts1);
    struct bpf_link *l1 = bpf_program__attach_tcx(
        skel->progs.counter, ifindex, &opts1);
    if (!l1) goto cleanup;

    /* firewall goes after counter */
    LIBBPF_OPTS(bpf_tcx_opts, opts2, .flags = BPF_F_AFTER);
    struct bpf_link *l2 = bpf_program__attach_tcx(
        skel->progs.firewall, ifindex, &opts2);
    if (!l2) goto cleanup;

    while (!exiting) sleep(2);

cleanup:
    bpf_link__destroy(l2);  /* detaches; FD-based */
    bpf_link__destroy(l1);
    tcx_bpf__destroy(skel);
}
```

Two programs, both at tcx-ingress. The `counter` runs first; if it returned `TC_ACT_SHOT` (it doesn't), the chain would stop. `firewall` runs after.

### Inspect the chain

```bash
sudo bpftool net show
```

You'll see:
```
xdp:
tc:
   eth0(2) tcx/ingress counter prog_id 5 link_id 3
   eth0(2) tcx/ingress firewall prog_id 6 link_id 4
```

### Run

```bash
sudo ./tcx_loader veth1 &
ping -c 3 10.0.0.2     # works (counter runs, firewall passes ICMP)
nc -u 10.0.0.2 9999    # blocked (firewall drops UDP after counter counts it)
```

Sample stats:
```
total: 5    (3 ICMP + 2 UDP including replies)
udp_drop: 1
```

Kill `tcx_loader` (Ctrl-C). The links auto-detach. Verify with `bpftool net show` — empty.

---

## What to break, in order

### Break 1 — Forget `BPF_F_AFTER`

Both programs use default flags. The second attach implicitly goes wherever the kernel decides (often "before"). The order may be `firewall → counter`, which means UDP is dropped *before* counted — total stat reflects only allowed traffic. Inspect with `bpftool net show` to verify the order. Use `BPF_F_BEFORE`/`BPF_F_AFTER` explicitly.

### Break 2 — Pin the link

```c
bpf_link__pin(l1, "/sys/fs/bpf/counter_link");
```

Now even if your loader exits, the link persists (kernel holds a reference via the pin). Useful for daemons that load BPF then exit. Detach via:

```bash
sudo rm /sys/fs/bpf/counter_link
```

### Break 3 — Mix XDP and tcx

Attach an XDP counter and a tcx counter to the same interface. Both run, in order: XDP first (no skb), tcx after (with skb). Useful pattern: XDP for raw drops, tcx for skb-aware logic.

### Break 4 — Replace a link

```c
LIBBPF_OPTS(bpf_tcx_opts, opts, .flags = BPF_F_REPLACE, .replace_link = old_link);
struct bpf_link *new = bpf_program__attach_tcx(skel->progs.new_prog, ifindex, &opts);
```

Atomically swap one program for another. No window where the hook is empty.

---

## What to read in the kernel

- **`kernel/bpf/tcx.c`** — the whole file is ~250 lines. Read it.
- **`kernel/bpf/mprog.c`** — the multi-program ordering machinery. Used by tcx, netkit, and others.
- **`tools/lib/bpf/libbpf.c`** — search `bpf_program__attach_tcx`. The userspace wrapper.
- **`tools/testing/selftests/bpf/prog_tests/tc_opts.c`** — extensive tcx tests.

---

## Bullet Points

- **tcx** is the modern attach for tc-position BPF programs. Same hook position as tc-bpf classic, better lifecycle.
- Returns a `bpf_link` FD; closing it detaches.
- **mprog** lets you attach multiple programs in a defined order: `BPF_F_BEFORE`, `BPF_F_AFTER`, `BPF_F_REPLACE`.
- No `tc qdisc add clsact` ceremony — kernel installs the hook implicitly.
- Inspect with `bpftool net show`.
- For new code, **always tcx, never classic tc-bpf**.

---

## Check question

You attach three programs to tcx-ingress on `eth0`. The first returns `TC_ACT_OK`, the second `TC_ACT_SHOT`, the third *would* return `TC_ACT_OK`. Is the third program invoked?

<details>
<summary>Click to reveal answer</summary>

**Answer:** No. `TC_ACT_SHOT` ends the chain. The third program is never called for this packet. This is the design: each program is a **filter** in the pipeline, and any one of them can short-circuit. Counters and observability programs use `TC_ACT_OK`; firewalls and policy programs use `TC_ACT_SHOT` to stop the chain. Order them so observability runs before drop.

</details>

---

## Tomorrow

Day 18: AF_XDP — bypass the kernel network stack entirely. Get raw packets to a userspace ring at 30+ Mpps per core.
