# Day 14 — XDP: count every packet on an interface

> **Today's mission:** count packets per protocol on a network interface, faster than the kernel can allocate sk_buffs. Total time: ~75 minutes.

> **Phase 3 starts here.** Days 14–19 are about networking BPF. You'll see XDP, tc, tcx, AF_XDP, cgroup, sockops. By Day 19 you'll be able to write the kind of packet-path BPF that powers Cilium and similar projects.

## XDP, the earliest hook in the kernel

Yesterday's tracing programs ran when *something interesting* happened to a function that already existed. XDP is different: **XDP runs the moment a packet arrives at the NIC, before the kernel allocates an `sk_buff`**, before any iptables, routing, or socket lookup happens.

![XDP position](diagrams/day14_xdp_position.png)

That's why XDP is fast. A skb allocation costs ~500 ns on a modern x86; routing/lookup/etc. add hundreds more. XDP runs in the driver's NAPI poll, called with a pointer to the raw frame, returns an action constant, and that's it.

Throughput numbers in the literature: 10 Mpps per core trivially, 100+ Mpps with hardware offload (offloaded XDP on supporting NICs). Your single-core software cap is around the line rate of a 10 Gbps link with small packets.

## The XDP context: `struct xdp_md`

![xdp_md](diagrams/day14_xdp_md.png)

You receive `struct xdp_md *ctx`. The two fields you'll touch on every program:

- `ctx->data` — pointer (cast from u32) to the first packet byte.
- `ctx->data_end` — pointer one-past-the-last byte.

Other fields:
- `ingress_ifindex` — which interface the packet arrived on.
- `rx_queue_index` — which NIC RX queue.
- `data_meta` — optional metadata area (Day 18, AF_XDP).
- `egress_ifindex` — only readable in devmap-egress XDP programs (`expected_attach_type == BPF_XDP_DEVMAP`); the Verifier rejects access from a plain `SEC("xdp")` program (see `xdp_is_valid_access` in `net/core/filter.c`).

**Bounds checking is not optional.** The Verifier requires every byte access be proven below `data_end`:

```c
void *data = (void *)(long)ctx->data;
void *end  = (void *)(long)ctx->data_end;
struct ethhdr *eth = data;
if (eth + 1 > end)
    return XDP_PASS;        /* skip — not enough bytes for an Ethernet header */
```

The pattern repeats for each header layer. `ip + 1 > end` for IP, `tcp + 1 > end` for TCP, etc.

## XDP actions

![xdp actions](diagrams/day14_xdp_actions.png)

Five constants you can return:

- **`XDP_PASS`** — continue to the kernel stack (allocate skb, hand off).
- **`XDP_DROP`** — free the packet now. Doesn't touch skb path.
- **`XDP_TX`** — send the (possibly modified) packet back out the same interface. DDoS-mitigation classic.
- **`XDP_REDIRECT`** — paired with `bpf_redirect_map(...)`, send to a different interface, a different CPU (cpumap), or an AF_XDP socket.
- **`XDP_ABORTED`** — error path. Equivalent to DROP plus a tracepoint fires (so you can find bugs).

> ### There are no Dumb Questions
>
> **Q: Why isn't every packet path written as XDP?**
>
> A: Because XDP runs *before* the kernel knows much. There's no socket lookup, no routing decision, no connection state. For most stacks you want skb-level processing (or higher) to use the kernel's accumulated knowledge. XDP is for cases where speed beats sophistication: DDoS drop, load balancing, L2/L3 forwarding for known patterns.
>
> **Q: Are there modes of XDP?**
>
> A: Yes. **Native XDP** runs in the driver as described — fastest. **Generic XDP** (`XDP_FLAGS_SKB_MODE`) runs slightly later, after a partial skb-like setup; works on any driver but is slower (about half the speed of native). **Offloaded XDP** runs *on the NIC* itself for hardware that supports it (Netronome, some Mellanox); program is JITed to NIC firmware. Native is the default and what we'll use.
>
> **Q: How do I attach safely without crashing my SSH session?**
>
> A: Test on a `veth` pair, not your real NIC. We'll do that in the lab.

> ### Sharpen your pencil
>
> You write an XDP program that counts packets and returns `XDP_PASS`. Compared to the same logic written as a tc-bpf ingress program, which is faster?
>
> .  
> .  
> .
>
> **Answer:** XDP, by ~500ns per packet. The tc-bpf path runs *after* skb allocation; XDP runs before. For pure observability that doesn't modify the packet, XDP wins. For complex forwarding decisions that benefit from skb metadata, tc may be the right choice — Day 17.

---

## The lab

### Setup: a veth pair to play with

```bash
sudo ip netns add ns1
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns ns1
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip link set veth0 up
sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev veth1
sudo ip netns exec ns1 ip link set veth1 up
```

`veth1` lives in its own namespace, `ns1`, and this matters: if both ends shared the root namespace, `10.0.0.2` would be a *local* address, and the kernel would short-circuit `ping 10.0.0.2` through `lo` — the packet would never leave `veth0`, and XDP on `veth1` would never fire. Putting `veth1` in `ns1` forces traffic to cross the wire. We attach our program to `veth1` inside `ns1`; pinging `10.0.0.2` from the host sends echo requests out `veth0`, across the link into `veth1`'s RX path, where XDP runs.

### `xdp_count.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);   /* indexed by IP protocol number */
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth + 1 > end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end)
        return XDP_PASS;

    __u32 key = ip->protocol;          /* TCP=6, UDP=17, ICMP=1 */
    __u64 *c = bpf_map_lookup_elem(&counts, &key);
    if (c) (*c)++;                     /* per-CPU; no atomic needed */

    return XDP_PASS;
}
```

What's new:
- **`SEC("xdp")`** — XDP attach. Userspace specifies the interface.
- **`#include <bpf/bpf_endian.h>`** — for `bpf_htons`. Network byte order is big-endian; x86 is little-endian. `bpf_htons` is portable.
- **`BPF_MAP_TYPE_PERCPU_ARRAY`** — each CPU gets its own value slot. No atomic needed for increment because no two CPUs share a slot. Userspace must sum across CPUs to get a total.
- The bounds check pattern is *the* XDP idiom. Everyone writes it.

### `xdp_count.c` — userspace

```c
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "xdp_count.skel.h"

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { exiting = 1; }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <iface>\n", argv[0]); return 1; }
    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct xdp_count_bpf *skel = xdp_count_bpf__open_and_load();
    if (!skel) return 1;

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_count, ifindex);
    if (!link) { fprintf(stderr, "attach failed\n"); return 1; }

    signal(SIGINT, on_sigint);

    while (!exiting) {
        sleep(2);
        int fd = bpf_map__fd(skel->maps.counts);
        int ncpu = libbpf_num_possible_cpus();
        for (__u32 k = 0; k < 256; k++) {
            __u64 vals[ncpu];
            if (bpf_map_lookup_elem(fd, &k, vals) == 0) {
                __u64 sum = 0;
                for (int i = 0; i < ncpu; i++) sum += vals[i];
                if (sum) printf("proto %3u: %llu\n", k, sum);
            }
        }
        printf("---\n");
    }
    bpf_link__destroy(link);
    xdp_count_bpf__destroy(skel);
    return 0;
}
```

### Run

```bash
make
sudo ip netns exec ns1 ./xdp_count veth1 &
# From the host (root namespace):
ping -c 5 10.0.0.2
nc -u 10.0.0.2 9999 <<< "hello"
```

Expected output every 2 seconds:
```
proto   1: 5      # ICMP
proto  17: 1      # UDP
---
```

You're now counting every packet that hits `veth1`. Now redirect this same program at a real NIC (`eno1` or whatever) and you've got line-rate counters with effectively zero overhead.

### Cleanup

```bash
sudo kill %1                 # stop the loader; closing its bpf_link fd auto-detaches the XDP program
sudo ip link del veth0       # deletes the pair (veth1 goes with it)
sudo ip netns del ns1        # remove the namespace
```

The XDP program stays attached only as long as the loader runs — the link is never pinned, so `bpf_link__destroy` (or simply the process exiting) detaches it. If you stopped the loader some other way and the program is still attached, detach it explicitly with `sudo ip netns exec ns1 ip link set dev veth1 xdp off`.

---

## What to break, in order

### Break 1 — Drop the bounds check

```c
struct iphdr *ip = (void *)(eth + 1);
__u32 key = ip->protocol;     /* no bounds check */
```

Verifier rejects at load time. libbpf prints the log to stderr when `xdp_count_bpf__open_and_load()` fails (the `if (!skel) return 1;` path — the userspace program prints nothing of its own):

```
invalid access to packet, off=23 size=1, R1(id=0,off=0,r=14)
```

`off=23` because `protocol` sits 9 bytes into the IP header and the IP header starts 14 bytes (one Ethernet header) into the frame; only those first 14 bytes were bounds-checked (`r=14`). The Verifier's per-byte tracking doesn't know the byte at `eth+1+offsetof(protocol)` is reachable. The exact wording and offsets are kernel- and clang-version dependent.

### Break 2 — Pre-bound the index, then atomic

Switch from per-CPU to a regular hash:

```c
__uint(type, BPF_MAP_TYPE_HASH);
```

A `PERCPU_ARRAY` pre-allocates all 256 indices, so `bpf_map_lookup_elem(&counts, &key)` always returns a (zeroed) slot. A `HASH` map starts empty — the lookup returns `NULL` for every protocol it hasn't seen yet, so `if (c) ...` never fires and the counter stays at zero. You have to create the entry on first sight, and because a shared (not per-CPU) map can be touched by several CPUs at once, the increment now needs an atomic:

```c
__u64 *c = bpf_map_lookup_elem(&counts, &key);
if (c) {
    __sync_fetch_and_add(c, 1);          /* shared map: atomic now required */
} else {
    __u64 one = 1;
    bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);  /* create on first sight */
}
```

(The first concurrent update for a brand-new key can still race on a non-preallocated hash; `BPF_NOEXIST` plus the atomic add on the existing-entry path is the standard mitigation.)

The throughput lesson — a shared hash contends on a per-bucket lock where the per-CPU array does not — is **not observable on this veth**: a 5-packet ping over a single-queue virtual link generates no contention. To see it you need a real multi-queue NIC and parallel load that spreads RX across CPUs (e.g. `iperf3 -u -P 16` to a peer, or `pktgen` across queues), then `sudo perf top -e cycles -g`. With the hash you'll see time in `queued_spin_lock_slowpath`/`_raw_spin_lock` under `htab_map_update_elem`/`bpf_map_lookup_elem`; with the per-CPU array those frames are absent.

### Break 3 — Return `XDP_DROP` instead of `XDP_PASS`

Change the return to `XDP_DROP`, then rebuild and re-attach — editing the program does nothing until you reload it:

```bash
make
sudo ip netns exec ns1 ./xdp_count veth1 &
ping -c 5 10.0.0.2
```

The ping now reports `100% packet loss` (0 received): the echo requests cross the wire, hit `veth1`'s RX inside `ns1`, and XDP drops them before they reach the IP stack, so no replies come back. SSH into your box still works (it's on a different interface). Lesson: XDP is the literal first hop. Be careful which iface you attach to. (This break is invisible without the namespace separation from the setup above — a same-namespace `10.0.0.2` is delivered locally over `lo` and never reaches `veth1`'s XDP hook.)

### Break 4 — Forget a per-layer bounds check

```c
struct iphdr *ip = (void *)(eth + 1);
if (ip + 1 > end) return XDP_PASS;
struct tcphdr *tcp = (void *)(ip + 1);
if (tcp + 1 > end) return XDP_PASS;
__u16 dport = tcp->dest;
```

As written this compiles and loads — every layer is bounds-checked. Now **delete** the `if (tcp + 1 > end) return XDP_PASS;` line and rebuild. The Verifier rejects the load with the same `invalid access to packet` error, this time pointing at the `tcp->dest` read: each header layer needs its own check, and Break 1's lesson generalizes from one header to a multi-layer chain.

---

## What to read in the kernel

- **`include/net/xdp.h`** — `bpf_prog_run_xdp`, the inline that drivers call to run an XDP program.
- **`include/uapi/linux/bpf.h`** — `struct xdp_md` and `enum xdp_action` (the action constants).
- **`net/core/dev.c`** — search `xdp_buff`; the driver-side dispatch path.
- **`net/core/filter.c`** — XDP helpers (`xdp_func_proto` table). Note which helpers are XDP-only.
- **`tools/testing/selftests/bpf/progs/test_xdp_*`** — many examples of common patterns.
- **`Documentation/networking/xdp.rst`** — official doc; one read recommended.

---

## Bullet Points

- **XDP** runs in the driver's NAPI poll, before skb allocation. Fastest place to drop, redirect, or count.
- `struct xdp_md`: `data`, `data_end`, `ingress_ifindex`, `rx_queue_index`, `data_meta`, `egress_ifindex`.
- **Bounds checks are mandatory**: every byte you read must be proven `< data_end` before access.
- Actions: **PASS, DROP, TX, REDIRECT, ABORTED**.
- `BPF_MAP_TYPE_PERCPU_ARRAY` for hot-path counters — no contention, sum in userspace.
- `bpf_htons`/`bpf_ntohs` for byte-order conversion (network = big-endian).
- Test with `veth` pairs before attaching to real interfaces.

---

## Check question

You attach an XDP program that always returns `XDP_PASS`. Why might it still affect performance compared to no program at all?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Two reasons. **(1)** Native XDP requires the driver to call into the BPF program for every packet — that's a function call (~10-30 ns) plus your logic. Even an empty program has measurable cost at line rate. **(2)** Some drivers disable certain optimizations (large receive offload, GRO) when XDP is attached, because XDP needs to see one packet at a time, not coalesced bursts. So even a passthrough XDP can reduce throughput by ~10% on workloads dependent on those features. For tracing/observability, this is fine; just be aware before deploying on a production load-balancer NIC.

</details>

---

## Tomorrow

Day 15: turn the counter into a denylist with `BPF_MAP_TYPE_LPM_TRIE` and userspace-controlled rules. Drop traffic from specific CIDRs at line rate.
