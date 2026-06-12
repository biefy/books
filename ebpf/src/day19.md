# Day 19 — cgroup BPF and sockops: policy at the socket layer

> **Today's mission:** filter network access per cgroup, then tune TCP behavior per cgroup. End of Phase 3. Total time: ~75 minutes.

## Above the packet, below the socket

Days 14–18 worked at the packet layer. Today goes higher: the **socket** and **cgroup** layers. Two related families:

![cgroup + sockops](diagrams/day19_cgroup_sockops.png)

- **`cgroup_skb`** — fires per-packet for sockets in a cgroup. Returns 0 (drop) or 1 (allow). Used for namespaced firewalls.
- **`sock_ops`** — fires at TCP state-machine events (connect, ESTABLISHED, RTT updates, header option negotiation). Tune connection params per cgroup.
- **`sk_msg`** — fires on `sendmsg` for sockets in a sockmap; used for L7 load balancing (Cilium service mesh).
- **`cgroup_sock_addr`** — fires on `connect()`, `bind()`, `sendmsg()` to UDP, etc. Modify sockaddr (do socket-level NAT).

These programs run in **process context** with full kernel scheduling, so they have the full non-sleepable helper set and can call helpers like `bpf_setsockopt`. (They are *not* sleepable, though — `can_be_sleepable()` in the verifier only permits fentry/fexit/fsession/fmod_ret, LSM, iter, uprobe, and struct_ops.)

## Why cgroups

Linux cgroups partition resources (CPU, memory, IO, network). BPF cgroup hooks let you attach policy to a cgroup that runs only for processes in that cgroup. This is how systemd, Cilium, and Kubernetes sidecars implement per-pod or per-service network rules without iptables overhead.

## sockops example: per-cgroup TCP tuning

![sockops flow](diagrams/day19_sockops_flow.png)

When a TCP connection event fires (e.g., `BPF_SOCK_OPS_TCP_CONNECT_CB`), your BPF program can call `bpf_setsockopt(skops, ..., TCP_CONGESTION, "bbr", 3)` to set BBR for *this socket*. Combined with cgroup attachment, you've got "all sockets from cgroup X use BBR; all sockets from cgroup Y use CUBIC."

> ### There are no Dumb Questions
>
> **Q: When does `cgroup_skb` run vs `tc`?**
>
> A: `cgroup_skb/ingress` runs *after* IP routing decided this packet is for a local socket; the kernel knows which cgroup the destination socket belongs to. `cgroup_skb/egress` runs *after* the socket sent — kernel knows the source socket's cgroup. tc runs at L2/L3, before/after socket layer. Use cgroup_skb when policy is "this cgroup's traffic" rather than "this interface's traffic."
>
> **Q: How is sock_ops different from setting sysctls?**
>
> A: Sysctls are global; sock_ops is per-socket and conditional. You can set RTO_MIN to 500ms for cgroup A and 5ms for cgroup B without touching sysctls. The conditional check happens in BPF, evaluated per connection.
>
> **Q: Are these used much in practice?**
>
> A: Yes — Cilium uses cgroup_sock_addr extensively for socket-level service translation (kube-proxy replacement). Service meshes use sk_msg for L7 routing. Most users don't touch them directly because tools abstract them.

## The lab — two parts

### Part A: cgroup_skb firewall

Create a test cgroup and block egress UDP for any process in it.

> **Prerequisite:** cgroup v2 (unified hierarchy) mounted at `/sys/fs/cgroup` — verify with `mount | grep cgroup2` (expect `cgroup2 on /sys/fs/cgroup type cgroup2 ...`) — and a kernel built with `CONFIG_CGROUP_BPF=y` (check `zgrep CGROUP_BPF /proc/config.gz` or `/boot/config-$(uname -r)`). On cgroup v1 / hybrid hosts the path and attach semantics differ.

```bash
sudo mkdir /sys/fs/cgroup/test_block
echo $$ | sudo tee /sys/fs/cgroup/test_block/cgroup.procs   # only this shell
```

`fw.bpf.c`:
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/egress")
int block_udp(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct iphdr *ip = data;
    if (ip + 1 > end) return 1;       /* allow if can't parse */
    if (ip->protocol == IPPROTO_UDP) return 0;  /* drop UDP */
    return 1;
}
```

Note: `cgroup_skb/ingress` returns **1 = allow, 0 = drop**. `cgroup_skb/egress` is wider — the verifier enforces a return range of **0-3**: `0`=drop, `1`=keep, `2`=drop and notify TCP of congestion (cn), `3`=keep and cn. Returning anything outside that range is rejected at load time.

Userspace attach. Compile this loader with the day's Makefile (same skeleton-driven pattern as earlier days) and **keep it running** while you test — `bpf_program__attach_cgroup` returns a `struct bpf_link *` whose lifetime is tied to the process. When the loader exits, the link is freed and UDP egress is allowed again:

```c
int cg_fd = open("/sys/fs/cgroup/test_block", O_RDONLY);
struct fw_bpf *skel = fw_bpf__open_and_load();
struct bpf_link *l = bpf_program__attach_cgroup(skel->progs.block_udp, cg_fd);
printf("attached, Ctrl-C to detach\n");
pause();   /* keep the process (and the link) alive */
```

If you want the policy to survive loader exit, pin the link instead: `bpf_link__pin(l, "/sys/fs/bpf/block_udp")` (needs bpffs mounted at `/sys/fs/bpf`, which is standard). Run the loader in one terminal, then perform the Test below from the `test_block` shell while it is still running.

Test. Use a UDP probe whose success/failure is *visible* — `dig` defaults to UDP/53, exactly the protocol/port the filter drops, so the timeout-vs-answer contrast is unambiguous (raw `nc -u` would hang identically in both cases and reveal nothing):

```bash
# from the shell that's in test_block (egress UDP dropped):
dig +tries=1 +timeout=2 @1.1.1.1 example.com
#   -> ";; communications error to 1.1.1.1#53: timed out
#       ... no servers could be reached"   (UDP/53 blocked)
ping -c 3 1.1.1.1            # works: 3 replies (ICMP, not UDP)

# from another shell (NOT in test_block):
dig +tries=1 +timeout=2 @1.1.1.1 example.com
#   -> returns an A-record ANSWER section, e.g.
#        example.com.   215   IN   A   104.20.23.154   (UDP/53 allowed)
```

This ties back to the chapter's own check question: DNS over UDP/53 is exactly what a `cgroup_skb/egress` UDP drop kills.

**Teardown** (run this when done — and it's also the Break 2 recovery):
```bash
# 1. move your shell back to the root cgroup (run from another shell if the
#    current one is locked out by the egress drop):
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs
# 2. stop the loader (Ctrl-C). Since the bpf_link isn't pinned, this detaches
#    the egress program automatically.
# 3. remove the cgroup (rmdir only succeeds once it has no procs):
sudo rmdir /sys/fs/cgroup/test_block
```

### Part B: sock_ops TCP tuning

`tune.bpf.c`:
```c
SEC("sockops")
int tcp_tune(struct bpf_sock_ops *skops)
{
    if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB ||
        skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        /* Set BBR for connections in this cgroup */
        char cc[] = "bbr";
        bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
    }
    return 0;
}
```

Attach to a cgroup:
```c
struct bpf_link *l = bpf_program__attach_cgroup(skel->progs.tcp_tune, cg_fd);
```

Verify. There's nothing to observe until a *fresh* TCP connection fires sockops from inside the cgroup, and BBR must actually be available — otherwise `bpf_setsockopt(...,"bbr",...)` fails silently (that's Break 3). Also scope `ss` to the target so you don't match unrelated sockets (e.g. your SSH session, which may itself be on BBR):

```bash
# prerequisite: BBR must be available
sudo modprobe tcp_bbr 2>/dev/null   # no-op if built in
sysctl net.ipv4.tcp_available_congestion_control
#   -> net.ipv4.tcp_available_congestion_control = reno cubic dctcp bbr htcp
#      (the list must include 'bbr')

# with the loader attached, run from the shell that's in the cgroup so a fresh
# connect fires sockops; keep the socket alive long enough to observe it:
curl -s https://speed.cloudflare.com/__up -T /dev/zero --max-time 4 >/dev/null &
sleep 1
ss -ti dst :443 | grep bbr
#   -> the info line for this socket shows 'bbr', e.g.
#        bbr wscale:6,10 rto:219 rtt:18.6/1.2 ... bbr:(bw:7.35Mbps,...)
```

Expected: the in-cgroup connection's `ss -i` info line contains `bbr`. A socket opened from a shell **not** in the cgroup shows the system default (e.g. `cubic`). If `ss` is empty, either no fresh connection was made from the cgroup, or BBR is not loaded (the `bpf_setsockopt` failed silently — Break 3).

---

## What to break, in order

### Break 1 — Out-of-range return

Return `5` (or any value > 3) from a `cgroup_skb/egress` program. The verifier rejects it at load: egress return values must fall in `retval_range(0, 3)` (`kernel/bpf/verifier.c`). The defined values are `0`=drop, `1`=keep, `2`=drop+cn, `3`=keep+cn — so returning `TC_ACT_SHOT` (which is `2`) actually *loads and runs*, but it means "drop and signal congestion," not "allow." It's a **defined egress value**, not a coincidental pass. On ingress the range is just `0`/`1`. Don't borrow tc's `TC_ACT_*` constants here — the conventions only overlap by accident.

### Break 2 — Forget the IPPROTO check

Drop *all* packets in cgroup_skb/egress (`return 0` always). Your shell loses all network access. Be careful with cgroup attachment — you can lock yourself out as easily as with `iptables -P OUTPUT DROP`. Recover with the **Teardown** steps above: either kill the loader (which detaches the filter from `test_block`) or, from a second shell, move your stuck shell back to the root cgroup with `echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs`. Either restores network, because the egress program only runs for procs still inside the cgroup.

### Break 3 — TCP CC not loaded

`bpf_setsockopt(..., "bbr_invalid", ...)`. Returns -EINVAL silently. The connection still succeeds with the system default. Symptom: your sockops "doesn't work" — it's running but the helper failed. Always check return values.

### Break 4 — Use `cgroup_sock_addr` for socket-level NAT

```c
SEC("cgroup/connect4")
int rewrite_connect(struct bpf_sock_addr *ctx)
{
    if (ctx->user_port == bpf_htons(8080)) {
        ctx->user_port = bpf_htons(80);
        return 1;
    }
    return 1;
}
```

Now connections from this cgroup to port 8080 are silently redirected to port 80. This is how Cilium's "socket-level service translation" works — kube-proxy without iptables.

---

## What to read in the kernel

- **`kernel/bpf/cgroup.c`** — the cgroup BPF infrastructure. ~1500 lines. Read the dispatch path.
- **`include/linux/bpf-cgroup.h`** — interface and program types.
- **`net/core/filter.c`** — search `bpf_sock_ops_func_proto`. Helpers available to sockops.
- **`tools/testing/selftests/bpf/progs/sockopt_*.c`** — sockops examples.
- **`Documentation/bpf/prog_cgroup_sockopt.rst`** — official docs.

---

## Bullet Points

- **`cgroup_skb`** runs per-packet for sockets in a cgroup. Ingress returns 1=allow/0=drop; egress allows 0-3 (0=drop, 1=keep, 2=drop+cn, 3=keep+cn), verifier-enforced.
- **`sock_ops`** runs at TCP state events; can call `bpf_setsockopt` to tune the connection.
- **`sk_msg`** runs on send for sockets in a sockmap; used for L7 routing.
- **`cgroup_sock_addr`** lets you rewrite sockaddrs at `connect`/`bind` — socket-level NAT.
- These hooks run in **process context** — full non-sleepable helper set, can call `bpf_setsockopt`.
- Used heavily in production: Cilium, systemd, Kubernetes service meshes.

---

## Check question

You attach a `cgroup_skb/egress` program that returns `0` (drop) for every packet. A process in the cgroup runs `wget google.com`. Does the DNS lookup happen?

<details>
<summary>Click to reveal answer</summary>

**Answer:** No. DNS uses UDP/53; both UDP and TCP egress are filtered by `cgroup_skb`. The lookup `socket()`, `connect()`, and `sendmsg()` all succeed (cgroup_skb fires later, on packet send), but the actual UDP packet leaving the cgroup is dropped by your program. `wget` times out. To allow DNS specifically, gate by destination port in BPF.

</details>

---

## End of Phase 3

You can now write BPF programs at every layer of the network stack: XDP at the driver, tc/tcx at the skb layer, AF_XDP for kernel bypass, cgroup_skb for per-cgroup filtering, sock_ops for TCP tuning, sk_msg for L7. That's the full surface.

Phase 4 (Days 20–24) shifts to modern primitives: kfuncs, kptrs, struct_ops, BTF spelunking. The infrastructure that makes 2024–2026 BPF feel different from 2019 BPF.
