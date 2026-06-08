# Day 20 — Netfilter hooks

> **Today's mission:** see exactly where in the network stack `iptables`/`nftables` run, the verdict pipeline that turns a rule decision into a packet action, and the per-protocol/per-netns hook tables that make it all per-namespace. Total time: ~75 minutes.

> **Phase 4 starts here.** Days 20–26 cover the kernel's network subsystems: netfilter, nftables, conntrack, traffic control, `SO_REUSEPORT`, kTLS, MPTCP.

## What Netfilter is

Netfilter is the kernel's framework for **inspecting, modifying, and dropping packets** at well-defined points along the network stack. iptables, nftables, conntrack, IPVS, ebtables, and arptables all hook into this same framework. Understanding the hook layout means understanding *where* every firewall/NAT rule actually runs.

The framework is intentionally minimal: it's just a set of hook points, a registration API, and a verdict pipeline. Specific filtering logic (matching rules, computing actions) lives in the consumers (`nf_tables`, `ip_tables`, `nf_conntrack`).

## The five hooks (per protocol family)

![nf hooks](diagrams/day20_nf_hooks.png)

For IPv4 (`NFPROTO_IPV4`), defined at `include/uapi/linux/netfilter.h:42`:

```c
enum nf_inet_hooks {
    NF_INET_PRE_ROUTING,    // 0 — after IP header validation, before routing decision
    NF_INET_LOCAL_IN,       // 1 — packets routed to local sockets
    NF_INET_FORWARD,        // 2 — packets being routed through us
    NF_INET_LOCAL_OUT,      // 3 — packets we're generating
    NF_INET_POST_ROUTING,   // 4 — just before TX
    NF_INET_NUMHOOKS
};
```

(The real enum also carries a trailing `NF_INET_INGRESS = NF_INET_NUMHOOKS` (value 5) — a special-purpose inet ingress hook; the five entries above are the traditional hooks we focus on.)

### Where each one fires

- **PRE_ROUTING** runs in `ip_rcv` (`net/ipv4/ip_input.c`), right after `ip_rcv_core` validates the header, *before* the routing decision. This is where you do **DNAT** (destination NAT — change where the packet is going) because the routing decision uses the post-rewrite destination.

- **LOCAL_IN** runs in `ip_local_deliver` after the routing decision determines the packet is for us. Last chance to drop before delivery to a socket. iptables' `INPUT` chain.

- **FORWARD** runs in `ip_forward` after routing determines the packet is *not* for us. iptables' `FORWARD` chain. It is the transit-only filter point, but a forwarded packet also passed through PREROUTING before the route lookup and will pass through POSTROUTING before TX.

- **LOCAL_OUT** runs in `__ip_local_out` for packets we're generating, immediately after the IP header is built. Note: by the time this fires the **initial route lookup has already run** (`ip_route_output_flow` precedes `ip_local_out`, so `skb_dst` is set). If a NAT rule here changes the destination, the original route no longer applies and the packet must be re-routed (`ip_route_me_harder`).

- **POST_ROUTING** runs in `ip_output` after all routing decisions, just before handing to the device. This is where you do **SNAT** (source NAT, including masquerading) because the new source IP doesn't change where the packet goes from here.

### IPv6 has equivalents

Same enum, same five hooks, all with `NFPROTO_IPV6`. Plus `NFPROTO_BRIDGE` (a separate set: PREROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POSTROUTING for bridged frames) and `NFPROTO_ARP` (3 hooks for ARP packets).

## Per-netns, per-priority hook lists

Each `(net, protocol_family, hook_id)` triple has its own list of registered callbacks. `struct net` holds them at `net->nf.hooks_ipv4[NF_INET_NUMHOOKS]`, `net->nf.hooks_ipv6[]`, etc. Registering a hook = appending to that list at a given priority.

Priority determines order. Constants in `enum nf_ip_hook_priorities` (`include/uapi/linux/netfilter_ipv4.h`):

```c
NF_IP_PRI_RAW              = -300,    // raw table (early)
NF_IP_PRI_CONNTRACK_DEFRAG = -400,    // conntrack defrag
NF_IP_PRI_CONNTRACK        = -200,    // conntrack itself
NF_IP_PRI_MANGLE           = -150,    // mangle table
NF_IP_PRI_NAT_DST          = -100,    // dnat
NF_IP_PRI_FILTER           =    0,    // filter table
NF_IP_PRI_NAT_SRC          =  100,    // snat
NF_IP_PRI_LAST             =  INT_MAX,
```

Lower numbers run first. So at PRE_ROUTING, conntrack runs before NAT, which runs before user filter rules — because that's the order priorities give.

## How a hook gets invoked

The kernel uses the macro `NF_HOOK(pf, hook, net, sk, skb, indev, outdev, okfn)`. If no hooks are registered (the `hooks` static key is off), the macro inlines `okfn(...)` directly — zero overhead. If hooks exist, it calls `nf_hook_slow` (`net/netfilter/core.c:612`):

1. Walks the registered list at `net->nf.hooks_<family>[hook]` in priority order.
2. Calls each hook function with `nf_hook_state` (the context) and skb.
3. Each hook returns a *verdict*.
4. If all return ACCEPT, calls `okfn(skb)` — the next stage in the pipeline.

## The verdicts

```c
#define NF_DROP        0   // free skb, stop
#define NF_ACCEPT      1   // proceed
#define NF_STOLEN      2   // hook took ownership; don't free
#define NF_QUEUE       3   // queue to userspace via NFQUEUE
#define NF_REPEAT      4   // re-run from the start of this hook
#define NF_STOP        5   // accept, but don't continue to the next hook (rare)
```

- **`NF_ACCEPT`** is the common path: continue to the next hook, then to `okfn`.
- **`NF_DROP`** ends the journey; skb is freed (with a drop-reason if `kfree_skb_reason` is used).
- **`NF_STOLEN`** is for hooks that take ownership and will free or forward the skb later (used by IPVS, conntrack defrag).
- **`NF_QUEUE`** sends the skb to a userspace process via the NFQUEUE protocol (`libnetfilter_queue`). Userspace returns a verdict via netlink.
- **`NF_REPEAT`** re-runs the same hook (used by some rule engines for re-evaluation after a state change).
- **`NF_STOP`** remains in the UAPI for compatibility but is deprecated; treat it as historical, not something new code should return.

The verdict can also pack additional data — for `NF_QUEUE`, the queue number; for `NF_DROP`, an errno. The high bits of the return value carry these; `NF_VERDICT_BITS` masks them.

## Who registers what

You can see all hooks in a netns via:

```bash
sudo nft list hooks
```

(Requires recent nftables.) Output looks like:

```
family ip {
    hook prerouting {
        +0010 ip_sabotage_in [nf_conntrack]
        -0100 ipv4_conntrack_in [nf_conntrack]
         ...
    }
    hook input {
         ...
    }
}
```

Each line: priority, function name, owning module. You'll typically see conntrack at low priorities, the filter chains at 0, and SNAT/DNAT around ±100.

## A concrete trace

For a forwarded TCP SYN to port 80 going through a NAT box:

1. **`ip_rcv`** is called. Calls `NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, ...)`.
   - `nf_conntrack_in` (priority -200): create or look up conntrack entry. State = NEW.
   - `nf_nat_ipv4_pre_routing` (priority -100): apply DNAT rule if any. Maybe rewrites dst from `1.2.3.4:80` to `10.0.0.5:8080`.
   - User filter at priority 0 (e.g., `nft add rule ip filter prerouting accept`).
   - All ACCEPT → `okfn = ip_rcv_finish`.
2. **`ip_rcv_finish`** does the routing lookup using the (now possibly rewritten) destination. Decides this packet goes to `10.0.0.5` via `eth1`.
3. **`ip_forward`** is called (since the packet is for someone else). `NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD, ...)`.
   - User filter at priority 0 (e.g., `iptables -A FORWARD -j ACCEPT`).
4. **`ip_output`** → `NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, ...)`.
   - `nf_nat_ipv4_out` (priority 100): apply SNAT/MASQUERADE if the NAT rule matched. Maybe rewrites src from `192.168.1.10` to the gateway's WAN IP.
   - All ACCEPT → packet leaves on `eth1`.

The conntrack entry created in step 1's PREROUTING is what links steps 1 and 4: the SNAT in step 4 mirrors the DNAT in step 1 so reply traffic comes back symmetrically.

## Today's experiment

```bash
# See registered hooks (modern nft only)
sudo nft list hooks ip

# Old way: per-table inspection
sudo iptables -L -n -v
sudo nft list ruleset

# Trace which hook fires when
sudo bpftrace -e 'fentry:nf_hook_slow {
  printf("hook %d pf %d\n", args->state->hook, args->state->pf);
}' &

ping -c 1 8.8.8.8
sudo killall bpftrace
```

You'll see PREROUTING, LOCAL_OUT, POSTROUTING, LOCAL_IN for the ICMP exchange.

### Add a hook of your own (via nft)

```bash
sudo nft add table inet test
sudo nft 'add chain inet test myinput { type filter hook input priority 0 ; policy accept ; }'
sudo nft add rule inet test myinput meta nftrace set 1
# Now any packet going through input gets nftrace logged
sudo nft monitor trace &
ping -c 1 8.8.8.8
```

You see each rule evaluation with the verdict.

### Drop a specific port and see it work

```bash
sudo nft add rule inet test myinput tcp dport 12345 drop
nc localhost 12345    # connection refused (port not open)
nc localhost 22       # works (different port)

# Cleanup
sudo nft delete table inet test
```

## What to read in the kernel

- **`net/netfilter/core.c:612`** — `nf_hook_slow`. The dispatcher. Read it end to end (~80 lines). Notice how it walks the per-hook list, dispatches each hook, and handles each verdict (especially `NF_QUEUE`'s userspace round-trip).

- **`net/netfilter/core.c:550`** — `nf_register_net_hook`. The registration function. How a module (nftables, conntrack, IPVS) plants its hook callback. Note the per-priority insertion (sorted insertion).

- **`include/linux/netfilter.h`** — `NF_HOOK` macro and friends. `NF_HOOK` is conditional on the `nf_hooks_needed[pf][hook]` static key; if no hooks, it skips the call entirely. This is the zero-cost-when-unused machinery.

- **`include/uapi/linux/netfilter.h`** — verdicts, hook IDs, and `enum nf_inet_hooks`. The vocabulary file.

- **`net/ipv4/netfilter/ip_tables.c`** — legacy iptables backend. Read the top to see how `xt_table_info` (the rule storage) is consulted; rules are linear, walked top-to-bottom per packet. Compare to nftables (next day), which evaluates compact expression sequences through `nft_do_chain`.

- **`net/netfilter/nf_tables_core.c`** — modern nftables runtime. The expression interpreter. Read this *after* tomorrow's nftables intro.

- **`net/netfilter/nf_conntrack_core.c`** — conntrack registers at PRE_ROUTING and LOCAL_OUT (the two "first sight" hooks). Day 22 covers this.

- **`Documentation/networking/netfilter-sysctl.rst`** — netfilter sysctl knobs (the closest in-tree netfilter doc; there is no hook-diagram text file). See also `nf_conntrack-sysctl.rst` and `nf_flowtable.rst`.

- **External: nftables wiki** at https://wiki.nftables.org — has nice diagrams of where each hook fires.

## Bullet Points

- **Five IPv4 hooks**: PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING. Same five for IPv6.
- **PREROUTING** = before routing (DNAT here); **POSTROUTING** = after routing (SNAT here).
- Each hook has a per-netns list of callbacks ordered by priority.
- Verdicts: **ACCEPT, DROP, STOLEN, QUEUE, REPEAT**; **STOP** is deprecated UAPI compatibility.
- `nf_hook_slow` is the dispatcher; `NF_HOOK` macro inlines to zero overhead when no hooks registered.
- iptables, nftables, conntrack, IPVS — **all** plug into the same hook system at different priorities.
- Inspect with `nft list hooks` (modern) or `iptables -L -v` (legacy).

## Check question

When you write `iptables -A INPUT ...`, which kernel hook does the rule actually attach to, and at what priority?

<details>
<summary>Click to reveal answer</summary>

**Answer:** **`NF_INET_LOCAL_IN`**, priority **0** (`NF_IP_PRI_FILTER`). The `INPUT` chain in iptables/nftables corresponds 1:1 with `LOCAL_IN` — the kernel hook that fires after routing has determined the packet is for a local socket. The priority is `NF_IP_PRI_FILTER = 0`, which puts user filter rules *after* conntrack (`NF_IP_PRI_CONNTRACK = -200`) but *before* anything at higher priority. Other iptables chains map similarly: `OUTPUT` → `LOCAL_OUT`, `FORWARD` → `FORWARD`, `PREROUTING` → `PRE_ROUTING`, `POSTROUTING` → `POST_ROUTING`. The names line up almost identically with the kernel's hook IDs because iptables was *designed* to expose them.

</details>

---

## Tomorrow

Day 21: nftables vs iptables. Why nftables exists, what it does better, and how to convert legacy iptables rules.
