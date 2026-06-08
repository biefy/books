# Day 8 — IP routing: the FIB

> **Today's mission:** see how Linux decides where to send a packet, what data structure powers route lookups, and why `ip route` shows what it shows. Total time: ~75 minutes.

## What "routing" means in Linux

Every packet that needs to go *somewhere not-here* requires a routing decision: which next-hop, which output interface, which source IP. The decision is fast — sub-microsecond on modern hardware, even against tables with hundreds of thousands of routes.

That speed comes from the **FIB** (Forwarding Information Base) and the **LC-trie** (level-compressed trie) data structure backing it.

## The lookup pipeline

![Route lookup](diagrams/day08_route_lookup.png)

For an incoming packet, `ip_rcv_finish` (via `ip_rcv_finish_core`) first checks whether the skb already has a dst attached (`skb_valid_dst` → fast path). If not, it calls `ip_route_input_noref` (`net/ipv4/route.c:2546`) which:

1. Calls `fib_lookup` → walks `fib_rules` to pick a table.
2. Calls `fib_table_lookup` (`net/ipv4/fib_trie.c:1420`) on that table — the LC-trie walk.
3. Builds an `rtable` (route entry) from the result, attaches it to the skb via `skb_dst_set`.

The skb's `dst->input` function pointer dispatches the next step:
- `ip_local_deliver` if the packet is for us.
- `ip_forward` if it's transit.
- `ip_error` for unreachable / TTL exceeded.

## Anatomy of a lookup

![FIB lookup](diagrams/day08_fib.png)

The lookup key is a `struct flowi4`:
```c
struct flowi4 {
    __be32  daddr;
    __be32  saddr;
    dscp_t  flowi4_dscp;
    __u32   flowi4_mark;
    int     flowi4_oif;
    int     flowi4_iif;
    __u8    flowi4_proto;
    /* ... ports, etc. */
};
```

The result is a `struct fib_result`:
```c
struct fib_result {
    __be32          prefix;
    unsigned char   prefixlen;
    unsigned char   nh_sel;
    unsigned char   type;       /* RTN_UNICAST, RTN_LOCAL, RTN_BROADCAST */
    struct fib_nh_common *nhc;  /* next-hop info */
    struct fib_info *fi;
    struct fib_table *table;
};
```

The interesting field is `nhc` — the next-hop. It tells you the egress device, the gateway IP (if any), the source IP to use, MTU, etc.

## LC-trie: why it's fast

The internet has ~1M IPv4 routes globally. A linear scan would be hopeless. A simple binary trie has 32 levels for IPv4 — too many memory accesses.

The **LC-trie** is a hybrid: it path-compresses (skip levels with one child) and level-compresses (use multi-bit nodes when density is high). On real internet routing tables, lookups average ~5–10 memory accesses regardless of table size.

Read `net/ipv4/fib_trie.c` if you want the gory details. The structure is well-commented.

## Multiple tables

Linux supports multiple routing tables. The defaults:

![FIB tables](diagrams/day08_tables.png)

- **local** (255) — IPs on local interfaces; kernel-maintained.
- **main** (254) — user-added routes go here by default.
- **default** (253) — lowest priority; rarely used.
- **custom** — created with `ip route add ... table N`. Small examples often use IDs below 253, but the kernel carries table IDs as `u32`; larger IDs travel through netlink attributes such as `RTA_TABLE`.

`fib_rules` decide *which* table to consult based on packet attributes: source IP, fwmark, OIF, IIF. Day 9 covers them.

> ### There are no Dumb Questions
>
> **Q: How does the kernel cache routes?**
>
> A: Modern Linux (since ~3.6) does NOT cache per-flow rtables. Instead, route lookups are cheap enough to do per-packet. The exception is per-CPU caches for outbound connect paths and the `dst_cache` mechanism that lwtunnels use. The pre-3.6 "rt_cache" was a security risk and is gone.
>
> **Q: Where does the kernel keep its own host IPs?**
>
> A: In the `local` FIB table (id 255). Kernel auto-inserts entries when interfaces get IPs assigned. `ip route show table local` lists them.
>
> **Q: How fast is a lookup, in practice?**
>
> A: ~50ns–150ns on modern x86_64 against a typical Linux server's small FIB. Internet routers with 1M routes see ~200–500ns per lookup, dominated by memory access patterns and cache effects.

## Today's experiment

### Inspect your routes

```bash
ip route show table main
ip route show table local
ip rule show
```

`ip rule` is the fib_rules list. Default has just three: local, main, default.

### Watch a route lookup

```bash
sudo bpftrace -e '
fentry:fib_table_lookup {
  printf("lookup daddr=%pI4 table_id=%d\n",
         &args->flp->daddr,
         args->tb->tb_id);
}'

# in another terminal:
ping -c 1 8.8.8.8
```

You'll see one fib_table_lookup per packet — for ICMP roundtrip, four lookups (request out, reply in for forwarding decision, etc.).

### Add a route

```bash
sudo ip route add 10.99.0.0/16 dev lo
ip route show

# remove:
sudo ip route del 10.99.0.0/16
```

### Trace `ip_route_output_flow`

```bash
sudo bpftrace -e '
fentry:ip_route_output_flow {
  printf("out: daddr=%pI4 oif=%d\n", &args->flp4->daddr, args->flp4->flowi4_oif);
}'
```

This is the outbound counterpart to `ip_route_input`.

## What to break

### Break a default route safely, inside a namespace

Do not replace your host's real default route. Put the failure in a disposable namespace:

```bash
sudo ip netns add fibbreak
sudo ip -n fibbreak link set lo up
sudo ip -n fibbreak route add default via 10.99.99.99 dev lo
sudo ip netns exec fibbreak ping -c 1 8.8.8.8   # fails inside the namespace only

sudo ip netns del fibbreak
```

The next-hop is unreachable, so the lookup succeeds but transmission cannot resolve a usable path. Your host routing table never changes.

### Inspect rt cache stats (legacy)

```bash
cat /proc/net/stat/rt_cache
```

Mostly zeros nowadays — the cache is gone, but the proc file remains for compatibility.

---

## What to read in the kernel

- **`net/ipv4/route.c`** — `ip_route_input_noref` (line 2546), `ip_route_output_flow` (line 2929).
- **`net/ipv4/fib_trie.c`** — `fib_table_lookup` (line 1420). The LC-trie implementation.
- **`net/ipv4/fib_frontend.c`** — netlink interface, `fib_lookup` wrapper.
- **`net/ipv4/fib_rules.c`** — fib_rules implementation.
- **`include/net/flow.h`** — `struct flowi4`.
- **`include/net/ip_fib.h`** — `struct fib_result`, `struct fib_nh_common`.
- **`Documentation/networking/fib_trie.rst`** — LC-trie internals; **`Documentation/networking/ip-sysctl.rst`** — routing-related sysctls.

---

## Bullet Points

- **FIB** is the kernel's routing table. Lookups happen via `fib_table_lookup` against an LC-trie.
- The lookup key is `struct flowi4`; the result is `struct fib_result`.
- Three well-known tables: **local (255)**, **main (254)**, **default (253)**. Custom table IDs are `u32`; low IDs are just convenient examples.
- **`fib_rules`** decide which table to consult; default rules just fall through local→main→default.
- No more flow-level rt_cache as of ~3.6 — lookups are cheap enough per-packet.
- The skb's `dst->input` function dispatches local-delivery vs forwarding.

---

## Check question

You add `ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0`. A packet with daddr `10.0.0.5` enters. Walk the lookup.

<details>
<summary>Click to reveal answer</summary>

**Answer:** `ip_rcv_finish` → `ip_route_input_noref` → `fib_lookup` walks rules; first match is the kernel's default `from all lookup main`. `fib_table_lookup(main, &flowi4)` walks the LC-trie, hits the `10.0.0.0/24` entry. `fib_result` has `prefix=10.0.0.0`, `prefixlen=24`, `nhc->nhc_gw.ipv4=192.168.1.1`, `nhc->nhc_dev=eth0`. The route is the gateway form, so the kernel knows to ARP for 192.168.1.1 (Day 7's neighbour subsystem) when transmitting. An rtable is built and attached to the skb; `dst->input = ip_forward` (assuming we're not 10.0.0.5 ourselves), and forwarding proceeds.

</details>

---

## Tomorrow

Day 9: multipath, policy routing, source-based routing. The fib_rules machinery gets serious.
