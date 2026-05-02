# Day 9 — Multipath, policy routing, source-based routing

> **Today's mission:** route packets based on something *other* than destination IP. Use multiple FIB tables. Configure ECMP. Total time: ~75 minutes.

## When destination-based routing isn't enough

Yesterday's lookup was destination-based: given the daddr, pick a next-hop. That's enough for 95% of routing. The other 5% needs more:

- **Source-based**: traffic from `10.0.0.0/24` should go through gateway A; everyone else through B.
- **Mark-based**: traffic with `fwmark 100` (set by netfilter) routes via VPN.
- **Multipath**: spread connections across multiple gateways.
- **Policy**: separate routing tables per VPN customer in a multi-tenant box.

## fib_rules: which table to consult

![fib_rules](diagrams/day09_rules.png)

Each rule is a predicate + table reference. `ip rule show` lists them, ordered by priority. The kernel walks them top-to-bottom; first match decides which table to look up in.

The default rules are minimal:
```
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
```

You add custom rules between these.

```bash
# Source-based:
sudo ip rule add from 10.99.0.0/24 lookup 100 priority 100
sudo ip route add default via 192.168.99.1 table 100
# now 10.99.0.x traffic goes via 192.168.99.1; everyone else uses main.

# Mark-based:
sudo ip rule add fwmark 0x42 lookup 200 priority 200
sudo ip route add default via 192.168.42.1 table 200
# nftables/iptables can mark packets and they get routed differently.

# OIF-based:
sudo ip rule add iif eth1 lookup 300 priority 300
```

Selectors include: `from`, `to`, `iif`, `oif`, `tos`, `fwmark`, `uidrange`, `ipproto`, `sport`, `dport`.

## ECMP — multiple next-hops to one destination

![ECMP](diagrams/day09_ecmp.png)

```bash
sudo ip route add default \
    nexthop via 192.168.1.1 weight 1 \
    nexthop via 192.168.2.1 weight 1
```

Per new flow, the kernel hashes 5-tuple (or 3-tuple, depending on `fib_multipath_hash_policy`) and picks one nexthop. Same flow → same nexthop (no reordering). Different flows → spread.

**Resilient nexthop groups** (added 2021) avoid the "removing a nexthop re-hashes everything" problem:

```bash
sudo ip nexthop add id 10 via 192.168.1.1 dev eth0
sudo ip nexthop add id 20 via 192.168.2.1 dev eth0
sudo ip nexthop add id 100 group 10/20 type resilient buckets 65536
sudo ip route add default nhid 100
```

Removing nexthop 10 only affects flows that were hashing into it.

## Today's experiment

```bash
# Source-based test
sudo ip route add 10.99.0.0/24 dev lo
sudo ip rule add from 10.99.0.0/24 lookup 99
sudo ip route add default via 127.0.0.1 table 99

# Trace
sudo bpftrace -e 'fentry:fib_table_lookup { printf("table_id=%d\n", args->tb->tb_id); }' &
ping -I 10.99.0.5 -c 1 8.8.8.8
```

You should see `table_id=99` (your custom table) when the source matches the rule.

## Bullet Points

- **`fib_rules`** chains decide which routing table to consult based on packet attributes.
- Default rules: `local → main → default`.
- Custom rules pivot on src, mark, OIF, IIF, etc.
- **ECMP** spreads flows across multiple nexthops; per-flow stickiness via 5-tuple hash.
- **Resilient nexthop groups** localize impact when a nexthop fails.
- Configure with `ip rule add/del/show` and `ip route add ... table N`.

## Check question

You add `ip rule add from 192.168.1.0/24 lookup 100 priority 50` and `ip rule add fwmark 0x42 lookup 200 priority 100`. A packet has src 192.168.1.5 AND fwmark 0x42. Which table is consulted?

.  
.  
.

**Answer:** Table 100. Rules are walked in priority order; the lower number is checked first. The packet matches the priority-50 rule (`from 192.168.1.0/24`), the lookup happens against table 100, and rule walking stops.

## Tomorrow

Day 10: IPv6 specifics — NDP, autoconfig, extension headers.
