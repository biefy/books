# Day 10 — IPv6 specifics: NDP, autoconfig, extension headers

> **Today's mission:** see what's different about IPv6 from IPv4 — the autoconfig flow, the neighbor discovery protocol, and the extension header chain that's caused real CVEs. Total time: ~75 minutes.

## Why IPv6 deserves its own day

Most of the kernel network stack is shared between IPv4 and IPv6 (sockets, routing infrastructure, netfilter). But IPv6 has three distinctive features that don't exist (or work differently) in IPv4:

1. **Autoconfiguration** — interfaces self-configure via Router Advertisements.
2. **NDP** — replaces ARP, runs over ICMPv6.
3. **Extension headers** — chained between IPv6 base header and L4.

## Autoconfiguration

![IPv6 autoconfig](diagrams/day10_ipv6_autoconf.png)

When IPv6 is enabled on an interface:

1. Kernel auto-assigns a **link-local** address (`fe80::/64`), derived from MAC (EUI-64) or random (`stable_secret`).
2. **Duplicate Address Detection** (DAD) — sends a Neighbor Solicitation for its own address. If anyone replies, the address is in use.
3. Listens for **Router Advertisements** (RAs). RAs come from local routers via ICMPv6 type 134.
4. RA carries flags: M (Managed), A (Autonomous). If A=1, **SLAAC** auto-generates a global address from the announced prefix. If M=1, kernel may also do DHCPv6.

Result: IPv6 interfaces "just work" without DHCP server in many cases.

## NDP — Neighbor Discovery Protocol

NDP replaces ARP on IPv6. Same machinery (the `neighbour` subsystem from Day 7), different protocol:

- **Neighbor Solicitation** (type 135) ≈ ARP request.
- **Neighbor Advertisement** (type 136) ≈ ARP reply.
- **Router Solicitation** (type 133), **Router Advertisement** (type 134) — IPv6-specific.

The neighbour table is `nd_tbl` (in `net/ipv6/ndisc.c`) — same `struct neigh_table` as `arp_tbl` from Day 7, just different protocol callbacks. Same NUD state machine.

## Extension headers

![IPv6 ext headers](diagrams/day10_ext_hdrs.png)

IPv6 base header has a `nexthdr` field. Instead of jumping straight to TCP/UDP, you can chain:

- **Hop-by-hop options** (0) — processed by every router on the path.
- **Routing** (43) — Source Routing Header (SRv6), RPL.
- **Fragment** (44) — IPv6 fragmentation.
- **Destination options** (60) — end-host options.
- **AH/ESP** (51/50) — IPsec.

Each extension has its own `nexthdr` field; you walk the chain via `ipv6_skip_exthdr`. The terminal `nexthdr` is the L4 protocol.

These chains are **bug-fertile**. Recent kernel CVEs:
- **2024**: SRv6 OOB write in `ipv6_rpl_srh_rcv` (kernel 7.0 fix `9e6bf146b559`).
- Repeated headroom-vs-mac_len bugs in tunnels.

## Today's experiment

```bash
# See your IPv6 addresses
ip -6 addr show

# Force a router solicitation
sudo ip -6 route add ::/0 via fe80::1 dev eth0  # if router not seen
sudo sysctl -w net.ipv6.conf.eth0.accept_ra=2   # accept RAs even if forwarding

# Watch NDP traffic
sudo tcpdump -i eth0 -n icmp6
```

Trace ext header parsing:
```bash
sudo bpftrace -e 'fentry:ipv6_skip_exthdr { printf("skip nexthdr=%d\n", args->nexthdr); }'
```

## What to read in the kernel

- **`net/ipv6/addrconf.c`** — autoconf, DAD, SLAAC.
- **`net/ipv6/ndisc.c`** — NDP. `ndisc_recv_ns`, `ndisc_recv_na`, `nd_tbl`.
- **`net/ipv6/exthdrs.c`** — extension header processing.
- **`net/ipv6/route.c`** — IPv6 routing (parallel to ipv4/route.c).

## Bullet Points

- IPv6 interfaces auto-configure via RAs (SLAAC) or DHCPv6.
- **NDP** (ICMPv6 types 133–136) replaces ARP.
- **Extension headers** chain after the base IPv6 header; walked by `ipv6_skip_exthdr`.
- The neighbour subsystem is shared with IPv4; just different protocol callbacks.
- Extension-header parsers have been a source of multiple CVEs; treat carefully.

## Check question

A node receives an IPv6 packet whose extension header chain ends in `nexthdr=0` (hop-by-hop options). What action is the kernel obligated to take?

.  
.  
.

**Answer:** Process the hop-by-hop options. Hop-by-hop is special — every router on the path must inspect it (unlike destination options, which only end-hosts process). Hop-by-hop after the base header is *required*; the kernel processes it via `ipv6_parse_hopopts`. If the option is unknown and has high-bit set in its type, the packet is silently dropped or ICMPv6 error is returned per the unknown-option-action bits.

## Tomorrow

Day 11: the bridge subsystem.
