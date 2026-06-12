# Day 7 — ARP and the `neighbour` subsystem

> **Today's mission:** see how Linux learns its peers' MAC addresses, the state machine an ARP entry walks through, and what happens at scale. Total time: ~75 minutes.

## ARP in one paragraph

When Linux wants to send an IP packet to some next-hop IP on a directly connected network, it needs the destination's MAC. The protocol is **ARP** (RFC 826): broadcast a query, receive a reply, cache the result. The cache is what `ip neigh` shows.

But "ARP" in Linux is a specific case of a more general **neighbour subsystem** at `net/core/neighbour.c`. The same code handles IPv6 NDP (Neighbour Discovery Protocol) and InfiniBand IPoIB. The L4-protocol-specific bits live in `net/ipv4/arp.c`.

## The neighbour table

![ARP table](diagrams/day07_arp_table.png)

`struct neigh_table arp_tbl` (`net/ipv4/arp.c:152`) holds all IPv4 neighbour entries. Each entry is a `struct neighbour` (`include/net/neighbour.h:140`) with:

- `primary_key`: the IP address.
- `ha[MAX_ADDR_LEN]`: hardware address (MAC).
- `dev`: which netdev this neighbour is reachable through.
- `nud_state`: state machine (REACHABLE, STALE, INCOMPLETE, ...).
- `confirmed`: jiffies of last confirmed reachability.
- `arp_queue`: skbs waiting for resolution.

## The state machine

![NUD states](diagrams/day07_neigh_states.png)

A neighbour entry walks through states:

- **NONE** — newly created, no resolution attempted yet.
- **INCOMPLETE** — ARP request sent, waiting for reply. Skbs going to this neighbour queue here.
- **REACHABLE** — fresh, recent confirmation (default `reachable_time = 30s`).
- **STALE** — has MAC but old. Next packet triggers a confirmation probe.
- **DELAY** — sent a packet expecting the L4 to confirm reachability quickly.
- **PROBE** — actively probing via ARP.
- **FAILED** — ARP timed out. Probe limits are state-dependent: INCOMPLETE resolution allows up to 6 probes (3 multicast + 3 unicast), PROBE state up to 3 (unicast only), each spaced by `retrans_time` (1s default).

The state machine is the canonical answer to "why does my first ping take 1ms longer than subsequent ones?" — first packet goes through INCOMPLETE → REACHABLE; later packets hit a cached entry directly.

## Lookup on TX

![lookup flow](diagrams/day07_neigh_lookup.png)

When `ip_finish_output2` needs the next-hop's MAC, it calls into `neigh_lookup` → `__neigh_create` if not found. If the entry is INCOMPLETE, the skb is queued on `arp_queue` and the kernel sends an ARP request. When the reply arrives, the queue flushes and the queued skbs are sent.

If the lookup hits FAILED, the skb is dropped and the kernel may send an ICMP "Destination Host Unreachable" back to the source.

> ### There are no Dumb Questions
>
> **Q: What is "gratuitous ARP"?**
>
> A: A node announcing its MAC unsolicited (e.g., on interface up, or after a failover). Linux sends one as an `arp_send(ARPOP_REQUEST, ETH_P_ARP, ...)` with target IP == source IP, from `inetdev_send_gratuitous_arp` in `net/ipv4/devinet.c`. It updates other nodes' caches without them having to ask.
>
> **Q: What's `arp_announce` for?**
>
> A: Sysctl that controls *which* IP the kernel uses as source for ARP requests. Default 0 (any local IP); 1 prefers same-subnet; 2 always uses the primary IP of the egress interface. Important for multi-homed servers.
>
> **Q: Why are there gc_thresh1/2/3?**
>
> A: gc_thresh3 is a hard cap; new ARP attempts beyond it fail. Heavy-traffic gateways routinely hit the default 1024 — symptom: `neighbor table overflow!` in dmesg. Bump via sysctl.

## Today's experiment

> **Before you start:** the commands below use `eth0` and the gateway `192.168.1.1` as examples. Replace them with *your* interface and default gateway — derive both from `ip route show default`:
>
> ```bash
> IFACE=$(ip route show default | awk '{print $5; exit}')
> GW=$(ip route show default | awk '{print $3; exit}')
> echo "iface=$IFACE gateway=$GW"
> # iface=eth0 gateway=10.0.0.1
> ```
>
> Run verbatim against a machine whose interface is `ens3`/`enp0s3` or whose gateway is different, and `ip neigh flush dev eth0` fails with "Cannot find device" and `ping 192.168.1.1` goes nowhere. Substitute `$IFACE`/`$GW` (or your real values) wherever you see `eth0`/`192.168.1.1` below.

### See your ARP table

```bash
ip neigh show
# 192.168.1.1 dev eth0 lladdr aa:bb:cc:11:22:33 REACHABLE
# 192.168.1.20 dev eth0 lladdr aa:bb:cc:44:55:66 STALE
```

### Force an ARP from scratch

```bash
sudo ip neigh flush dev eth0
ping -c 1 192.168.1.1
ip neigh show
# entry now REACHABLE
```

### Watch ARP packets

```bash
sudo tcpdump -i eth0 -n arp -e &
sudo ip neigh flush dev eth0
ping -c 1 192.168.1.1
sudo pkill tcpdump   # stop the background capture
```

You'll see the ARP request (broadcast) and reply (unicast). The `pkill` is essential: a backgrounded `tcpdump` with no count/timeout otherwise runs forever, spamming your terminal with every later ARP on the link.

### Trace neighbour state changes

```bash
sudo bpftrace -e '
fentry:neigh_update {
  printf("update: state=%d new_state=%d\n",
         args->neigh->nud_state, args->new);
}'
```

The numbers are NUD bitmask values (`include/uapi/linux/neighbour.h`): `1`=INCOMPLETE, `2`=REACHABLE, `4`=STALE, `8`=DELAY, `16`=PROBE, `32`=FAILED. In another terminal, flush and re-ping the gateway to drive transitions. A fresh resolution fires several `neigh_update` calls, so you'll see lines like:

```
# update: state=1 new_state=2   (INCOMPLETE -> REACHABLE, first resolution)
# update: state=4 new_state=8   (STALE -> DELAY, a packet hits an aged entry)
```

These tie directly back to the state machine at the top of the chapter. (Swap `%d` for `%x` in the `printf` if you'd rather see the raw hex `#define` values.)

### Probe gc thresholds

```bash
sysctl net.ipv4.neigh.default.gc_thresh1   # default 128
sysctl net.ipv4.neigh.default.gc_thresh2   # default 512
sysctl net.ipv4.neigh.default.gc_thresh3   # default 1024

# bump for high-fanout servers:
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=8192

# restore the default when you're done (this change is non-persistent —
# it's lost on reboot and not written to sysctl.conf):
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=1024
```

## What to break

### Statically pin a wrong MAC

> **Warning:** do **not** pin a wrong MAC for the gateway on the interface you're SSH-ing in over — it drops your session before you can run the undo, locking you out. Pin a non-gateway LAN peer instead, or run this from the local console.

```bash
sudo ip neigh add 192.168.1.1 lladdr aa:bb:cc:00:00:00 dev eth0 nud permanent
ping -c 3 -W 1 192.168.1.1   # no replies — packets sent to a MAC nobody owns

# undo:
sudo ip neigh del 192.168.1.1 dev eth0
```

This shows the cache is authoritative until the kernel re-resolves. The `-c 3 -W 1` is important: a bare `ping` runs until you Ctrl-C, and until you do, the `del` line never executes and the entry stays poisoned.

### Watch FAILED state

To actually watch INCOMPLETE → FAILED you must (a) target an address that is *directly connected* — pick an **unused** IP inside your `eth0` subnet, not an off-subnet one like `10.99.99.99` (those route via the gateway, so the kernel never ARPs for them) — and (b) send real traffic to kick off resolution. Note too that a bare `ip neigh add IP dev eth0` with no `lladdr`/`nud` is rejected by modern iproute2 ("No link layer address given") and creates no entry at all.

```bash
# pick an unused IP in your eth0 subnet, e.g. 192.168.1.250
sudo ip neigh flush 192.168.1.250 dev eth0 2>/dev/null
ping -c1 -W1 192.168.1.250 || true   # queues a packet -> kernel starts ARPing
sleep 8                              # past 3 multicast probes @ retrans_time 1s
ip neigh show 192.168.1.250
# 192.168.1.250 dev eth0  FAILED     (briefly INCOMPLETE first)
sudo ip neigh del 192.168.1.250 dev eth0   # cleanup
```

---

## What to read in the kernel

- **`net/core/neighbour.c`** — the generic subsystem. Read `neigh_lookup` (line 625), `___neigh_create` (line 646), `neigh_update`, `neigh_timer_handler` (the state machine).
- **`net/ipv4/arp.c`** — ARP-specific protocol. `arp_rcv`, `arp_send`, `arp_solicit`. ~1500 lines.
- **`include/net/neighbour.h`** — `struct neighbour` (line 140), the NUD_* state constants.
- **`Documentation/networking/ip-sysctl.rst`** — the `neigh.*` sysctls (gc thresholds, probe counts, timers); pair it with the source itself.

---

## Bullet Points

- The neighbour subsystem (ARP for IPv4, NDP for IPv6) lives at `net/core/neighbour.c`.
- Entries cycle through **NONE → INCOMPLETE → REACHABLE → STALE → DELAY → PROBE → REACHABLE/FAILED**.
- TX-side lookup is via **`neigh_lookup`** in `ip_finish_output2`.
- Skbs queue on `arp_queue` while a neighbour is INCOMPLETE.
- **GC thresholds** (`gc_thresh1/2/3`) cap entry count; default 128/512/1024.
- Inspect: `ip neigh show`. Manipulate: `ip neigh add/del/replace`.
- **Gratuitous ARP** announces MAC changes (e.g., failover).

---

## Check question

You set `net.ipv4.neigh.default.gc_thresh3=128` on a server with 500 active client peers. What symptoms appear?

<details>
<summary>Click to reveal answer</summary>

**Answer:** `neighbor table overflow!` messages in `dmesg`. New connections to peers whose ARP entries got evicted will hang briefly while ARP re-resolves; if entries are evicted faster than they're re-resolved, traffic stalls. The fix is to raise `gc_thresh3` (and `gc_thresh1/2` proportionally — typically 4096/8192/16384 for a busy server). The kernel doesn't drop packets directly because of this; it just refuses to create new entries, which manifests as resolution failures.

</details>

---

## Tomorrow

Day 8: IP routing — the FIB. How the kernel decides where to send a packet, and why route lookups are so cheap on modern hardware.
