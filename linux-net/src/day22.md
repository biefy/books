# Day 22 — Conntrack: stateful firewalls

> **Today's mission:** see how the kernel tracks connection state. Total time: ~75 minutes.

![conntrack](diagrams/day22_conntrack.png)

## What conntrack does

For every packet, the kernel hashes the 5-tuple (proto, src, dst, sport, dport) and looks up an existing **connection track** (`struct nf_conn`). If found, it tags the skb with the conntrack reference; the connection's state is updated. If not found, a new conntrack is created.

The state field (`enum ip_conntrack_info`) tells your firewall rules whether to treat the packet as new or part of an existing flow. This enables:

```bash
nft add rule inet filter input ct state established,related accept
```

— accept return traffic for connections we initiated, without enumerating every reverse flow.

## States

- **NEW** — first packet of a connection.
- **ESTABLISHED** — at least one packet seen in each direction.
- **RELATED** — child connection of an ESTABLISHED (e.g., FTP data channel, ICMP error referencing an established TCP).
- **INVALID** — doesn't match expectations (out-of-state TCP, malformed).
- **UNTRACKED** — opted out via `notrack`.

## Capacity

Conntrack is bounded:
- `net.netfilter.nf_conntrack_max` — total entries.
- `net.netfilter.nf_conntrack_buckets` — hash table size.

Heavy gateways set these to millions.

## Today's experiment

```bash
# Inspect conntrack entries
sudo conntrack -L

# Stats
sudo conntrack -S

# Live events
sudo conntrack -E

# Force a flow:
ping -c 5 8.8.8.8 &
sudo conntrack -L | grep 8.8.8.8
```

## What to read in the kernel

- **`net/netfilter/nf_conntrack_core.c`** — the core. ~3000 lines.
- **`net/netfilter/nf_conntrack_proto_*.c`** — per-protocol logic (TCP state machine, UDP timeouts).
- **`include/net/netfilter/nf_conntrack.h`** — `struct nf_conn`.

## Bullet Points

- **Conntrack** tracks connection state across packets.
- States: NEW, ESTABLISHED, RELATED, INVALID, UNTRACKED.
- Stateful firewall rules use `ct state` to filter.
- Capacity: `nf_conntrack_max` (global), `_buckets` (hash size).
- Conntrack inserts during PRE_ROUTING / LOCAL_OUT; confirms only on ACCEPT verdict.
- Per-cpu locks; high contention possible at very high pps.

## Check question

A SYN packet arrives, conntrack creates a NEW entry. Netfilter chains run; the rule says DROP. Does the conntrack entry persist?

<details>
<summary>Click to reveal answer</summary>

**Answer:** No. Conntrack entries are *created* in PRE_ROUTING but *confirmed* (inserted into the global hash) only when the packet completes the verdict pipeline with ACCEPT. If DROP, the unconfirmed entry is freed. This way a port-scanning probe doesn't fill up your conntrack table with NEW entries that never see a reply.

</details>

## Tomorrow

Day 23: traffic control / qdiscs.
