# Day 21 — nftables vs iptables

> **Today's mission:** know what's running on your system, write a basic nft ruleset, understand why nftables superseded iptables. Total time: ~75 minutes.

![nft vs ipt](diagrams/day21_nft_vs_ipt.png)

## The transition

iptables (2001) was the previous generation. Per-protocol tools (iptables, ip6tables, arptables, ebtables) and a linear matching engine. Modules per match type in `net/netfilter/ipt_*.c`.

**nftables** (2014, kernel 3.13) replaces all that with:
- Single tool (`nft`), single config syntax.
- Inet, ipv4, ipv6, arp, bridge tables — all under one umbrella.
- Native sets (hash, ranges, intervals).
- Bytecode VM that's JIT-compiled.
- Faster matching, smaller rule sets.

Most modern distros ship nftables by default. iptables compatibility is provided by `iptables-nft` (translates iptables commands to nftables internally).

## Basic nft

```bash
# Create table
sudo nft add table inet filter

# Add chains for each hook
sudo nft 'add chain inet filter input { type filter hook input priority 0 ; policy drop ; }'
sudo nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }'
sudo nft 'add chain inet filter output { type filter hook output priority 0 ; policy accept ; }'

# Allow established + related (conntrack-aware)
sudo nft add rule inet filter input ct state established,related accept

# Allow loopback
sudo nft add rule inet filter input iif lo accept

# Allow specific ports
sudo nft add rule inet filter input tcp dport { 22, 80, 443 } accept

# Show
sudo nft list ruleset
```

## Sets and maps

```bash
# Anonymous set inline:
sudo nft add rule inet filter input ip saddr { 10.0.0.1, 10.0.0.2 } accept

# Named set (mutable):
sudo nft add set inet filter blocked { type ipv4_addr \; }
sudo nft add element inet filter blocked { 1.2.3.4 }
sudo nft add rule inet filter input ip saddr @blocked drop

# Map (key → value):
sudo nft add map inet filter port_to_action { type inet_service : verdict \; }
sudo nft add element inet filter port_to_action { 22 : accept, 80 : accept, 443 : accept }
```

## What to read in the kernel

- **`net/netfilter/nf_tables_core.c`** — the bytecode VM.
- **`net/netfilter/nf_tables_api.c`** — netlink interface.
- **`net/netfilter/nft_*.c`** — individual expression types.
- `man nft`.

## Bullet Points

- nftables = modern; iptables = legacy.
- `nft list ruleset` for inspection.
- Native sets/maps make rule sets compact and fast.
- Hooks are the same as Day 20 (`type filter hook input priority 0`).
- iptables compatibility via `iptables-nft`.

## Check question

You write `nft add rule inet filter input tcp dport 22 accept` and `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` on the same system. Do they conflict?

.  
.  
.

**Answer:** Depends. If `iptables` is the iptables-nft compat tool, both end up as nftables rules in different tables (the compat tool uses a `mangle/filter/nat` table set; nft commands use whatever table you named). They coexist. If you have legacy iptables (xtables backend) running alongside nftables, both run independently against the same hook — order is determined by registration priority. To avoid surprises, pick one and stick with it.

## Tomorrow

Day 22: conntrack — stateful firewalls.
