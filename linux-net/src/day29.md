# Day 29 — Recent additions: PSP, drop_monitor, devlink, NETLINK YAML

> **Today's mission:** know what's new in the network stack as of kernel 7.1, what each of these subsystems is *for*, and where they fit alongside what you've already learned. Total time: ~75 minutes.

## PSP — Packet Security Protocol

A datacenter-scale L4 encryption protocol developed by Google, contributed to Linux in 2025 (in-tree by 7.x).

- **What:** symmetric authenticated encryption applied to L4 packets (UDP or TCP). Per-flow keys, designed for hardware offload (NICs with PSP-aware crypto).
- **Why:** datacenter operators want confidentiality and integrity on internal traffic without IPsec's complexity (IKE, SA database, kernel SADB) or TLS's per-connection handshake. PSP is lightweight: per-flow shared secret negotiated out of band, then plain symmetric crypto on every packet.
- **When:** datacenter East-West traffic between trusted hosts running compatible PSP stacks. Not for internet-facing.
- **Where:** **`net/psp/`** — `psp_main.c` (registration), `psp_sock.c` (socket integration), `psp_nl.c` (netlink config interface), `psp.h` (UAPI).
- **Status:** in-tree but new; tooling (`ip psp ...` via iproute2) is being established. Practical use is mostly inside Google for now; broader adoption pending.

## drop_monitor + `kfree_skb_reason`

Observability infrastructure for "where do packets get dropped?"

`net/core/drop_monitor.c`. Listens on the `skb:kfree_skb` tracepoint and aggregates by drop reason + location. Combined with `kfree_skb_reason` (Day 1), gives you a categorized dropwatch.

**The `kfree_skb_reason` API:**

```c
kfree_skb_reason(skb, SKB_DROP_REASON_TCP_INVALID_SEQUENCE);
```

Replaces the older `kfree_skb(skb)`. The reason is one of ~150 categories defined in `include/net/dropreason-core.h`:

```c
enum skb_drop_reason {
    SKB_DROP_REASON_NOT_SPECIFIED,        // legacy callers
    SKB_DROP_REASON_NO_SOCKET,             // no listener
    SKB_DROP_REASON_PKT_TOO_SMALL,         // truncated
    SKB_DROP_REASON_TCP_CSUM,              // bad TCP checksum
    SKB_DROP_REASON_SOCKET_FILTER,         // BPF socket filter dropped
    SKB_DROP_REASON_UDP_CSUM,
    SKB_DROP_REASON_NETFILTER_DROP,        // iptables/nftables rule
    SKB_DROP_REASON_TC_INGRESS,
    /* ... 150+ more ... */
};
```

**Why the change:** old `kfree_skb` gave no signal beyond "a packet died here." With reasons, dropwatch tells you `SOCKET_FILTER` (a BPF filter dropped) vs `NETFILTER_DROP` (a firewall rule did) vs `IP_INHDR_INVALID` (the packet was malformed). Differentiating those is the difference between "fix my firewall rules" and "fix my broken sender."

**Inspect drops:**

```bash
# Live event stream with reasons
sudo perf trace --no-syscalls -e skb:kfree_skb 2>&1 | head -50

# Or dropwatch
sudo dropwatch -l kw       # 'kw' = kallsyms based
> start
# (see drops with location and reason)
> stop

# Aggregate by reason
sudo perf trace --no-syscalls -e skb:kfree_skb 2>&1 | awk '{print $NF}' | sort | uniq -c | sort -rn | head
```

**Adopting `kfree_skb_reason`** is an ongoing kernel project. Many call sites still use plain `kfree_skb`; new code is expected to use `_reason`.

## devlink — generic device control

`net/devlink/`. A netlink-based generic interface for device-level configuration that doesn't fit ethtool.

What ethtool does: per-NIC counters, ring sizes, offload flags. It's been growing for years and getting sloppy at the edges.

What devlink does: more abstract device knobs.
- **SR-IOV management**: configure virtual functions, switchdev mode, port representors.
- **Health reporting**: hardware/firmware telemetry, recovery actions.
- **Resource control**: device-internal table sizes (bridge FDB, IPv4 routes, ACLs).
- **DPLL** (Digital PLL): time-synchronization for 5G and HFT applications.
- **Per-port congestion-control profiles**: configure NIC-level CC behavior.

Tools: `devlink dev show`, `devlink port show`, `devlink dev info`, `devlink resource show`. The `iproute2` package ships the `devlink` binary.

```bash
devlink dev show
devlink dev info pci/0000:01:00.0
devlink resource show pci/0000:01:00.0
```

devlink is **driver-specific** — each driver opts in by registering its capabilities. mlx5, ice (Intel), nfp (Netronome) have rich devlink support; many older drivers don't.

## NETLINK YAML and libynl

Netlink is the kernel's preferred control-plane protocol — `ip`, `ss`, `nft`, `tc`, all of devlink, and most modern subsystems use it. Adding new netlink ops historically required:

1. Define the protocol's UAPI structs/enums.
2. Implement the kernel-side handler.
3. Write the userspace parsing/formatting code (often in libnl, iproute2, or a custom binding).

The third step was the bottleneck — every binding had to be written by hand for every new netlink subsystem. So the kernel community now writes netlink protocols as **YAML specifications**, and tooling auto-generates bindings.

The YAML specs live at `Documentation/netlink/specs/`:

```
Documentation/netlink/specs/
├── conntrack.yaml
├── devlink.yaml
├── dpll.yaml
├── ethtool.yaml
├── handshake.yaml
├── psp.yaml         # PSP's spec
└── ...
```

Each spec describes the protocol's messages, attributes, types. From these, tools generate:

- C bindings for the kernel side (in `net/.../netlink_gen.c`).
- Python bindings (`tools/net/ynl/pyynl/`).
- C library code (`tools/net/ynl/lib/`).
- Test scaffolding.

The generator is `tools/net/ynl/`. Adding a new netlink protocol is now: write the YAML, run the generator, implement only the actual logic.

**Practical impact:** new features land with bindings on day one. Less drift between kernel UAPI and userspace tooling.

## Other 2024–2026 highlights

A grab bag of features that aren't dedicated days but matter:

### Resilient nexthop groups (Day 9)

ECMP that survives nexthop changes without re-hashing every flow.

### tcx and netkit (Days 17 of eBPF book / 16-17 of network book)

Modern tc-bpf attach with `bpf_link` lifecycle and link-based multi-program ordering. Replaces classic `tc filter add bpf` for new code.

### bigtcp

TCP segments larger than 64 KB on the local stack (up to 4 MB). Useful for very fast NICs (200/400 Gbps) where the per-segment overhead becomes the bottleneck. Configurable via `ip link set <dev> gso_max_size <bytes>` and matching `gro_max_size`.

### Page Pool memory provider

Improved zero-copy receive (in progress). Lets receivers get packet payloads without copying from kernel page-cache pages. Integrated with io_uring's zero-copy recv work.

### net_iov and skb fragments

Unifies the "skb frags hold pages" model with io_uring's iovec model. Gives a single representation that both kernel networking and io_uring's I/O batching can use. Reduces translation overhead.

### Smart NIC offload progress

Per-flow TLS offload (Day 25) is well-established. Inline IPsec offload landed in 2024. Per-flow QoS offload (some NICs support arbitrary classification rules) keeps maturing.

## Today's experiment

```bash
# See drops with reasons (live)
sudo perf trace --no-syscalls -e skb:kfree_skb 2>&1 | head -20

# Probe devlink
which devlink && devlink dev show

# Look at YAML netlink specs
ls Documentation/netlink/specs/    # in the kernel tree

# Try a YAML-generated python tool
cd tools/net/ynl
python3 ./pyynl/cli.py --spec ../../../Documentation/netlink/specs/devlink.yaml \
    --do dev-get --json '{}' 2>&1 | head     # may need root
```

## What to read in the kernel

- **`net/psp/`** — PSP. Read `psp_main.c` first (~300 lines) for the registration model, then `psp_sock.c` for the socket-side integration.

- **`include/net/dropreason-core.h`** — the `enum skb_drop_reason` list. Skim. Tells you what categories of drops dropwatch can report.

- **`net/core/drop_monitor.c`** — the drop-monitor implementation. Read `trace_drop_common` to see how the tracepoint is dispatched to userspace via netlink.

- **`net/devlink/`** — devlink core. ~10000 lines across multiple files. Read `core.c` for the registration model, `dev.c` for device lifecycle, `health.c` for the health-reporter framework.

- **`Documentation/netlink/specs/`** — the YAML protocol specs. Open `devlink.yaml` or `ethtool.yaml`; the structure is self-descriptive.

- **`tools/net/ynl/`** — the YAML processing toolchain. `pyynl/cli.py` is a runnable example.

- **`Documentation/networking/devlink/`** — devlink user-facing docs. Subsystem-specific writeups.

- **External:** the netdev mailing list (`netdev@vger.kernel.org`) is where these things land. Subscribe if you want to track future features in real time.

## Bullet Points

- **PSP** — Google's lightweight datacenter L4 encryption. In-tree 7.x; `net/psp/`.
- **`kfree_skb_reason` + drop_monitor** — categorized drop attribution. Replace `kfree_skb` in new code.
- **devlink** — netlink-based generic device control. Replaces ad-hoc ethtool extensions for SR-IOV, DPLL, health reporting, resource control.
- **NETLINK YAML** + **libynl** (`tools/net/ynl/`) — YAML-driven binding generation. New protocols ship with bindings.
- **bigtcp** — segments > 64 KB locally for very fast NICs.
- **Resilient nexthop groups** — ECMP without re-hash on nexthop change (Day 9).
- **tcx + netkit** — modern tc-bpf with link-based lifecycle.

## Check question

Why is `kfree_skb_reason` strictly better than `kfree_skb` in new code, and what infrastructure depends on it?

<details>
<summary>Click to reveal answer</summary>

**Answer:** It feeds the drop monitor with a *category* enum, making "where do my drops come from?" answerable. Plain `kfree_skb` just disposes of the skb; `kfree_skb_reason(skb, SKB_DROP_REASON_X)` does the same plus emits a tracepoint `skb:kfree_skb` whose payload includes the reason. Tools that depend on this:

- **`dropwatch`** aggregates drops by category and source location, reporting top contributors over time.
- **`perf trace --no-syscalls -e skb:kfree_skb`** prints each drop with the category in real time.
- **eBPF programs** can attach to the tracepoint (e.g., `tracepoint:skb:kfree_skb`) and apply custom aggregation.

Without `_reason`, you can still see *that* a drop happened (the tracepoint fires for plain `kfree_skb` too) but you can't tell *why* — and the most common reason of all becomes `SKB_DROP_REASON_NOT_SPECIFIED`, which is useless for diagnosis.

In a kernel with full `_reason` adoption, you can do meaningful "why are my packets being dropped?" analysis without strace, ftrace, or guesswork. The conversion of every legacy `kfree_skb` call site is an ongoing project; new code is required to use the reason'd variant.

</details>

---

## Tomorrow

Day 30: capstone — pick a real packet and trace it end to end through every kernel layer you've learned.
