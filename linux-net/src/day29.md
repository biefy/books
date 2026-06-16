# Day 29 — Recent additions: PSP, drop_monitor, devlink, NETLINK YAML

> **Today's mission:** know what's new in the network stack as of kernel 7.1, what each of these subsystems is *for*, and where they fit alongside what you've already learned. Total time: ~75 minutes.

## PSP — Packet Security Protocol

A datacenter-scale L4 encryption protocol developed by Google, contributed to Linux in 2025 (in-tree by 7.x).

- **What:** symmetric authenticated encryption applied to L4 payloads inside a UDP encapsulation (`PSP_DEFAULT_UDP_PORT` 1000); the in-tree Linux socket integration upgrades TCP connections. Per-flow keys, designed for hardware offload (NICs with PSP-aware crypto).
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

Replaces the older `kfree_skb(skb)`. The reason is one of ~125 categories defined in `include/net/dropreason-core.h`:

```c
enum skb_drop_reason {     /* names real; order/values abridged for illustration */
    SKB_DROP_REASON_NOT_SPECIFIED,        // legacy callers
    SKB_DROP_REASON_NO_SOCKET,             // no listener
    SKB_DROP_REASON_PKT_TOO_SMALL,         // truncated
    SKB_DROP_REASON_TCP_CSUM,              // bad TCP checksum
    SKB_DROP_REASON_SOCKET_FILTER,         // BPF socket filter dropped
    SKB_DROP_REASON_UDP_CSUM,
    SKB_DROP_REASON_NETFILTER_DROP,        // iptables/nftables rule
    SKB_DROP_REASON_TC_INGRESS,
    /* ... ~115 more ... */
};
```

**Why the change:** old `kfree_skb` gave no signal beyond "a packet died here." With reasons, dropwatch tells you `SOCKET_FILTER` (a BPF filter dropped) vs `NETFILTER_DROP` (a firewall rule did) vs `IP_INHDR` (the packet was malformed). Differentiating those is the difference between "fix my firewall rules" and "fix my broken sender."

**Inspect drops:**

An idle box drops almost nothing, so provoke some `NO_SOCKET` drops first. In another terminal, hit a closed port a few times — each attempt is dropped with no listener:

```bash
for i in $(seq 1 50); do curl -s --max-time 1 http://localhost:1 >/dev/null; done
```

While that runs, watch the live event stream:

```bash
# Live event stream with reasons (timeout so it terminates cleanly)
sudo timeout 10 perf trace --no-syscalls -e skb:kfree_skb 2>&1 | head -50
```

Each line names the call site that freed the skb plus the reason category:

```
0.104 curl/506057 skb:kfree_skb(skbaddr: 0xffff..., location: 0xffff..., protocol: 2048, reason: SKB_DROP_REASON_NO_SOCKET)
```

`dropwatch` aggregates the same tracepoint by reason and location. It ships in its own `dropwatch` package (`apt install dropwatch` / `dnf install dropwatch`) — skip this block if it isn't installed:

```bash
sudo dropwatch -l kw       # 'kw' = kallsyms based
```

That drops you at dropwatch's interactive prompt (`dropwatch>`); type `start`, generate drops, then `stop`:

```
dropwatch> start
1 drops at tcp_v4_rcv+0x2a (SKB_DROP_REASON_NO_SOCKET)
dropwatch> stop
```

To aggregate reasons over a window, bound `perf trace` with `timeout` *before* the pipe — `perf trace` streams forever, and `sort`/`uniq` only print after the input stream ends, so they need a clean EOF:

```bash
# Aggregate by reason
sudo timeout 10 perf trace --no-syscalls -e skb:kfree_skb 2>&1 | awk '{print $NF}' | sort | uniq -c | sort -rn | head
```

With the closed-port loop running, `SKB_DROP_REASON_NO_SOCKET` dominates the histogram:

```
    160 SKB_DROP_REASON_NO_SOCKET)
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

Run `devlink dev show` first and copy one of the listed handles into the next two commands — `pci/0000:01:00.0` below is a placeholder that almost certainly won't match your NIC:

```bash
devlink dev show
# Substitute a handle from the line above, e.g.:
devlink dev info pci/0000:01:00.0
devlink resource show pci/0000:01:00.0
```

On virtio-net / `hv_netvsc` / most cloud-VM NICs `devlink dev show` prints **nothing** — those drivers don't register a devlink instance, so there is no handle to inspect. You need an mlx5 / ice / nfp device (some cloud VMs expose an mlx5 SR-IOV VF) to see real output. Even then `resource show` often returns `Operation not supported` — it's driver-specific (see below).

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

### tcx and netkit (Day 17 of eBPF book / Day 23 of network book)

Modern tc-bpf attach with `bpf_link` lifecycle and link-based multi-program ordering. Replaces classic `tc filter add bpf` for new code.

### bigtcp

TCP segments larger than 64 KB on the local stack (up to ~512 KB, `GSO_MAX_SIZE`). Useful for very fast NICs (200/400 Gbps) where the per-segment overhead becomes the bottleneck. Configurable via `ip link set <dev> gso_max_size <bytes>` and matching `gro_max_size`.

### Page Pool memory provider

Improved zero-copy receive (in progress). Lets receivers get packet payloads without copying from kernel page-cache pages. Integrated with io_uring's zero-copy recv work.

### net_iov and skb fragments

Unifies the "skb frags hold pages" model with io_uring's iovec model. Gives a single representation that both kernel networking and io_uring's I/O batching can use. Reduces translation overhead.

### Smart NIC offload progress

Per-flow TLS offload (Day 25) is well-established. Inline IPsec offload landed in 2024. Per-flow QoS offload (some NICs support arbitrary classification rules) keeps maturing.

## Today's experiment

First provoke some drops (idle boxes drop almost nothing), then watch them with reasons:

```bash
# Trigger NO_SOCKET drops in another terminal:
for i in $(seq 1 50); do curl -s --max-time 1 http://localhost:1 >/dev/null; done

# See drops with reasons (live; timeout so the pipe ends cleanly)
sudo timeout 10 perf trace --no-syscalls -e skb:kfree_skb 2>&1 | head -20
```

Each line names the kernel call site that freed the skb plus a drop-reason category (e.g. `SKB_DROP_REASON_NO_SOCKET`) when the disposal used `kfree_skb_reason`.

```bash
# Probe devlink
which devlink && devlink dev show
```

Prints one device handle per registered device — or nothing on virtio/cloud NICs that register no devlink instance.

```bash
# Look at the YAML netlink specs
cd ~/code/linux                    # your kernel source tree
ls Documentation/netlink/specs/
```

Lists the per-protocol `.yaml` spec files, including `devlink.yaml`, `ethtool.yaml`, and `psp.yaml`.

```bash
# Try a YAML-generated python tool. Install the ynl deps first:
pip install -r tools/net/ynl/requirements.txt   # or: pip install jsonschema pyyaml
cd tools/net/ynl
# ethtool's spec decodes cleanly against a stock NIC — dump the ring sizes:
python3 ./pyynl/cli.py --spec ../../../Documentation/netlink/specs/ethtool.yaml \
    --dump rings-get 2>&1 | head     # may need root
```

This prints a JSON object per interface — the kernel's ethtool ring config, fetched over netlink with zero hand-written C:

```
[{'header': {'dev-index': 2, 'dev-name': 'eth0'}, 'rx': 9362, 'rx-max': 18139, ...}]
```

Two gotchas worth knowing. **Op naming:** ops are `get`/`rings-get`, not `dev-get` — `--do dev-get` raises `KeyError: 'dev-get'`. Use `--dump <op>` (lists every instance, like `devlink dev show`) since the `--do` form needs a specific id. **Spec-vs-kernel skew:** the YAML specs track mainline, so dumping a spec whose attributes are newer/older than your running driver can raise `YnlException: Space '...' has no attribute with value 'N'` — e.g. `devlink.yaml --dump get` against an mlx5 device on this kernel. That's a spec/kernel version mismatch, not a bug in your invocation; the stabler specs like `ethtool.yaml` decode cleanly. Without the deps you'll instead see `ModuleNotFoundError: No module named 'jsonschema'`.

## What to read in the kernel

- **`net/psp/`** — PSP. Read `psp_main.c` first (~380 lines) for the registration model, then `psp_sock.c` for the socket-side integration.

- **`include/net/dropreason-core.h`** — the `enum skb_drop_reason` list. Skim. Tells you what categories of drops dropwatch can report.

- **`net/core/drop_monitor.c`** — the drop-monitor implementation. Read `trace_drop_common` to see how the tracepoint is dispatched to userspace via netlink.

- **`net/devlink/`** — devlink core. ~15000 lines across multiple files. Read `core.c` for the registration model, `dev.c` for device lifecycle, `health.c` for the health-reporter framework.

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
