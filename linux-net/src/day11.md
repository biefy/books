# Day 11 — The bridge subsystem

> **Today's mission:** create a software Linux bridge, attach two interfaces to it, watch the FDB learn MACs as traffic flows. Total time: ~75 minutes.

## What a Linux bridge is

A virtual L2 switch. Add interfaces as "ports" and the bridge forwards frames between them based on MAC addresses. This is how:

- Container runtimes wire pods to a virtual network.
- VMs on the same host talk to each other.
- A box becomes a wired switch with multiple Ethernet NICs.

Implementation is in `net/bridge/` (~10k lines).

## Anatomy

![bridge struct](diagrams/day11_bridge_struct.png)

A bridge is a netdev plus a set of ports. Each slave interface becomes a port. The bridge has its own MAC and IP (you can configure `br0` like any interface). Frames traversing the bridge use the FDB (Forwarding Database) to decide where to go.

## Forwarding logic

![bridge forwarding](diagrams/day11_bridge.png)

For each frame on a port:

1. **Learn**: insert/refresh `(src MAC, port)` in the FDB.
2. **Lookup**: find `(dst MAC)` → port.
3. **Forward** to that port if found, else **flood** to all ports except input.

Special cases: broadcast (always flood), multicast (IGMP-snooped optionally), STP control frames (don't forward).

## Set up a bridge

```bash
sudo ip link add br0 type bridge
sudo ip link set veth1 master br0
sudo ip link set veth2 master br0
sudo ip link set br0 up
```

Now `veth1` and `veth2` are bridged. Frames from one go to the other (after FDB learning).

## VLAN-aware bridges

```bash
sudo ip link set br0 type bridge vlan_filtering 1
sudo bridge vlan add dev veth1 vid 100 pvid untagged
sudo bridge vlan add dev veth2 vid 100 tagged
```

Now `br0` is VLAN-aware; tagging policy is per-port. Modern container networking relies heavily on this.

## Today's experiment

```bash
sudo ip link add br0 type bridge
sudo ip link add v1 type veth peer name v1p
sudo ip link add v2 type veth peer name v2p
sudo ip link set v1p master br0
sudo ip link set v2p master br0
sudo ip link set br0 up
sudo ip link set v1p up
sudo ip link set v2p up

# move v1 and v2 to namespaces
sudo ip netns add ns1; sudo ip link set v1 netns ns1
sudo ip netns add ns2; sudo ip link set v2 netns ns2
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev v1
sudo ip netns exec ns1 ip link set v1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev v2
sudo ip netns exec ns2 ip link set v2 up

# Test
sudo ip netns exec ns1 ping 10.0.0.2

# Watch FDB learn
bridge fdb show dev v1p
bridge fdb show dev v2p
```

You'll see two MAC entries learned, one per port.

## What to read in the kernel

- **`net/bridge/br_input.c`** — `br_handle_frame`, the entry point for bridge processing.
- **`net/bridge/br_fdb.c`** — FDB management. Hash table keyed by (vlan_id, MAC).
- **`net/bridge/br_forward.c`** — `br_forward`, `br_flood`.
- **`net/bridge/br_vlan.c`** — VLAN-aware bridge logic.
- **`include/linux/if_bridge.h`** — UAPI.

## Bullet Points

- Linux bridge is a software L2 switch. Add ports with `ip link set <if> master br0`.
- **FDB** maps `(vlan, MAC) → port`. Learned from src MAC of incoming frames.
- Lookup miss → flood. STP/IGMP-snooping handle special cases.
- **VLAN-aware bridges** (`vlan_filtering 1`) implement true 802.1Q switches.
- Inspect: `bridge link`, `bridge fdb`, `bridge vlan`.

## Check question

A bridge has 4 ports. A frame with dst MAC `aa:bb:cc:dd:ee:ff` arrives on port 1. The FDB has no entry. What ports does the frame go out on?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Ports 2, 3, and 4 — the bridge floods to all ports except the input port (split-horizon). Once a reply comes back from one of those ports with src `aa:bb:cc:dd:ee:ff`, the FDB learns and subsequent unicast frames go directly to that port.

</details>

## Tomorrow

Day 12: tunnels — VXLAN, GRE, IPIP, WireGuard. End of Phase 2.
