# Day 12 — Tunnels: VXLAN, GRE, IPIP, WireGuard

> **Today's mission:** build a VXLAN tunnel between two namespaces. Understand how tunneling layers work in the kernel. End of Phase 2. Total time: ~75 minutes.

## The tunnel zoo

![tunnel types](diagrams/day12_tunnels.png)

All tunnels in Linux are netdevs — `vxlan0`, `gre0`, `wg0`. You configure routes through them like any other interface. The magic is in their xmit/rx handlers, which encapsulate/decapsulate packets in transit.

Common types:

- **IPIP** — IP-in-IP. ~20 bytes overhead. Simple. `net/ipv4/ipip.c`.
- **GRE** — Generic Routing Encapsulation. Carries any L3 over IP. `net/ipv4/ip_gre.c`.
- **VXLAN** — Ethernet-in-UDP. VNI identifies overlay network. The cornerstone of container networking.
- **GENEVE** — successor to VXLAN with extensible options.
- **WireGuard** — modern UDP-based VPN. `drivers/net/wireguard/`.

## VXLAN in detail

![VXLAN flow](diagrams/day12_vxlan_flow.png)

A VXLAN frame on the wire:
```
[outer Ethernet][outer IP][outer UDP=4789][VXLAN hdr (VNI:24)][inner Ethernet][inner IP][...]
```

The "outer" Ethernet/IP go from VTEP to VTEP (the box endpoints). The "inner" Ethernet is what would have been on a flat L2 network. The VNI is a 24-bit overlay-network ID, so 16M overlays per IP cloud.

## Set up a VXLAN tunnel

```bash
# Two namespaces, both with VTEPs:
sudo ip netns add A; sudo ip netns add B

# Underlay network (using veth + bridge would work, but for demo use lo addrs in init_net):
sudo ip link add vxlanA type vxlan id 100 \
    local 192.168.99.1 remote 192.168.99.2 \
    dstport 4789

sudo ip link add vxlanB type vxlan id 100 \
    local 192.168.99.2 remote 192.168.99.1 \
    dstport 4789

# Move and configure
sudo ip link set vxlanA netns A
sudo ip netns exec A ip addr add 10.100.0.1/24 dev vxlanA
sudo ip netns exec A ip link set vxlanA up

sudo ip link set vxlanB netns B
sudo ip netns exec B ip addr add 10.100.0.2/24 dev vxlanB
sudo ip netns exec B ip link set vxlanB up

# Test (assuming underlay is set up):
sudo ip netns exec A ping 10.100.0.2
```

Frames flow: app sends to 10.100.0.2 → vxlanA xmit handler encapsulates → outer UDP/IP/Ethernet sent through underlay → vxlanB receives via udp_tunnel dispatch → decap → inner frame appears at vxlanB → up to app.

## WireGuard

A standout tunnel in the modern kernel. UDP-based VPN that's:
- **Crypto-routed**: peer identified by pubkey, not just IP.
- **Stateless control plane**: no session negotiation phases.
- **Minimal**: ~5k LOC vs OpenVPN's ~100k.

Configure:
```bash
sudo ip link add wg0 type wireguard
sudo wg set wg0 private-key /tmp/privatekey \
    listen-port 51820 \
    peer <peer_pubkey> allowed-ips 10.0.0.0/24 \
    endpoint peer.example.com:51820
sudo ip addr add 10.0.0.1/24 dev wg0
sudo ip link set wg0 up
```

The `allowed-ips` field is both source and destination filter — packets to those IPs go through the tunnel, packets from outside those IPs are dropped.

## What to read in the kernel

- **`drivers/net/vxlan/`** — VXLAN. `vxlan_xmit_one`, `vxlan_rcv`.
- **`net/ipv4/ip_tunnel.c`** — generic IP tunnel infrastructure (used by IPIP, GRE).
- **`net/ipv4/udp_tunnel.c`** — UDP-based tunnel dispatch (used by VXLAN, GENEVE).
- **`drivers/net/wireguard/`** — WireGuard implementation.
- **`net/ipv4/ip_gre.c`** — GRE.

## Bullet Points

- All tunnels are netdevs; their `ndo_start_xmit` encapsulates.
- **VXLAN** = Ethernet-in-UDP, 24-bit VNI. UDP port 4789. The standard for overlays.
- **WireGuard** = modern UDP VPN, in-tree since 5.6.
- Underlay must be reachable; tunnels add overhead (20–60 bytes typically).
- Inspect: `ip -d link show vxlan0` shows tunnel parameters.
- Tunneling and offloads interact carefully — see `net/core/gso.c` for GSO across tunnels.

## Check question

A VXLAN tunnel is configured. Why do users sometimes see MTU issues with TCP through the tunnel?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Each VXLAN frame adds ~50 bytes of overhead (outer Ethernet 14 + IP 20 + UDP 8 + VXLAN 8). If the underlying link MTU is 1500 and the tunnel doesn't account for the overhead, an inner 1500-byte packet won't fit (1550 wire). Solutions: (1) lower the tunnel netdev's MTU to 1450; (2) ensure path-MTU discovery works (ICMP "frag needed" propagates); (3) use TCP MSS clamping (`-mss 1410` in iptables/nftables) so endpoints negotiate smaller segments. Linux's tunnel netdevs default to a sensible reduced MTU, but if endpoints set DF=1 and underlay drops without ICMP, you get black-holed connections.

</details>

## End of Phase 2

You can now read the L2/L3 layers of the kernel network stack. Ethernet parsing, VLANs, ARP/NDP, the FIB and routing rules, IPv6 specifics, bridges, tunnels.

Phase 3 (Days 13–19) goes up to L4: sockets, UDP, TCP state machine, congestion control, retransmission, sockopts, epoll.
