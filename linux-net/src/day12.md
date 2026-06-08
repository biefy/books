# Day 12 — Tunnels: VXLAN, GRE, IPIP, WireGuard

> **Today's mission:** build a VXLAN tunnel between two namespaces. Understand the encapsulation/decapsulation cycle that every tunnel implements. End of Phase 2. Total time: ~75 minutes.

## What "tunneling" is, in one paragraph

A tunnel takes a packet (the *inner* packet) and wraps it in another header (the *outer* packet) so it can travel through a network that wouldn't otherwise carry it. The outer packet is delivered to a remote endpoint that strips the outer header and emits the inner packet on the other side. Different tunnel types differ in *what they wrap with* (IP, UDP, ESP) and *what extra metadata they carry* (VNI, GRE keys, sequence numbers).

In Linux, every tunnel is a **netdev** (`vxlan0`, `gre0`, `wg0`). You configure routes and bind sockets through it like any other interface. The tunneling magic lives in the netdev's `ndo_start_xmit` (encapsulation) and a paired RX hook (decapsulation).

## The tunnel zoo

![tunnel types](diagrams/day12_tunnels.png)

### IPIP — IP-in-IP (RFC 1853)

The simplest tunnel: outer IPv4 header + inner IP packet. 20 bytes overhead. No extra metadata.

- **What:** prepends an outer IPv4 header with `proto=4` (for IPIP) or `proto=41` (IPv6 in IPv4 — also known as 6in4).
- **Why:** route IP packets across a network that can't see them directly (e.g., a private subnet across the public Internet).
- **When:** rarely chosen directly today. GRE or VXLAN usually wins.
- **Gotcha:** no peer authentication — anyone can spoof an IPIP packet. Combine with IPsec (transport mode) for security, or filter by source IP.
- **Where:** `net/ipv4/ipip.c`. RX entry `ipip_rcv` (line 266) → `ipip_tunnel_rcv` (line 215). TX `ipip_tunnel_xmit` (line 282).

### GRE — Generic Routing Encapsulation (RFC 2784)

Outer IP + 4-byte GRE header + inner packet. The GRE header is variable: optional 4-byte *key* (tag for tenant separation), 4-byte *sequence number*, 4-byte *checksum*. Carries any L3 protocol (IPv4, IPv6, MPLS, even Ethernet via NVGRE).

- **What:** generic L3-over-L3 tunneling with optional metadata (key, sequence).
- **Why:** carry any-protocol-over-any-protocol with optional flow tagging. Originally for Cisco router interconnect; today common in MPLS-over-IP, ERSPAN port mirroring, and some VPN setups.
- **When:** when you need lightweight tunneling with a tag (32-bit GRE key) and want point-to-point or point-to-multipoint. ERSPAN (Cisco port mirroring) builds on GRE.
- **Gotcha:** GRE keys aren't authentication — they're separation. Same caveats as IPIP for security; pair with IPsec for confidentiality.
- **Where:** `net/ipv4/ip_gre.c`. RX `gre_rcv` (line 440) → `__ipgre_rcv` (line 366). TX `ipgre_xmit` (line 652). ERSPAN variant has its own paths (line 267, 704).

### VXLAN — Virtual eXtensible LAN (RFC 7348)

The standard for datacenter overlays. Outer Ethernet + outer IP + outer UDP (port 4789) + 8-byte VXLAN header + inner Ethernet frame. (4789 is the IANA-assigned port; the Linux module's legacy default is 8472 for backward compatibility, so always set `dstport` explicitly as the labs do.)

- **What:** Ethernet-in-UDP. The 24-bit VNI ("VXLAN Network Identifier") in the VXLAN header identifies the overlay — 16 million possible overlays per IP underlay.
- **Why:** scale beyond 4096 VLANs (the 802.1Q limit). Lets a single physical IP network carry many isolated L2 networks. Each VNI is its own broadcast domain.
- **When:** Kubernetes pod networking (Flannel, Calico in some modes, Cilium), datacenter SDN, multi-tenant cloud platforms. The dominant overlay today.
- **Gotcha:** **MTU.** Outer headers cost ~50 bytes. If the underlay MTU is 1500, the tunnel netdev should be MTU 1450. Otherwise inner 1500-byte packets won't fit; either path-MTU discovery saves you (if ICMP works) or you get black-holed connections. Solutions: (1) set tunnel MTU correctly; (2) MSS-clamp TCP via iptables/nftables (`tcp option mss set 1410`); (3) jumbo-frame underlay.
- **Where:** `drivers/net/vxlan/vxlan_core.c`. RX `vxlan_rcv` (line 1643) — registered as a UDP encap handler. TX `vxlan_xmit` (line 2722).

### GENEVE — successor to VXLAN

Same Ethernet-in-UDP idea, but with extensible TLV options in the header. Designed to subsume VXLAN, NVGRE, and STT into one protocol with room to grow. UDP port 6081. Heavier in the option-parsing path, but production-deployed (some Kubernetes deployments, OVN). Code: `drivers/net/geneve.c`.

### WireGuard — modern VPN (in-tree since 5.6)

Outer UDP + WireGuard's own framing (handshake messages or transport messages with ChaCha20-Poly1305). Crypto-routed: peers identified by Curve25519 public keys, not by IP.

- **What:** authenticated, encrypted L3 VPN over UDP.
- **Why:** the only modern in-kernel VPN with serious cryptographic and code review. Replaces OpenVPN (userspace, slow), IPsec (complex), and other options for most use cases.
- **When:** point-to-point or point-to-multipoint VPN. Roaming clients (mobile devices). Anywhere you'd reach for OpenVPN.
- **Gotcha:** **`AllowedIPs`** is both a routing rule *and* a source-address filter. A peer can only send packets *from* IPs in its `AllowedIPs`; a peer can only *receive* packets *to* IPs in its `AllowedIPs`. Misconfigure and you get silent drops with no diagnostic.
- **Where:** `drivers/net/wireguard/`. RX in `receive.c`, TX in `send.c`.

## VXLAN in detail (the canonical case)

A frame on the wire — 50 bytes of overhead total:

```
[outer Ethernet 14] [outer IP 20] [outer UDP 8] [VXLAN hdr 8] [inner Ethernet ...]
```

VXLAN header layout: Flags(1B) | Reserved(3B) | VNI(3B) | Reserved(1B). The Flags byte's "I" bit must be set; the VNI is 24 bits packed into the next three bytes.

![VXLAN flow](diagrams/day12_vxlan_flow.png)

### Encap path

When a packet hits a VXLAN netdev's TX:

1. **Resolve the destination VTEP** — for unicast inner MAC, the bridge-style FDB tells which remote VTEP IP holds that MAC. For unknown unicast/multicast, send to the configured multicast underlay group (commonly `239.1.1.1` in examples) or to the configured remote unicast IP.
2. **Build outer headers** — Ethernet, IP, UDP, VXLAN. Source UDP port is hashed from the inner flow (gives ECMP-like spread on the underlay).
3. **`udp_tunnel_xmit_skb`** — the generic UDP-tunnel send helper at `net/ipv4/udp_tunnel_core.c:174`. Routes the outer packet through the underlay's normal IP stack.

### Decap path

A frame arrives at the underlay, traverses ip_rcv, lands at UDP. The UDP socket at port 4789 is special — it's a "tunnel socket" registered by `setup_udp_tunnel_sock` (`net/ipv4/udp_tunnel_core.c:71`). Instead of queueing on a normal sk_receive_queue, the kernel calls the registered encap handler — for VXLAN, **`vxlan_rcv`** at `drivers/net/vxlan/vxlan_core.c:1643`.

Inside `vxlan_rcv`:
1. Parse VXLAN header, extract VNI.
2. Find the right VXLAN netdev for that VNI in this netns.
3. Strip outer headers (`skb_pull`).
4. Hand the inner Ethernet frame to that netdev's RX path — looks like a normal frame arriving at `vxlan0`.

## Set up a VXLAN tunnel (lab)

Two namespaces, both with VTEPs talking through the host (init_net) acting as the underlay:

```bash
sudo ip netns add A
sudo ip netns add B

# Underlay veth pairs
sudo ip link add vethA type veth peer name vethA_p
sudo ip link add vethB type veth peer name vethB_p
sudo ip link set vethA_p netns A
sudo ip link set vethB_p netns B
sudo ip addr add 192.168.99.10/24 dev vethA
sudo ip addr add 192.168.99.20/24 dev vethB
sudo ip link set vethA up
sudo ip link set vethB up
sudo ip netns exec A ip addr add 192.168.99.1/24 dev vethA_p
sudo ip netns exec B ip addr add 192.168.99.2/24 dev vethB_p
sudo ip netns exec A ip link set vethA_p up
sudo ip netns exec B ip link set vethB_p up

# VXLAN endpoints
sudo ip netns exec A ip link add vxlan0 type vxlan \
    id 100 local 192.168.99.1 remote 192.168.99.2 dstport 4789
sudo ip netns exec A ip addr add 10.100.0.1/24 dev vxlan0
sudo ip netns exec A ip link set vxlan0 up

sudo ip netns exec B ip link add vxlan0 type vxlan \
    id 100 local 192.168.99.2 remote 192.168.99.1 dstport 4789
sudo ip netns exec B ip addr add 10.100.0.2/24 dev vxlan0
sudo ip netns exec B ip link set vxlan0 up

# Test
sudo ip netns exec A ping -c 2 10.100.0.2
```

Then watch the encapsulated traffic:
```bash
sudo tcpdump -i vethA -nn 'udp port 4789'
```

You'll see UDP packets carrying the VXLAN-wrapped pings.

## Today's experiment — break the MTU

```bash
# Default: vxlan0 MTU = 1450 (1500 underlay − 50 overhead)
sudo ip netns exec A ip link show vxlan0

# Force inner side to send 1500-byte packets that won't fit:
sudo ip netns exec A ip link set vxlan0 mtu 1500
sudo ip netns exec A ping -M do -s 1472 -c 2 10.100.0.2   # don't fragment, 1500 total
# Likely fails. Verify: tcpdump shows ICMP "frag needed" or just silent drop.

# Restore
sudo ip netns exec A ip link set vxlan0 mtu 1450
```

This is the classic VXLAN deployment failure. Production datacenters either use jumbo frames on the underlay (MTU 9000) or rigorously MSS-clamp TCP.

## What to read in the kernel

- **`drivers/net/vxlan/vxlan_core.c:1643`** — `vxlan_rcv`. The decap entry. Read end to end (~300 lines including option handling). Trace how the VNI is extracted, how the right VXLAN netdev is looked up via `vxlan_vs_find_vni`, and how the inner Ethernet frame is handed to `gro_cells_receive` for the inner stack.

- **`drivers/net/vxlan/vxlan_core.c:2722`** — `vxlan_xmit`. The encap entry. Notice the FDB lookup (per-VXLAN bridge-style FDB), the outer-header construction, and the call to `vxlan_xmit_one` which eventually invokes `udp_tunnel_xmit_skb`.

- **`net/ipv4/udp_tunnel_core.c:71`** — `setup_udp_tunnel_sock`. How a tunnel registers itself as a UDP encap handler. Short function (~30 lines). Read the comments for what each `udp_tunnel_sock_cfg` field does.

- **`net/ipv4/udp_tunnel_core.c:174`** — `udp_tunnel_xmit_skb`. The generic outer-side TX. All UDP-based tunnels (VXLAN, GENEVE, FoU, GUE) use it. Notice GSO interaction — the tunnel sets up gso_type so segmentation does the right thing on the outer packet.

- **`net/ipv4/ip_tunnel.c`** — generic IP-tunnel infrastructure used by IPIP and GRE. Search `ip_tunnel_xmit` for the common encap path. Useful comparison point with `vxlan_xmit`.

- **`net/ipv4/ip_gre.c:440`** — `gre_rcv`. GRE is registered as IP `proto=47`; this function dispatches by GRE-header version (v0 = standard GRE, v1 = PPTP). For GRE-over-IP keys/sequence/checksum support, look at `gre_parse_header`.

- **`net/ipv4/ipip.c:266`** — `ipip_rcv`. The simplest tunnel decap. Read it as a reference; the others add features on top.

- **`drivers/net/wireguard/`** — WireGuard. Read `device.c` for the netdev integration, `receive.c` and `send.c` for the data path.

- **`Documentation/networking/vxlan.rst`** — official guide. Brief.

## Bullet Points

- All tunnels are netdevs; their `ndo_start_xmit` encapsulates, a paired RX hook decapsulates.
- **IPIP**: 20-byte overhead, simplest. Rarely first choice today.
- **GRE**: optional 32-bit key, sequence, checksum. Used in ERSPAN and some MPLS-over-IP setups.
- **VXLAN**: Ethernet-in-UDP, 24-bit VNI, port 4789. The standard for container/cloud overlays.
- **GENEVE**: VXLAN's TLV-extensible successor. UDP 6081.
- **WireGuard**: modern UDP VPN, in-tree since 5.6. Crypto-routed via peer pubkey.
- **MTU is always the trap.** Tunnel netdev MTU = underlay MTU − overhead. Use jumbo frames or MSS-clamping.
- **Inspect with `ip -d link show`** to see tunnel parameters (VNI, remote, port).

## Check question

A VXLAN tunnel is set up between two hosts (underlay MTU 1500). A user complains: short pings work fine, but file transfers stall after a few KB. What's the most likely cause and what's the simplest fix?

<details>
<summary>Click to reveal answer</summary>

**Answer:** **Path-MTU issue.** Short ICMP pings fit in the encapsulated 1500-byte budget. File transfers (TCP) try to use the path's full MSS — TCP negotiated MSS based on the *interface* MTU, but the tunnel adds ~50 bytes of overhead, and the underlay drops oversize packets. If ICMP "fragmentation needed" is being filtered (very common), the sender doesn't learn to reduce MSS, and the connection hangs. The simplest fix is **MSS clamping**: `nft add rule inet filter forward tcp flags syn / syn,rst tcp option maxseg size set 1410` — the kernel rewrites the SYN's MSS option as packets traverse, forcing both ends to use a smaller MSS that fits. Alternatives: set the tunnel MTU correctly (Linux usually does this automatically: 1450 for VXLAN over 1500), enable jumbo frames on the underlay (MTU 9000), or unblock ICMP "frag needed" so PMTUD works naturally.

</details>

---

## End of Phase 2

You can now read the L2/L3 layers of the kernel network stack. Ethernet parsing, VLANs, ARP/NDP, the FIB and routing rules, IPv6 specifics, bridges, tunnels.

Phase 3 (Days 13–19) goes up to L4: sockets, UDP, TCP state machine, congestion control, retransmission, sockopts, epoll/io_uring.
