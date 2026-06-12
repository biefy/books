# Day 6 — Ethernet, VLAN, and the L2 layer

> **Today's mission:** see what `eth_type_trans` does to every received packet, understand 802.1Q tagging, create a VLAN device. Total time: ~75 minutes.

> **Phase 2 starts here.** Days 6–12 walk the L2/L3 layers in detail: Ethernet, ARP, IP routing, IPv6, bridges, tunnels.

## What L2 means in Linux

The "Layer 2" code in Linux is small but ubiquitous. Every received frame passes through it; every transmitted frame has its Ethernet header built there. The implementation lives mostly in **`net/ethernet/eth.c`** (~640 lines).

The single most important function in this layer is `eth_type_trans` — called by every Ethernet driver on RX, every time.

## `eth_type_trans` — the universal RX header parser

![eth_type_trans](diagrams/day06_eth_type_trans.png)

`eth_type_trans(skb, dev)` (`net/ethernet/eth.c:155`) does five things in tight succession:

1. **`skb_reset_mac_header(skb)`** — record where the Ethernet header is by storing the offset of `skb->data` within the buffer (`skb->data - skb->head`); it's at `skb->data` right now.
2. **Read `eth = (struct ethhdr *)skb->data`**.
3. **Set `skb->pkt_type`** (via `eth_skb_pkt_type`) based on destination MAC:
   - `PACKET_BROADCAST` if dst is `ff:ff:ff:ff:ff:ff`.
   - `PACKET_MULTICAST` if the multicast bit is set.
   - `PACKET_OTHERHOST` if dst doesn't match `dev->dev_addr` (would be dropped on a normal NIC; promiscuous mode keeps these). Otherwise it leaves the default `PACKET_HOST` when dst matches `dev_addr` (us).
4. **`skb_pull(skb, ETH_HLEN)`** — advance `skb->data` past the 14-byte header. Now `skb->data` points at the L3 payload.
5. **Return the protocol ID** — typically `eth->h_proto` (`ETH_P_IP` 0x0800, `ETH_P_IPV6` 0x86DD, or `ETH_P_8021Q` 0x8100, VLAN), but only `if (eth_proto_is_802_3(...))`. There are two short-circuits before that: if the device uses DSA tagging it returns `ETH_P_XDSA` without looking at the packet, and if `h_proto` is a length field (≤ 1500) it falls back to `ETH_P_802_3` (IPX magic) or `ETH_P_802_2` (802.2 LLC).

The driver assigns the return value to `skb->protocol`, then passes the skb to GRO / `netif_receive_skb`. From here the L3 dispatcher uses `skb->protocol` to find the right handler (`ip_rcv` for IP).

## VLAN tagging (802.1Q)

A VLAN tag is a 4-byte insert between the source MAC and the type field:

![VLAN tagging](diagrams/day06_vlan.png)

The kernel handles VLANs in two ways:

1. **HW acceleration** — most modern NICs strip the tag on RX and stash it in `skb->vlan_tci` + `skb->vlan_proto`. The stack sees an untagged frame plus metadata. Test with `skb_vlan_tag_present(skb)`. On TX, the kernel hands the NIC a tagged-or-not skb and the NIC adds the tag if requested.

2. **Software path** — for NICs without HW VLAN, or for stacked VLANs (QinQ), `vlan_do_receive` in `net/8021q/vlan_core.c` parses the tag and dispatches.

A **VLAN device** (`eth0.100`) is a virtual netdev that filters frames by VLAN ID:

```bash
sudo ip link add link eth0 name eth0.100 type vlan id 100
sudo ip link set eth0.100 up
sudo ip addr add 192.168.100.5/24 dev eth0.100
```

Now `eth0.100` is a fully-featured interface with its own routes, MTU, and IP. Frames with VLAN ID 100 arriving on `eth0` get redirected to `eth0.100`'s RX path; transmits on `eth0.100` get tagged and sent through `eth0`.

![VLAN dispatch](diagrams/day06_vlan_dispatch.png)

> ### There are no Dumb Questions
>
> **Q: What's the difference between `skb->protocol` and the type field?**
>
> A: They're set from the same source (`eth->h_proto`), but `skb->protocol` is what the stack uses for dispatch. For VLAN-tagged frames, the kernel processes the tag, then sets `skb->protocol` to the *inner* type. So a TCP-over-VLAN frame ends up with `skb->protocol = ETH_P_IP` after VLAN handling.
>
> **Q: Can I have a VLAN inside a VLAN?**
>
> A: Yes — QinQ (802.1ad). Outer type is 0x88a8, inner remains 0x8100. Linux supports it via `ip link add link eth0.100 name eth0.100.200 type vlan id 200`.
>
> **Q: How does the kernel pick the source MAC for outbound frames?**
>
> A: From `dev->dev_addr` of the egress device. Modern NICs allow random MACs at boot (privacy via `MACAddressPolicy=random` in systemd-networkd). The Ethernet header build happens in `dev_hard_header` → `eth_header` (`net/ethernet/eth.c`).

## Today's experiment

### See `eth_type_trans` in action

```bash
sudo bpftrace -e '
fentry:eth_type_trans {
  $eth = (struct ethhdr *)args->skb->data;
  printf("dst=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x\n",
         $eth->h_dest[0], $eth->h_dest[1], $eth->h_dest[2],
         $eth->h_dest[3], $eth->h_dest[4], $eth->h_dest[5], $eth->h_proto);
}' &
sleep 3                 # let the fentry BTF probe attach before we trigger traffic
ping -c 5 8.8.8.8
sleep 1                 # let the last frames drain through the probe
sudo killall bpftrace
```

The `sleep 3` matters: a BTF `fentry` probe takes a second or two to attach, and a single `ping -c 1` completes in a few hundred milliseconds — without the delay the trigger (and the kill) happen before the probe is live and you see nothing. `eth_type_trans` fires on *every* received frame, so with the probe up for a few seconds you'll get output even apart from the ping:

```
dst=00:22:48:7c:ffffffb3:ffffffef type=0x0008
dst=00:22:48:7c:ffffffb3:ffffffef type=0x0008
dst=00:22:48:7c:ffffffb3:ffffffef type=0x0008
```

You'll see actual MAC addresses and EtherTypes flying through. (bpftrace prints `h_dest` octets as signed bytes, so values ≥ 0x80 show sign-extended as `ffffffb3` — read the low two hex digits.) Note that `h_proto` is `__be16` (big-endian on the wire), so on a little-endian host the raw `%04x` print is byte-swapped — IP shows as `0x0008` rather than `0x0800`. Mentally swap the bytes, or wrap the field in `bswap()`.

### Create a VLAN and watch traffic

```bash
sudo ip link add link eth0 name eth0.100 type vlan id 100
sudo ip link set eth0.100 up
sudo ip addr add 10.100.0.1/24 dev eth0.100

# verify
ip -d link show eth0.100   # see vlan_id 100, vlan_protocol 802.1Q

# capture both:
sudo tcpdump -i eth0 -e -n vlan 100 &
sudo tcpdump -i eth0.100 -n &
sleep 1

# trigger: no peer answers, but the ARP request for 10.100.0.2
# egresses eth0 tagged with VID 100 (and untagged on eth0.100)
ping -c 3 -W1 10.100.0.2
sleep 1
```

You should see the *same* frame twice — on `eth0` carrying the 802.1Q tag that `-e` exposes (`vlan 100, p 0, ethertype ARP ...`) and on `eth0.100` already stripped/untagged. That side-by-side is the VLAN device doing tag insertion on egress and removal on ingress. The ping gets no replies (there's no host at 10.100.0.2) — that's fine; the tagged ARP requests are the point.

```bash
# cleanup
sudo pkill tcpdump            # stop both backgrounded captures (and drop promisc mode)
sudo ip link del eth0.100     # also removes the 10.100.0.1/24 address
```

### See pkt_type stats

```bash
sudo bpftrace -e '
fexit:eth_type_trans {
  @pkt_types[args->skb->pkt_type] = count();
}
interval:s:5 { exit(); }'
```

PACKET_HOST=0, BROADCAST=1, MULTICAST=2, OTHERHOST=3. We attach at `fexit` (function return), not `fentry`: `eth_type_trans` is the function that *sets* `pkt_type` (via `eth_skb_pkt_type`), so at entry the field still holds its prior value (usually 0). By the time the function returns, the assignment is complete. `fexit` exposes `args->` for the input arguments just like `fentry`.

## What to break

### Toggle promiscuous mode

```bash
sudo ip link set eth0 promisc on

# re-run the "See pkt_type stats" trace above while generating traffic

sudo ip link set eth0 promisc off   # restore
```

Now the kernel processes packets that aren't addressed to your MAC (where `pkt_type == PACKET_OTHERHOST`). `tcpdump` enables this implicitly.

> **Caveat:** on a mirrored/SPAN port, a hub, or a shared segment you'll now see `@pkt_types[3]` (PACKET_OTHERHOST) appear. On an ordinary switched link or a cloud vNIC the switch never delivers other hosts' unicast to your port, so key 3 may stay 0 even with promisc on — that's expected, not a bug. Always `promisc off` afterward so you don't leave the NIC in promiscuous mode.

### Set a non-default MAC

> **WARNING:** do **not** change the MAC of the interface carrying your SSH session. `eth0` is usually the management interface on a cloud/test VM — changing its MAC (or bringing the link down to do so) drops your connection, and many drivers reject an address change while the link is up. Use a throwaway interface instead:

```bash
# Option A (safe): a dummy interface, so you never touch the SSH link.
sudo ip link add mac-test type dummy
sudo ip link set mac-test address 02:00:00:00:00:01
ip link show mac-test            # observe the new MAC
sudo ip link delete mac-test     # cleanup

# Option B: a real spare NIC (NOT the one carrying SSH).
IF=eth1                          # NOT your SSH interface
orig=$(cat /sys/class/net/$IF/address)
sudo ip link set $IF down
sudo ip link set $IF address 02:00:00:00:00:01
sudo ip link set $IF up
ip link show $IF                 # confirm; re-run the eth_type_trans trace
sudo ip link set $IF down
sudo ip link set $IF address "$orig"   # restore the original MAC
sudo ip link set $IF up
```

Now `eth_type_trans` sees `02:00:00:00:00:01` as "us." Frames addressed there are PACKET_HOST. Useful for testing identity rules.

---

## What to read in the kernel

- **`net/ethernet/eth.c`** — `eth_type_trans` (line 155), `eth_header`, header_ops. The whole file is ~640 lines.
- **`include/linux/if_ether.h`** — `struct ethhdr`, EtherType constants.
- **`net/8021q/vlan_core.c`** — VLAN reception path.
- **`net/8021q/vlan_dev.c`** — VLAN device implementation.
- **`include/linux/skbuff.h`** — search `vlan_tci`, `vlan_proto`, `skb_vlan_tag_present`.

---

## Bullet Points

- **`eth_type_trans`** is the universal RX header parser; called from every Ethernet driver. Sets `skb->mac_header`, `skb->pkt_type`, `skb->protocol`, advances `skb->data` past the L2 header.
- `skb->pkt_type`: HOST / BROADCAST / MULTICAST / OTHERHOST.
- **VLAN** = 4 extra bytes between src MAC and EtherType. Type 0x8100 (or 0x88a8 for QinQ).
- **HW VLAN acceleration**: NIC strips tag, kernel reads from `skb->vlan_tci`. Otherwise software path in `net/8021q/`.
- **VLAN devices** are virtual netdevs that filter+strip by VLAN ID.
- TX side: `dev_hard_header` → `eth_header` builds the L2 frame.

---

## Check question

A frame arrives at eth0 with VLAN tag 100, but no `eth0.100` device exists. What happens?

<details>
<summary>Click to reveal answer</summary>

**Answer:** `vlan_do_receive()` looks up a registered VLAN device for (eth0, 100), finds none, and returns false. The frame isn't redirected to a VLAN netdev; `__netif_receive_skb_core` marks it `PACKET_OTHERHOST` and it's later dropped in `ip_rcv`, which bumps the `rx_otherhost_dropped` core stat (via `dev_core_stats_rx_otherhost_dropped_inc`). It doesn't bubble up to L3. To accept untagged "unknown VLAN" traffic, you'd configure a VLAN-aware bridge with the relevant VID on the port.

</details>

---

## Tomorrow

Day 7: ARP and the neighbour subsystem. How the kernel learns its peers' MAC addresses and what happens when neighbour entries go stale.
