# Day 4 — GRO, GSO, TSO: segmentation offloads

> **Today's mission:** understand why a single skb that enters `ip_rcv` may represent 40+ wire packets, and why the kernel writes one 64 KB skb on TX. Total time: ~75 minutes.

## The problem

Ethernet has an MTU of 1500 bytes. Most NICs can handle up to ~9000 bytes (jumbo frames) but not more. So one TCP connection sending a gigabyte through the kernel produces ~700,000 wire packets.

If the kernel ran its **full TCP send code path** (queue, build header, route lookup, qdisc, driver) once per wire packet, the per-packet overhead would crush throughput. Same on RX: 700,000 calls to `ip_rcv` is too many.

Three offload technologies move this work to either hardware or batched software so the stack runs at *aggregate* rate, not *per-segment* rate.

![offloads overview](diagrams/day04_offloads.png)

## TSO — TCP Segmentation Offload

The kernel hands the NIC **one large skb** (up to 64 KB) marked with `SKB_GSO_TCPV4` (or `SKB_GSO_TCPV6`). The NIC's hardware:

1. Reads the skb's TCP header as a template.
2. Walks the payload in MSS-sized chunks.
3. For each chunk, builds an IP+TCP header (cloning the template, adjusting sequence number, IP id, TTL, checksum), prepends Ethernet header, transmits.

Result: ~40 wire packets, **one** kernel call to `ndo_start_xmit`. Per-packet stack overhead drops by 40x.

Enable/check:

```bash
ethtool -k eth0 | grep tcp-segmentation-offload
# tcp-segmentation-offload: on
ethtool -K eth0 tso off
```

(The feature is named `tcp-segmentation-offload`, not `tso` — grepping for `tso` matches nothing.)

NIC must support it (most modern NICs do).

## GSO — Generic Segmentation Offload

Same idea, but the segmentation happens **in software** late in the TX path. If the NIC doesn't do TSO, the kernel still wants to avoid running the full TCP/IP code per segment. Instead:

1. TCP builds one big skb just like for TSO.
2. The skb travels down through `tcp_transmit_skb`, `ip_queue_xmit`, `dev_queue_xmit` as if it were a single packet.
3. Just before `ndo_start_xmit`, the qdisc/driver path detects the GSO marker and calls `__skb_gso_segment` (`net/core/gso.c:88`), which splits the skb into a chain of MTU-sized skbs.
4. The driver receives the chain and transmits each.

GSO is universal — works on any NIC. The CPU cost of segmentation is real but smaller than running the full stack per packet.

## GRO — Generic Receive Offload

The receive-side counterpart. Inside NAPI's poll function the driver calls `napi_gro_receive(napi, skb)`, a `static inline` that funnels into the exported `gro_receive_skb` (and `dev_gro_receive`):

```c
gro_receive_skb(&napi->gro, skb);   // net/core/gro.c — the traceable entry
```

The GRO engine (`net/core/gro.c`) compares the new skb against a list of "in flight" same-flow skbs. If it can merge (consecutive sequence numbers, same flow tuple, no flag changes), it appends payload to the existing one — extending the linear buffer or adding a page fragment. Result: one `ip_rcv` call for what was 40 wire packets.

Flush triggers:
- Different flow arrives.
- Timeout (per-device `/sys/class/net/<dev>/gro_flush_timeout`, or per-NAPI via netlink).
- NAPI poll exits.
- Special flag (FIN, RST, PSH).

## The full picture

![offload flow](diagrams/day04_flow.png)

> ### There are no Dumb Questions
>
> **Q: Why doesn't TSO break TCP correctness?**
>
> A: Because the segmenting NIC produces *correct wire packets* — same as if the kernel did it. From a peer's perspective, traffic is indistinguishable. Only the local stack saves work. Same for GRO: the merged skb has the same bytes as the original segments would; the local stack just sees them as one.
>
> **Q: When should I disable these?**
>
> A: For **latency-sensitive** measurements (HFT, microsecond timing, packet capture for forensics) — GRO can hold a packet briefly waiting for a possible merge buddy. Cost is usually <100 µs but visible. For **per-packet observability** (BPF programs that need to see wire packets) — GRO at the driver hides them.
>
> **Q: How does GSO interact with checksum offload?**
>
> A: Closely. GSO assumes the NIC will compute checksums (or computes them in software during segmentation). The skb has `ip_summed` flags (`CHECKSUM_PARTIAL` etc.) that the segmentation step uses. Look at `__skb_gso_segment` carefully if you ever debug a checksum-related issue.

## Pitfalls when offloads are on

![pitfalls](diagrams/day04_pitfalls.png)

The biggest gotcha is **observability**. If you trace `ip_rcv` and count packets, you're counting GRO superpackets, not wire packets. Multiply by `skb_shinfo(skb)->gso_segs` if you have it; or disable GRO during measurement.

For BPF programs that hook into the stack (XDP runs *before* GRO; tc-bpf runs *after*), this matters: XDP sees per-segment, tc sees coalesced.

## Today's experiment

### See offload state

```bash
ethtool -k eth0 | grep -E "segmentation-offload|receive-offload"
```

Output (typical):
```
tcp-segmentation-offload: on
generic-segmentation-offload: on
generic-receive-offload: on
large-receive-offload: on
```

The feature *names* are `tcp-segmentation-offload` / `generic-*-offload` — they don't contain the
substrings `tso`/`gso`/`gro`, so a `grep -E "tso|gso|gro"` would match only unrelated lines and never
print these. Match the real names. (`large-receive-offload` is the hardware LRO cousin of GRO; it may
read `off [fixed]` on NICs that don't support it.)

### Watch GRO in action

GRO coalesces many wire packets into one superpacket, so the *entry* probe (`gro_receive_skb`) fires
once per arriving segment, while the *post-GRO* probe fires far fewer times with much larger skbs. We
watch both the lengths and the call counts:

```bash
sudo bpftrace -e '
fentry:gro_receive_skb {
  @gro_lengths = lhist(args->skb->len, 0, 65536, 8192);
  @gro_calls = count();
}
tracepoint:net:netif_receive_skb {
  @postgro_lengths = lhist(args->len, 0, 65536, 8192);
  @postgro_calls = count();
}
interval:s:8 { exit(); }' &

# While that window is open, pull a real bulk download (server-less, follows redirects).
curl -sL -o /dev/null --max-time 6 \
  https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
wait
```

Run the download *inside* the bpftrace window, so background the tracer (`&`) and `wait`. Typical output
(numbers scale with the transfer):

```
@gro_calls: 237409          <- once per arriving segment, mostly small
@gro_lengths:
[0, 8K)           219020 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)          11732 |@@                                                |
 ...
@postgro_calls: 30527       <- ~8x fewer: GRO merged ~8 segments per superpacket
@postgro_lengths:
[0, 8K)            11056 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)           7203 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[56K, 64K)          3260 |@@@@@@@@@@@@@@@                                    |
```

The story is in the two `*_calls`: `gro_calls` ≫ `postgro_calls` (here ~8:1) is the coalescing ratio,
and `postgro_lengths` spreads into the big buckets — those are the merged superpackets the stack
processes once instead of eight times.

> **Why `netif_receive_skb` and not `ip_rcv`?** `tracepoint:net:netif_receive_skb` is the post-GRO entry
> into the stack and fires on every NIC. `fentry:ip_rcv` works on bare-metal NICs but on many virtual
> NICs (cloud/virtio) it attaches yet never fires — you'd see an empty histogram and wrongly conclude
> GRO is off. Use the tracepoint; add `fentry:ip_rcv { @ip = lhist(args->skb->len,0,65536,8192); }` too
> if you want to confirm it on bare metal.

### Disable GRO and re-measure

Now turn GRO off and run the *same* observation. The contrast is the whole point:

```bash
sudo ethtool -K eth0 gro off

sudo bpftrace -e '
tracepoint:net:netif_receive_skb {
  @postgro_lengths = lhist(args->len, 0, 65536, 8192);
  @postgro_calls = count();
} interval:s:8 { exit(); }' &
sleep 1
curl -sL -o /dev/null --max-time 6 \
  https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
wait

# Always restore — leaving GRO off slows every later experiment:
sudo ethtool -K eth0 gro on
```

With GRO off, `postgro_calls` jumps roughly back to the segment count (here ~233 000 vs ~30 000 with GRO
on — an ~8x increase), and `postgro_lengths` collapses almost entirely into the `[0, 8K)` bucket: the
stack now runs once per wire-sized packet instead of once per superpacket. That extra per-packet work is
the CPU cost GRO was hiding.

### Per-segment counter

TSO is a *transmit* offload: the stack hands the NIC large skbs and the NIC segments them onto the wire.
So you need an **upload** to see it (a download's TX side is just small ACKs). Watch the size of skbs
entering the device queue while pushing data out:

```bash
sudo bpftrace -e 'fentry:__dev_queue_xmit {
  @tx_skb_len = lhist(args->skb->len, 0, 65536, 8192);
} interval:s:6 { exit(); }' &

# Server-less upload sink; --max-time bounds it, the timeout exit is expected (|| true).
curl -s -o /dev/null -T /dev/zero --max-time 4 https://speed.cloudflare.com/__up || true
wait
```

Typical output — a strong spike in the top bucket, the 64 KB GSO/TSO skbs the stack handed down:

```
@tx_skb_len:
[0, 8K)              206 |@@@@@@                                            |
[8K, 16K)            120 |@@@                                               |
 ...
[56K, 64K)          1660 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

Each of those ~64 KB skbs becomes ~40+ MTU-sized wire packets, but the stack ran its TX path **once** per
skb. You can see the multiplication in the NIC counters too — the wire-packet count climbs far faster
than the skb count:

```bash
ethtool -S eth0 | grep -iE 'tx_packets|tx_queue.*packets'   # NIC's per-queue / aggregate wire packets
cat /sys/class/net/eth0/statistics/tx_packets               # kernel-level tx_packets
```

The field is named `tx_packets` / `tx_queue_N_packets` — **not** `tx_pkts`, which matches nothing on any
driver. Counter layout is driver-specific: on virtualized NICs (e.g. Azure/`mlx5` VF) the
`tx_queue_N_packets` lines may read `0` and the real counts live in `vf_tx_packets` / `cpuN_tx_packets`.

---

## What to read in the kernel

- **`net/core/gso.c`** — segmentation engine. ~300 lines. `__skb_gso_segment` is the entry; `skb_mac_gso_segment` does the L2 split.
- **`net/core/gro.c`** — coalescing engine. ~800 lines. `dev_gro_receive` is the workhorse (`gro_receive_skb` is the exported entry; `napi_gro_receive` itself is a `static inline` in `netdevice.h`); per-protocol callbacks (`tcp4_gro_receive`) live in protocol files.
- **`net/ipv4/tcp_offload.c`** — TCP-specific GRO/GSO callbacks.
- **`include/linux/netdev_features.h`** — `NETIF_F_GSO_*`, `NETIF_F_TSO_*`, `NETIF_F_GRO_*` flags.
- **`include/linux/skbuff.h`** — search `gso_size`, `gso_segs`, `gso_type` in `skb_shared_info`.
- **`Documentation/networking/segmentation-offloads.rst`** — official guide.

---

## Bullet Points

- **TSO**: hardware segments large skbs into wire packets. Saves stack overhead 40x.
- **GSO**: software segmentation late in TX (`net/core/gso.c:__skb_gso_segment`). Same stack savings as TSO; works on any NIC.
- **GRO**: receive-side coalescing in NAPI poll (`net/core/gro.c:dev_gro_receive`). One stack pass per superpacket.
- All three controlled with `ethtool -K`.
- **Default ON** for all three on modern NICs.
- Side effects: **per-packet observability is wrong unless you disable GRO** or multiply by gso_segs.
- For latency-critical workloads, sometimes GRO is disabled (sub-100µs latency floor).

---

## Check question

You run `iperf3` and for the first instant of a transfer the reported throughput briefly reads *above* the NIC's line rate, then settles. What's happening?

<details>
<summary>Click to reveal answer</summary>

**Answer:** iperf3 measures bytes through the userspace socket, not bytes on the wire. At the very start of a transfer the kernel's socket send buffer absorbs a burst of writes faster than the NIC can drain them — the application's bytes-per-second momentarily reflects how fast data entered the socket buffer, not how fast it left the wire. Once the buffer fills and TCP is paced by ACKs, the reading settles to the true wire rate (bounded by the NIC). TSO contributes to the illusion: those buffered bytes leave the kernel in 64 KB skbs that the NIC segments, so the "stack-level throughput" spikes briefly before flow control clamps it. Steady-state iperf3 throughput tracks wire rate.

</details>

---

## Tomorrow

Day 5: network namespaces. Why a single kernel can run dozens of independent network stacks at once, and how `struct net` makes it work.
