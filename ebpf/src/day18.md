# Day 18 — AF_XDP: packets to userspace at line rate

> **Today's mission:** redirect raw packets from XDP to a userspace ring at line rate without copying. Build a tiny zero-copy packet receiver. Total time: ~90 minutes.

## Why bypass the stack

The Linux network stack is general-purpose. For most workloads that's fine — sockets, retransmits, congestion control, all done for you. But for packet-processing apps (DPI, custom load balancers, network testing, telemetry pipelines), the stack adds overhead you don't want: skb allocation, protocol parsing you'll redo anyway, syscalls per packet.

**AF_XDP** is the kernel's answer to DPDK: packet receive directly into userspace-managed rings, with no syscalls in the steady-state receive loop (with the `XDP_USE_NEED_WAKEUP` flag the driver may ask you to `poll()`/`recvfrom()` to wake it — see below). On NICs and drivers with zero-copy support, packets DMA directly into UMEM; otherwise AF_XDP still works in copy mode with lower throughput.

![AF_XDP architecture](diagrams/day18_afxdp.png)

The trick: userspace pre-allocates a memory region (UMEM) and registers it with the kernel. In zero-copy mode, the NIC driver DMAs incoming packets directly into that memory. In copy mode, the kernel copies packet data into UMEM but keeps the same ring and descriptor model. An XDP program redirects to an AF_XDP socket bound to that UMEM, and userspace polls descriptors pointing into UMEM.

Throughput on supported zero-copy NICs can reach 30+ Mpps per core. A veth lab is still useful for learning the lifecycle, but it demonstrates functional/copy-mode behavior rather than NIC DMA zero-copy performance.

## The ring quartet

Each AF_XDP socket has four rings shared between kernel and userspace:

- **FILL ring** (user → kernel): "here are free buffers in UMEM you can DMA into."
- **RX ring** (kernel → user): "here are packets I just received."
- **TX ring** (user → kernel): "send these for me."
- **COMPLETION ring** (kernel → user): "TX done; recycle these buffers."

User and kernel both advance their pointers; no syscalls needed in the steady state. (You do call `sendto()` to kick TX after enqueueing, but kernel handles batching.)

## XDP and AF_XDP cooperate

![xskmap redirect](diagrams/day18_xskmap.png)

The XDP program decides per packet: pass to stack, drop, or **redirect to an AF_XDP socket**. Multiple sockets are kept in a `BPF_MAP_TYPE_XSKMAP` keyed by RX queue index — the standard pattern is one socket per RX queue for parallelism.

```c
SEC("xdp")
int xdp_redirect_to_xsk(struct xdp_md *ctx) {
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}
```

That's the whole BPF side for AF_XDP — the work happens in userspace.

> ### There are no Dumb Questions
>
> **Q: Is this DPDK?**
>
> A: Conceptually similar (kernel-bypass, zero-copy, polled rings) but cooperative with the kernel rather than commandeering the NIC. AF_XDP keeps the driver in the kernel; DPDK takes the device entirely. AF_XDP is easier to install/maintain and supports per-queue split (some queues to AF_XDP, others to the kernel stack).
>
> **Q: Can I run AF_XDP on any NIC?**
>
> A: There's *zero-copy* mode for NICs with explicit support (Mellanox, Intel ice/i40e, Realtek r8169 recently). For unsupported NICs, "copy mode" works (one copy per packet) at lower throughput.
>
> **Q: This sounds complicated. Is there a tool I can use?**
>
> A: `xdp-tools` from the XDP project provides example senders/receivers. `libxdp` (a sister to libbpf) wraps the AF_XDP plumbing. We'll use libxdp's helpers in the lab.

## The lab

This is the densest lab so far; budget the full 90 minutes.

### Setup

```bash
# BPF + userspace build toolchain: clang/llvm compile the BPF object,
# bpftool generates vmlinux.h, libxdp/libbpf supply the AF_XDP ring + loader helpers.
sudo apt install clang llvm bpftool libxdp-dev libbpf-dev linux-headers-$(uname -r)
# On some distros bpftool ships in linux-tools-$(uname -r) / linux-tools-common instead.

git clone https://github.com/xdp-project/xdp-tutorial
# We build and run xdp-tutorial/advanced03-AF_XDP below; the listings in this
# chapter are an annotated walk-through of what that example does.
```

The BPF object includes `vmlinux.h`. If you compile it yourself rather than using the tutorial Makefile, generate that header first with bpftool:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### `xsk.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);    /* xsk fd */
} xsks_map SEC(".maps");

SEC("xdp")
int xsk_redirect(struct xdp_md *ctx)
{
    __u32 q = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &q))
        return bpf_redirect_map(&xsks_map, q, 0);
    return XDP_PASS;
}
```

### `xsk_recv.c` — userspace receiver (annotated walk-through)

> This listing is **reference-only** — read it to understand the AF_XDP lifecycle, don't compile it verbatim. It deliberately elides glue: it never loads the BPF object, so `xsks_map_fd` and `exiting` have no source here, and the `stdio.h`/`unistd.h`/`stdlib.h`/`signal.h` includes are omitted. To actually **Run**, build the complete `xdp-tutorial/advanced03-AF_XDP` example below — it wires all of this up (loading the object and obtaining the XSKMAP fd through `xsk_socket__create`, installing a SIGINT handler to set `exiting`).

```c
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <net/if.h>

#define UMEM_NUM_FRAMES 4096
#define FRAME_SIZE 2048

struct umem_info {
    void *buffer;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
};

int main(int argc, char **argv) {
    int ifindex = if_nametoindex(argv[1]);

    /* 1. Allocate UMEM */
    void *buffer;
    posix_memalign(&buffer, 4096, UMEM_NUM_FRAMES * FRAME_SIZE);

    struct umem_info umem = {.buffer = buffer};
    xsk_umem__create(&umem.umem, buffer,
                     UMEM_NUM_FRAMES * FRAME_SIZE, &umem.fq, &umem.cq, NULL);

    /* 2. Create AF_XDP socket */
    struct xsk_socket *xsk;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_socket_config cfg = {.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD};
    xsk_socket__create(&xsk, argv[1], 0, umem.umem, &rx, &tx, &cfg);

    /* 3. Load and attach the BPF program separately */
    /* (the libxdp default would do this for you, but we want to control it) */

    /* 4. Insert this AF_XDP socket fd into xsks_map at queue 0 */
    int xsk_fd = xsk_socket__fd(xsk);
    __u32 qid = 0;
    bpf_map_update_elem(xsks_map_fd, &qid, &xsk_fd, BPF_ANY);

    /* 5. Pre-fill the FILL ring */
    __u32 idx;
    __u32 got = xsk_ring_prod__reserve(&umem.fq, UMEM_NUM_FRAMES, &idx);
    if (got != UMEM_NUM_FRAMES) { /* ring full / no space — handle it */ }
    for (__u32 i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&umem.fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&umem.fq, got);

    /* 6. Poll loop */
    while (!exiting) {
        __u32 idx_rx, n;
        n = xsk_ring_cons__peek(&rx, 64, &idx_rx);
        if (!n) {
            usleep(10);
            continue;
        }
        __u64 addrs[64];
        for (__u32 i = 0; i < n; i++) {
            __u64 addr = xsk_ring_cons__rx_desc(&rx, idx_rx + i)->addr;
            __u32 len  = xsk_ring_cons__rx_desc(&rx, idx_rx + i)->len;
            addrs[i]   = addr;           /* remember it so we can recycle below */
            void *pkt  = xsk_umem__get_data(buffer, addr);
            /* process pkt directly — zero copy */
            printf("got %u bytes: %02x:%02x:%02x:%02x:%02x:%02x ...\n",
                   len, ((__u8*)pkt)[0], ((__u8*)pkt)[1], ((__u8*)pkt)[2],
                   ((__u8*)pkt)[3], ((__u8*)pkt)[4], ((__u8*)pkt)[5]);
        }
        xsk_ring_cons__release(&rx, n);

        /* recycle: hand the same frames back to the driver via the FILL ring */
        __u32 idx_fq;
        __u32 reserved = xsk_ring_prod__reserve(&umem.fq, n, &idx_fq);
        if (reserved < n) {
            /* FILL ring full — driver hasn't drained yet; drop these or retry later */
        }
        for (__u32 i = 0; i < reserved; i++)
            *xsk_ring_prod__fill_addr(&umem.fq, idx_fq + i) = addrs[i];
        xsk_ring_prod__submit(&umem.fq, reserved);
    }

    bpf_map_delete_elem(xsks_map_fd, &qid);
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem.umem);
}
```

The important lifecycle is: create UMEM, bind an AF_XDP socket to `(ifname, queue)`, put the socket fd in `XSKMAP`, redirect by queue id, then remove the map entry before destroying the socket. This is busier than previous labs because AF_XDP exposes the rings directly. libxdp helps but doesn't hide everything.

### Run

First build a topology. XDP/AF_XDP on `veth1` only ever sees frames arriving **into** `veth1`, so the traffic has to originate from the peer end — we put that peer in its own namespace:

```bash
# Topology: veth0 (in lab netns) <-> veth1 (host, runs the AF_XDP receiver)
sudo ip netns add lab
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns lab
sudo ip netns exec lab ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec lab ip link set veth0 up
sudo ip addr add 10.0.0.2/24 dev veth1
sudo ip link set veth1 up
```

Now build and run the complete example (the chapter listings are a walk-through of it):

```bash
cd xdp-tutorial/advanced03-AF_XDP
make
sudo ./af_xdp_user -d veth1
```

In another terminal, drive ingress **into** `veth1` from the peer side:

```bash
sudo ip netns exec lab ping -c 5 10.0.0.2
```

You should see raw frame bytes / per-packet stats printed by the receiver. The XDP program redirects the ICMP echo requests to the AF_XDP socket *before* they reach the stack, so `ping` itself gets no replies — that's expected; all you care about is that the receiver prints the frames it pulled off the RX ring. On veth, stop there: it proves the redirect/ring lifecycle. Use a supported physical NIC and driver before making zero-copy throughput claims with packet generators (`pktgen`, `trafgen`).

Tear down the lab when you're done (this also removes the veth pair):

```bash
sudo ip netns del lab
```

---

## What to break, in order

### Break 1 — Forget the FILL ring

Skip the pre-fill. The driver has no buffers to DMA into, so the RX ring stays empty and the receiver prints nothing. Confirm the pings are actually arriving with `sudo tcpdump -ni veth1 icmp` in another terminal — when tcpdump shows the echo requests but the receiver still prints nothing, you know the empty RX ring is caused by the missing FILL pre-fill, not by absent traffic. The FILL ring is your handshake to the driver.

### Break 2 — Don't recycle

Skip the "refill FILL ring" step in the polling loop. After 4096 packets, the FILL ring is empty and the driver has nowhere to DMA new frames, so it drops them. Watch the per-queue drop counter climb in another terminal:

```bash
watch -n1 "ethtool -S veth1 | grep xdp_drops"
```

`rx_queue_0_xdp_drops` increments once the FILL ring drains (veth exposes per-queue `rx_queue_N_xdp_*` stats — pick the queue you bound to). A more direct, driver-independent check is to poll the socket's own counters with `getsockopt(xsk_fd, SOL_XDP, XDP_STATISTICS, &stats, &len)` and watch `stats.rx_dropped` rise, since redirect-to-a-starved-socket drops are accounted at the socket layer rather than always surfacing in a generic ethtool stat.

### Break 3 — Multi-queue

Real NICs have multiple RX queues. Spawn one userspace thread per queue, one AF_XDP socket each, all in the xskmap. RPS/RSS distributes packets across queues; each thread processes its queue independently. This is how you scale linearly with cores.

---

## What to read in the kernel

- **`net/xdp/xsk.c`** — the AF_XDP implementation. ~1800 lines. Read the top to understand the ring structures.
- **`net/xdp/xsk_queue.h`** — the lock-free ring code. Tight, copy-this-pattern level.
- **`include/uapi/linux/if_xdp.h`** — UAPI for AF_XDP rings, descriptors, configurations.
- **`tools/testing/selftests/bpf/xskxceiver.c`** — comprehensive AF_XDP test suite. Best example.
- **`samples/bpf/xdpsock_user.c`** — older but well-commented userspace example.

---

## Bullet Points

- **AF_XDP** is kernel-bypass for packet processing — polled rings and no syscalls in the steady-state receive loop (with `XDP_USE_NEED_WAKEUP`, poll the driver when it sets the need-wakeup flag); zero-copy requires driver/NIC support.
- Architecture: UMEM (user memory) + 4 rings (FILL, RX, TX, COMP) + XDP redirect.
- BPF side is one line: `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0)`.
- Throughput: **30+ Mpps per core** is a supported-NIC zero-copy result; veth/copy mode is for functional learning.
- Use **libxdp** (`xsk.h`) for ring helpers; raw kernel UAPI is doable but verbose.
- Modes: zero-copy (best), copy-mode (universal, slower).
- Cooperates with the kernel — you can split queues between AF_XDP and the kernel stack.

---

## Check question

If you don't refill the FILL ring, what's the symptom?

<details>
<summary>Click to reveal answer</summary>

**Answer:** The kernel runs out of UMEM buffers to DMA new packets into. New packets are silently dropped at the driver level (an NIC stat increments). Your RX ring stays empty even though traffic is hitting the wire. The "feed me more" half of the loop is FILL ring refilling — every consumed packet's address must be returned for reuse, or you starve the driver.

</details>

---

## Tomorrow

Day 19: cgroup BPF and sockops — per-cgroup network policy and TCP tuning. Less hot-path, more configuration-plane.
