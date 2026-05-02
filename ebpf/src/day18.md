# Day 18 — AF_XDP: zero-copy packets to userspace at line rate

> **Today's mission:** redirect raw packets from XDP to a userspace ring at line rate without copying. Build a tiny zero-copy packet receiver. Total time: ~90 minutes.

## Why bypass the stack

The Linux network stack is general-purpose. For most workloads that's fine — sockets, retransmits, congestion control, all done for you. But for packet-processing apps (DPI, custom load balancers, network testing, telemetry pipelines), the stack adds overhead you don't want: skb allocation, protocol parsing you'll redo anyway, syscalls per packet.

**AF_XDP** is the kernel's answer to DPDK: zero-copy packet receive directly from the NIC into userspace memory, with no syscalls in the fast path.

![AF_XDP architecture](diagrams/day18_afxdp.png)

The trick: userspace pre-allocates a memory region (UMEM) and registers it with the kernel. The NIC driver DMAs incoming packets directly into that memory. An XDP program redirects to an AF_XDP socket bound to that UMEM. Userspace polls a ring of descriptors pointing into UMEM — no copy, ever.

Throughput on commodity hardware: 30+ Mpps per core. With multi-queue, you scale linearly with cores.

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
sudo apt install libxdp-dev libbpf-dev linux-headers-$(uname -r)
git clone https://github.com/xdp-project/xdp-tutorial
# Use xdp-tutorial/advanced03-AF_XDP as a reference
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

### `xsk_recv.c` — userspace receiver (skeleton)

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

    /* 4. Pre-fill the FILL ring */
    __u32 idx;
    xsk_ring_prod__reserve(&umem.fq, UMEM_NUM_FRAMES, &idx);
    for (int i = 0; i < UMEM_NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&umem.fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&umem.fq, UMEM_NUM_FRAMES);

    /* 5. Poll loop */
    while (!exiting) {
        __u32 idx_rx, n;
        n = xsk_ring_cons__peek(&rx, 64, &idx_rx);
        if (!n) {
            usleep(10);
            continue;
        }
        for (__u32 i = 0; i < n; i++) {
            __u64 addr = xsk_ring_cons__rx_desc(&rx, idx_rx + i)->addr;
            __u32 len  = xsk_ring_cons__rx_desc(&rx, idx_rx + i)->len;
            void *pkt  = xsk_umem__get_data(buffer, addr);
            /* process pkt directly — zero copy */
            printf("got %u bytes: %02x:%02x:%02x:%02x:%02x:%02x ...\n",
                   len, ((__u8*)pkt)[0], ((__u8*)pkt)[1], ((__u8*)pkt)[2],
                   ((__u8*)pkt)[3], ((__u8*)pkt)[4], ((__u8*)pkt)[5]);
        }
        xsk_ring_cons__release(&rx, n);

        /* recycle: refill the FILL ring */
        __u32 idx_fq;
        xsk_ring_prod__reserve(&umem.fq, n, &idx_fq);
        /* ...mark these addrs available... */
        xsk_ring_prod__submit(&umem.fq, n);
    }
}
```

This is busier than previous labs because AF_XDP exposes the rings directly. libxdp helps but doesn't hide everything.

### Run

```bash
sudo ./xsk_recv veth1
# Other terminal: send packets
ping -c 5 10.0.0.2
```

You should see raw frame bytes printed. Throughput-test with packet generators (`pktgen`, `trafgen`) to confirm Mpps.

---

## What to break, in order

### Break 1 — Forget the FILL ring

Skip the pre-fill. Driver has no buffers to DMA into. RX ring stays empty; you observe nothing. The FILL ring is your handshake to the driver.

### Break 2 — Don't recycle

Skip the "refill FILL ring" step in the polling loop. After 4096 packets, the FILL ring is empty; the driver drops new packets. Watch a `ethtool -S veth1` counter increment.

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

- **AF_XDP** is kernel-bypass for packet processing — zero copy, polled rings, no syscalls in the fast path.
- Architecture: UMEM (user memory) + 4 rings (FILL, RX, TX, COMP) + XDP redirect.
- BPF side is one line: `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0)`.
- Throughput: **30+ Mpps per core**, scales linearly with multi-queue.
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
