// ANCHOR: book
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "xsk.skel.h"

#define UMEM_NUM_FRAMES 4096
#define FRAME_SIZE      2048
#define RX_BATCH_SIZE   64
#define FILL_RING_SIZE  XSK_RING_PROD__DEFAULT_NUM_DESCS  /* 2048 */
#define COMP_RING_SIZE  XSK_RING_CONS__DEFAULT_NUM_DESCS  /* 2048 */

static volatile sig_atomic_t exiting;

/* XDP attach mode actually used, remembered so teardown detaches with the
 * same flags it attached with. */
static __u32 xdp_flags;

struct umem_info {
    void *buffer;
    struct xsk_ring_prod fq;   /* FILL ring   (user -> kernel) */
    struct xsk_ring_cons cq;   /* COMPLETION  (kernel -> user) */
    struct xsk_umem *umem;
};

struct xsk_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_socket *xsk;
};

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

static int install_signal_handlers(void)
{
    const struct sigaction action = {
        .sa_handler = handle_signal,
    };

    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        fprintf(stderr, "failed to install signal handlers: %s\n",
                strerror(errno));
        return -errno;
    }

    return 0;
}

/* Attach the XDP program ourselves so we control the mode. Try native/driver
 * mode first (fast path on real NICs and modern veth), then fall back to the
 * universal SKB/generic mode so the lab still runs on drivers without a native
 * XDP path. The flags that succeed are stored for the matching detach. */
static int attach_xdp(int ifindex, int prog_fd)
{
    const __u32 modes[] = { XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
    int err = -1;

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        err = bpf_xdp_attach(ifindex, prog_fd, modes[i], NULL);
        if (err == 0) {
            xdp_flags = modes[i];
            return 0;
        }
    }

    fprintf(stderr, "failed to attach XDP program (native and skb): %s\n",
            strerror(-err));
    return err;
}

/* Prefill the FILL ring: producer protocol reserve -> write -> submit. Each
 * entry is a byte OFFSET into UMEM (frame i lives at i * FRAME_SIZE), never a
 * pointer. Skipping this is Break 1 (the driver never gets a frame to DMA
 * into, RX stays empty). */
static int umem_prefill(struct umem_info *umem)
{
    __u32 idx = 0;
    __u32 got;

    got = xsk_ring_prod__reserve(&umem->fq, FILL_RING_SIZE, &idx);
    if (got != FILL_RING_SIZE) {
        fprintf(stderr, "could not reserve FILL ring (%u/%u)\n", got,
                (unsigned int)FILL_RING_SIZE);
        return -1;
    }

    for (__u32 i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx + i) =
            (__u64)i * FRAME_SIZE;

    xsk_ring_prod__submit(&umem->fq, got);
    return 0;
}

/* Return each consumed frame's offset to the FILL ring so the driver can DMA
 * into it again. Skipping this is Break 2 (the driver starves after the pool
 * drains and the kernel bumps rx_dropped / rx_queue_full). */
static void umem_recycle(struct umem_info *umem, const __u64 *addrs,
                         unsigned int n)
{
    __u32 idx = 0;
    unsigned int reserved;

    reserved = xsk_ring_prod__reserve(&umem->fq, n, &idx);
    for (unsigned int i = 0; i < reserved; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&umem->fq, reserved);

    if (reserved < n)
        fprintf(stderr,
                "FILL ring full: %u frame(s) not recycled this round\n",
                n - reserved);
}

int main(int argc, char **argv)
{
    struct umem_info umem = {0};
    struct xsk_info xsk = {0};
    struct xsk_bpf *skel = NULL;
    struct xsk_umem_config umem_cfg = {
        .fill_size = FILL_RING_SIZE,
        .comp_size = COMP_RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };
    const size_t umem_size = (size_t)UMEM_NUM_FRAMES * FRAME_SIZE;
    unsigned long long received = 0;
    struct pollfd pfd;
    int ifindex;
    int xsk_fd = -1;
    int map_fd = -1;
    int xdp_attached = 0;
    __u32 qid = 0;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc != 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 2;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "unknown interface '%s': %s\n", argv[1],
                strerror(errno));
        return 1;
    }

    err = install_signal_handlers();
    if (err)
        return 1;

    /* 1. Load the XDP redirect program and get the XSKMAP fd. */
    skel = xsk_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load xsk BPF skeleton\n");
        return 1;
    }
    map_fd = bpf_map__fd(skel->maps.xsks_map);

    /* 2. Attach XDP to the interface (native, else SKB). */
    err = attach_xdp(ifindex, bpf_program__fd(skel->progs.xsk_redirect));
    if (err)
        goto cleanup;
    xdp_attached = 1;

    /* 3. Allocate page-aligned UMEM: NUM_FRAMES chunks of FRAME_SIZE. */
    if (posix_memalign(&umem.buffer, sysconf(_SC_PAGESIZE), umem_size) != 0) {
        fprintf(stderr, "posix_memalign(%zu) failed\n", umem_size);
        err = 1;
        goto cleanup;
    }

    /* xsk_umem__create wraps socket(AF_XDP) + setsockopt(XDP_UMEM_REG) and
       sizes/mmaps the FILL (fq) and COMPLETION (cq) rings. */
    err = xsk_umem__create(&umem.umem, umem.buffer, umem_size, &umem.fq,
                           &umem.cq, &umem_cfg);
    if (err) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-err));
        goto cleanup;
    }

    /* 4. Create the AF_XDP socket bound to (ifname, queue 0). INHIBIT_PROG_LOAD
       tells libxdp not to load/attach its own program or manage the map — we
       own both. This wraps setsockopt(XDP_RX_RING/XDP_TX_RING), the ring
       mmaps, and bind(sockaddr_xdp). */
    err = xsk_socket__create(&xsk.xsk, argv[1], qid, umem.umem, &xsk.rx,
                             &xsk.tx, &xsk_cfg);
    if (err) {
        fprintf(stderr, "xsk_socket__create failed on %s queue %u: %s\n",
                argv[1], qid, strerror(-err));
        goto cleanup;
    }
    xsk_fd = xsk_socket__fd(xsk.xsk);

    /* 5. Arm queue 0: insert the socket fd into the XSKMAP. The redirect only
       fires AFTER this insert — that is what "arming" means. */
    err = bpf_map_update_elem(map_fd, &qid, &xsk_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to arm XSKMAP slot %u: %s\n", qid,
                strerror(errno));
        goto cleanup;
    }

    /* 6. Pre-fill the FILL ring so the driver has frames to DMA into. */
    err = umem_prefill(&umem);
    if (err)
        goto cleanup;

    printf("AF_XDP receiver up on %s (queue %u, %s mode); Ctrl-C to stop.\n",
           argv[1], qid,
           xdp_flags == XDP_FLAGS_DRV_MODE ? "native" : "skb");

    pfd.fd = xsk_fd;
    pfd.events = POLLIN;

    /* 7. Receive loop: consumer protocol peek -> read -> release, then recycle
       the frames back to the FILL ring to close the ownership cycle. */
    while (!exiting) {
        __u64 addrs[RX_BATCH_SIZE];
        __u32 idx_rx = 0;
        unsigned int n;

        /* With XDP_USE_NEED_WAKEUP the driver may be asleep; poke it. */
        if (xsk_ring_prod__needs_wakeup(&umem.fq))
            recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);

        err = poll(&pfd, 1, 200);
        if (err < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "poll failed: %s\n", strerror(errno));
            goto cleanup;
        }
        if (err == 0)
            continue;

        n = xsk_ring_cons__peek(&xsk.rx, RX_BATCH_SIZE, &idx_rx);
        if (n == 0)
            continue;

        for (unsigned int i = 0; i < n; i++) {
            const struct xdp_desc *d =
                xsk_ring_cons__rx_desc(&xsk.rx, idx_rx + i);
            __u64 addr = d->addr;      /* byte offset into UMEM */
            __u32 len = d->len;        /* real packet length    */
            const __u8 *pkt = xsk_umem__get_data(umem.buffer, addr);

            addrs[i] = addr;           /* remember for recycling */
            received++;
            if (len >= 6)
                printf("rx %u bytes  %02x:%02x:%02x:%02x:%02x:%02x ...  "
                       "(total %llu)\n",
                       len, pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
                       received);
            else
                printf("rx %u bytes (short frame)  (total %llu)\n", len,
                       received);
        }

        xsk_ring_cons__release(&xsk.rx, n);
        umem_recycle(&umem, addrs, n);
    }

    err = 0;

cleanup:
    /* Teardown order matters: remove the XSKMAP entry BEFORE destroying the
       socket, or the map would hold a dangling reference to a freed socket. */
    if (map_fd >= 0 && xsk_fd >= 0)
        bpf_map_delete_elem(map_fd, &qid);
    if (xsk.xsk)
        xsk_socket__delete(xsk.xsk);
    if (umem.umem)
        xsk_umem__delete(umem.umem);
    free(umem.buffer);
    if (xdp_attached)
        bpf_xdp_detach(ifindex, xdp_flags, NULL);
    xsk_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
