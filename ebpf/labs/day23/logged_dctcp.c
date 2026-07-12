// SPDX-License-Identifier: GPL-2.0
/*
 * logged_dctcp.c — userspace loader for the Day 23 telemetry DCTCP derivative.
 *
 * PROVENANCE / STRUCTURE
 *   The BPF object it loads is derived from the kernel's bpf_dctcp selftest
 *   (see logged_dctcp.bpf.c). This loader follows the Day 3 ringbuf loader
 *   (open/load/attach, SIGINT/SIGTERM teardown, record-size validation) plus a
 *   struct_ops attach: bpf_map__attach_struct_ops() registers the CC with the
 *   kernel, and destroying that link on exit detaches and unregisters it.
 *
 *   The loader owns exactly one BPF link, one ring_buffer consumer, and one
 *   skeleton; every exit path frees all three, so nothing is left registered
 *   in the CC framework and nothing is pinned in bpffs.
 */
// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "logged_dctcp.h"
#include "logged_dctcp.skel.h"

static volatile sig_atomic_t exiting;

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

static int handle_event(void *ctx, void *data, size_t size)
{
    const struct tcp_event *e = data;

    (void)ctx;
    if (size != sizeof(*e)) {
        fprintf(stderr, "unexpected ringbuf record size: %zu\n", size);
        return 0;
    }

    printf("[sk=%llu t=%lluns] cwnd=%u in_flight=%u srtt=%uus\n",
           (unsigned long long)e->sk_cookie, (unsigned long long)e->ts_ns,
           e->cwnd, e->in_flight, e->srtt_us);
    return 0;
}

int main(void)
{
    struct logged_dctcp_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = logged_dctcp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load logged_dctcp skeleton\n");
        return 1;
    }

    /* struct_ops attach registers "bpf_dctcp_log" in the TCP CC framework. */
    link = bpf_map__attach_struct_ops(skel->maps.dctcp);
    if (!link) {
        err = -errno;
        fprintf(stderr,
                "failed to attach struct_ops (need root or CAP_BPF): %s\n",
                strerror(errno));
        goto cleanup;
    }

    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event,
                               NULL, NULL);
    if (!ringbuf) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    fprintf(stderr,
            "bpf_dctcp_log registered; select it per-socket with "
            "'-C bpf_dctcp_log'. Ctrl-C to detach.\n");

    while (!exiting) {
        err = ring_buffer__poll(ringbuf, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll failed: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(ringbuf);
    bpf_link__destroy(link);            /* detaches + unregisters bpf_dctcp_log */
    logged_dctcp_bpf__destroy(skel);
    return err ? 1 : 0;
}
// ANCHOR_END: book
