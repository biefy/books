// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "schedlat.h"
#include "schedlat.skel.h"

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
    const struct event *e = data;

    (void)ctx;
    if (size != sizeof(*e)) {
        fprintf(stderr, "unexpected ringbuf record size: %zu\n", size);
        return 0;
    }

    printf("%s [%u] waited %llu \xC2\xB5s after %s [%u]\n",
           e->next_comm, e->next_pid,
           (unsigned long long)e->wait_ns / 1000,
           e->prev_comm, e->prev_pid);
    return 0;
}

int main(void)
{
    struct schedlat_bpf *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = schedlat_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open schedlat BPF skeleton\n");
        return 1;
    }

    err = schedlat_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load schedlat BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = schedlat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach schedlat BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event,
                               NULL, NULL);
    err = libbpf_get_error(ringbuf);
    if (err) {
        ringbuf = NULL;
        fprintf(stderr, "failed to create ringbuf consumer: %s\n",
                strerror(-err));
        goto cleanup;
    }

    puts("Measuring per-task scheduling latency; press Ctrl-C to stop.");
    while (!exiting) {
        err = ring_buffer__poll(ringbuf, 100);
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "ringbuf poll failed: %s\n", strerror(-err));
            goto cleanup;
        }
    }

    err = 0;

cleanup:
    ring_buffer__free(ringbuf);
    schedlat_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
