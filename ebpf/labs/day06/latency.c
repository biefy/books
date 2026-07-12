// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "latency.h"
#include "latency.skel.h"

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

    printf("PID %u TID %u vfs_read \xE2\x86\x92 %lld bytes in %llu \xC2\xB5s (%s)\n",
           e->pid, e->tid, (long long)e->ret,
           (unsigned long long)e->dur_ns / 1000, e->comm);
    return 0;
}

int main(void)
{
    struct latency_bpf *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open latency BPF skeleton\n");
        return 1;
    }

    err = latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load latency BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach latency BPF programs: %s\n",
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

    puts("Measuring vfs_read latency; press Ctrl-C to stop.");
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
    latency_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
