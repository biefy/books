// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dropviz.h"
#include "dropviz.skel.h"

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

    printf("%-16.*s pid=%-7u dur=%llu ns\n", (int)sizeof(e->comm), e->comm,
           e->pid, e->dur);
    return 0;
}

/* Sample the per-CPU drops counter and sum across CPUs. */
static void sample_drops(int fd)
{
    int ncpu = libbpf_num_possible_cpus();
    __u64 total = 0;
    __u32 key = 0;

    if (ncpu <= 0)
        return;

    __u64 vals[ncpu];
    if (bpf_map_lookup_elem(fd, &key, vals) != 0)
        return;
    for (int i = 0; i < ncpu; i++)
        total += vals[i];
    fprintf(stderr, "[total drops: %llu]\n", total);
}

int main(void)
{
    struct dropviz_bpf *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    struct timespec last, now;
    int drops_fd;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = dropviz_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load dropviz BPF skeleton\n");
        return 1;
    }

    err = dropviz_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach dropviz BPF programs: %s\n",
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

    drops_fd = bpf_map__fd(skel->maps.drops);

    puts("Tracing vfs_read latency; sampling drops every ~1s. "
         "press Ctrl-C to stop.");
    clock_gettime(CLOCK_MONOTONIC, &last);
    while (!exiting) {
        err = ring_buffer__poll(ringbuf, 100);   /* 100 ms timeout */
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "ringbuf poll failed: %s\n", strerror(-err));
            goto cleanup;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - last.tv_sec >= 1) {   /* ~1s tick */
            sample_drops(drops_fd);
            last = now;
        }
    }

    err = 0;

cleanup:
    ring_buffer__free(ringbuf);
    dropviz_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
