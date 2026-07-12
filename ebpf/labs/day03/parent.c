// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "parent.h"
#include "parent.skel.h"

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
    const struct parent_event *event = data;

    (void)ctx;
    if (size != sizeof(*event)) {
        fprintf(stderr, "unexpected ringbuf record size: %zu\n", size);
        return 0;
    }

    printf("PID %u (%.*s) ppid %u (%.*s) deleted a file\n",
           event->pid, (int)sizeof(event->comm), event->comm,
           event->ppid, (int)sizeof(event->parent_comm), event->parent_comm);
    return 0;
}

int main(void)
{
    struct parent_bpf *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = parent_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open parent BPF skeleton\n");
        return 1;
    }

    err = parent_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load parent BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = parent_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach parent BPF programs: %s\n",
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

    puts("Tracing unlink callers and parents; press Ctrl-C to stop.");
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
    parent_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
