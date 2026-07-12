// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "count.skel.h"

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

static int dump_counts(int map_fd)
{
    const __u32 *previous = NULL;
    __u32 key;
    __u32 next;
    __u64 value;
    int ret;

    puts("--- snapshot ---");
    errno = 0;
    while ((ret = bpf_map_get_next_key(map_fd, previous, &next)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next, &value) == 0)
            printf("PID %u: %llu unlinks\n", next,
                   (unsigned long long)value);
        else if (errno != ENOENT)
            fprintf(stderr, "lookup failed for PID %u: %s\n", next,
                    strerror(errno));

        key = next;
        previous = &key;
        errno = 0;
    }

    if (ret != 0 && errno != ENOENT) {
        fprintf(stderr, "map iteration failed: %s\n", strerror(errno));
        return -errno;
    }

    return 0;
}

int main(void)
{
    struct count_bpf *skel = NULL;
    int map_fd;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = count_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open count BPF skeleton\n");
        return 1;
    }

    err = count_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load count BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = count_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach count BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.counts);
    puts("Counting unlink calls; press Ctrl-C to stop.");
    while (!exiting) {
        unsigned int remaining = sleep(2);

        if (exiting)
            break;
        if (remaining != 0)
            continue;

        err = dump_counts(map_fd);
        if (err)
            goto cleanup;
    }

    err = 0;

cleanup:
    count_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
