// ANCHOR: book
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_count.skel.h"

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

int main(int argc, char **argv)
{
    struct xdp_count_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    unsigned int ifindex;
    int ncpu;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return 1;
    }
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = xdp_count_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load xdp_count BPF skeleton\n");
        return 1;
    }

    link = bpf_program__attach_xdp(skel->progs.xdp_count, ifindex);
    if (!link) {
        err = -errno;
        fprintf(stderr, "failed to attach XDP program to ifindex %u: %s\n",
                ifindex, strerror(errno));
        goto cleanup;
    }

    ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) {
        fprintf(stderr, "libbpf_num_possible_cpus failed\n");
        err = 1;
        goto cleanup;
    }

    printf("Counting packets per IP protocol on %s; press Ctrl-C to stop.\n",
           argv[1]);
    while (!exiting) {
        int fd;

        if (sleep(2) != 0)
            continue;

        fd = bpf_map__fd(skel->maps.counts);
        for (__u32 k = 0; k < 256; k++) {
            __u64 vals[ncpu];

            if (bpf_map_lookup_elem(fd, &k, vals) == 0) {
                __u64 sum = 0;

                for (int i = 0; i < ncpu; i++)
                    sum += vals[i];
                if (sum)
                    printf("proto %3u: %llu\n", k, sum);
            }
        }
        printf("---\n");
    }

    err = 0;

cleanup:
    bpf_link__destroy(link);
    xdp_count_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
