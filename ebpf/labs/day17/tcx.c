// ANCHOR: book
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tcx.skel.h"          /* generated from tcx.bpf.o */

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

static int sum_slot(int fd, __u32 key, int ncpu, __u64 *out)
{
    __u64 vals[ncpu];
    __u64 total = 0;

    if (bpf_map_lookup_elem(fd, &key, vals) != 0)
        return -1;
    for (int i = 0; i < ncpu; i++)
        total += vals[i];
    *out = total;
    return 0;
}

int main(int argc, char **argv)
{
    struct tcx_bpf *skel = NULL;
    struct bpf_link *l1 = NULL;   /* counter */
    struct bpf_link *l2 = NULL;   /* firewall */
    unsigned int ifindex;
    int fd, ncpu;
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

    skel = tcx_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load tcx BPF skeleton\n");
        return 1;
    }

    /* counter goes first */
    LIBBPF_OPTS(bpf_tcx_opts, opts1);
    l1 = bpf_program__attach_tcx(skel->progs.counter, ifindex, &opts1);
    if (!l1) {
        err = -errno;
        fprintf(stderr, "attach counter failed: %s\n", strerror(errno));
        goto cleanup;
    }

    /* firewall goes after counter */
    LIBBPF_OPTS(bpf_tcx_opts, opts2, .flags = BPF_F_AFTER);
    l2 = bpf_program__attach_tcx(skel->progs.firewall, ifindex, &opts2);
    if (!l2) {
        err = -errno;
        fprintf(stderr, "attach firewall failed: %s\n", strerror(errno));
        goto cleanup;
    }

    ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) {
        fprintf(stderr, "libbpf_num_possible_cpus failed\n");
        err = 1;
        goto cleanup;
    }

    fd = bpf_map__fd(skel->maps.stats);
    printf("tcx counter+firewall attached to %s; press Ctrl-C to stop.\n",
           argv[1]);
    while (!exiting) {
        __u64 total = 0, udp_drop = 0;

        sum_slot(fd, 0, ncpu, &total);      /* key 0: all packets */
        sum_slot(fd, 1, ncpu, &udp_drop);   /* key 1: dropped UDP */
        printf("total: %llu  udp_drop: %llu\n", total, udp_drop);

        if (sleep(2) != 0)
            break;
    }

    err = 0;

cleanup:
    bpf_link__destroy(l2);   /* detaches; FD-based */
    bpf_link__destroy(l1);
    tcx_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
