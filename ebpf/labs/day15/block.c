// ANCHOR: book
/* Day 15 — loader for the XDP LPM-trie firewall.
 *
 * Usage: sudo ./block IFACE [OWNED_PIN_DIRECTORY]
 *
 * The optional directory must not already exist. The loader creates it, pins
 * both maps for blockcli, and removes the pins and directory on every exit.
 */
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "block.skel.h"

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
    struct block_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    char default_dir[PATH_MAX];
    char deny_pin[PATH_MAX];
    char stats_pin[PATH_MAX];
    const char *pin_dir;
    unsigned int ifindex;
    int dir_created = 0;
    int deny_pinned = 0;
    int stats_pinned = 0;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s IFACE [OWNED_PIN_DIRECTORY]\n", argv[0]);
        return 1;
    }
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    if (argc == 3) {
        pin_dir = argv[2];
    } else {
        snprintf(default_dir, sizeof(default_dir),
                 "/sys/fs/bpf/practical-ebpf-day15-%ld", (long)getpid());
        pin_dir = default_dir;
    }
    if (snprintf(deny_pin, sizeof(deny_pin), "%s/deny", pin_dir) >=
            (int)sizeof(deny_pin) ||
        snprintf(stats_pin, sizeof(stats_pin), "%s/stats", pin_dir) >=
            (int)sizeof(stats_pin)) {
        fprintf(stderr, "pin directory path is too long\n");
        return 1;
    }

    err = install_signal_handlers();
    if (err)
        return 1;

    if (mkdir(pin_dir, 0700) != 0) {
        fprintf(stderr, "refusing pin directory %s: %s\n", pin_dir,
                strerror(errno));
        return 1;
    }
    dir_created = 1;

    skel = block_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load block BPF skeleton\n");
        err = -errno;
        goto cleanup;
    }

    err = bpf_map__pin(skel->maps.deny, deny_pin);
    if (err) {
        fprintf(stderr, "failed to pin %s: %s\n", deny_pin, strerror(-err));
        goto cleanup;
    }
    deny_pinned = 1;

    err = bpf_map__pin(skel->maps.stats, stats_pin);
    if (err) {
        fprintf(stderr, "failed to pin %s: %s\n", stats_pin, strerror(-err));
        goto cleanup;
    }
    stats_pinned = 1;

    link = bpf_program__attach_xdp(skel->progs.xdp_block, ifindex);
    if (!link) {
        err = -errno;
        fprintf(stderr, "failed to attach XDP program to %s: %s\n",
                argv[1], strerror(errno));
        goto cleanup;
    }

    printf("Firewall attached to %s. Manage it with:\n"
           "  blockcli %s add|del <CIDR>\n"
           "  blockcli %s stats\n"
           "Press Ctrl-C to detach and remove the owned pins.\n",
           argv[1], pin_dir, pin_dir);
    while (!exiting)
        pause();
    err = 0;

cleanup:
    bpf_link__destroy(link);
    if (stats_pinned)
        unlink(stats_pin);
    if (deny_pinned)
        unlink(deny_pin);
    block_bpf__destroy(skel);
    if (dir_created && rmdir(pin_dir) != 0 && errno != ENOENT) {
        fprintf(stderr, "failed to remove owned pin directory %s: %s\n",
                pin_dir, strerror(errno));
        if (!err)
            err = -errno;
    }
    return err != 0;
}
// ANCHOR_END: book
