// ANCHOR: book
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "tune.skel.h"

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

/* Open the cgroup v2 directory whose fd is the cgroup-BPF attach target.
 * O_DIRECTORY makes a non-directory (or missing) path fail cleanly instead
 * of attaching to something unexpected. Empty arguments are rejected. */
static int open_cgroup_dir(const char *path)
{
    int fd;

    if (path == NULL || path[0] == '\0') {
        fprintf(stderr, "cgroup path must be a non-empty directory\n");
        return -1;
    }

    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "failed to open cgroup dir '%s': %s\n", path,
                strerror(errno));
        return -1;
    }

    return fd;
}

int main(int argc, char **argv)
{
    const char *cg_path;
    struct tune_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc != 2) {
        fprintf(stderr, "usage: %s <owned-cgroup-v2-directory>\n", argv[0]);
        return 2;
    }
    cg_path = argv[1];

    err = install_signal_handlers();
    if (err)
        return 1;

    cg_fd = open_cgroup_dir(cg_path);
    if (cg_fd < 0)
        return 1;

    skel = tune_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load tune BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach_cgroup(skel->progs.tcp_tune, cg_fd);
    if (!link) {
        err = -errno;
        fprintf(stderr, "failed to attach sockops to '%s': %s\n",
                cg_path, strerror(errno));
        goto cleanup;
    }

    printf("attached sockops TCP tuner to %s; Ctrl-C to detach\n", cg_path);
    while (!exiting)
        pause();

    err = 0;

cleanup:
    bpf_link__destroy(link);
    tune_bpf__destroy(skel);
    if (cg_fd >= 0)
        close(cg_fd);
    return err != 0;
}
// ANCHOR_END: book
