// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "reject.skel.h"

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

int main(void)
{
    /* kernel_log_level = 1 makes libbpf print the verifier log on every load,
     * so a rejection you introduce by editing reject.bpf.c is visible here. */
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 1);
    struct reject_bpf *skel = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = reject_bpf__open_opts(&opts);
    if (!skel) {
        fprintf(stderr, "failed to open reject BPF skeleton\n");
        return 1;
    }

    err = reject_bpf__load(skel);
    if (err) {
        fprintf(stderr, "load failed (this is expected once you break the "
                        "program): %s\n", strerror(-err));
        goto cleanup;
    }

    err = reject_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach reject BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    puts("reject.bpf.c loaded clean; press Ctrl-C to stop.");
    while (!exiting)
        sleep(1);

    err = 0;

cleanup:
    reject_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
