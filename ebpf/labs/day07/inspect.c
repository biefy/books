// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "inspect.skel.h"

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
    /* Log level 2 prints the per-instruction register state (the R1_w=...
     * lines) the chapter reads for each of the three program types. */
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 2);
    struct inspect_bpf *skel = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = inspect_bpf__open_opts(&opts);
    if (!skel) {
        fprintf(stderr, "failed to open inspect BPF skeleton\n");
        return 1;
    }

    err = inspect_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load inspect BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = inspect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach inspect BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    puts("All three programs attached; read "
         "/sys/kernel/tracing/trace_pipe. Press Ctrl-C to stop.");
    while (!exiting)
        sleep(1);

    err = 0;

cleanup:
    inspect_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
