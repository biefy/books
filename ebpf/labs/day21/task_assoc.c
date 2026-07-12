// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "task_assoc.skel.h"

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
    struct task_assoc_bpf *skel = NULL;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = task_assoc_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open task_assoc BPF skeleton\n");
        return 1;
    }

    err = task_assoc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load task_assoc BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = task_assoc_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach task_assoc BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    puts("Attached fentry+fexit/filename_unlinkat; watch trace_pipe. "
         "Press Ctrl-C to detach.");
    while (!exiting)
        pause();

    err = 0;

cleanup:
    task_assoc_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
