// ANCHOR: book
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "stacks.skel.h"

#define MAX_STACK_DEPTH 64

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

/* Dump every (kernel, user) stack pair with its count, printing raw return
 * addresses as hex. Symbolizing those addresses is the plumbing bpftool and
 * libblazesym exist for; Day 9 is about capturing the data. */
static int dump_stacks(int cnt_fd, int stk_fd)
{
    __u64 kframes[MAX_STACK_DEPTH];
    __u64 uframes[MAX_STACK_DEPTH];
    const __u64 *previous = NULL;
    __u64 key;
    __u64 next;
    __u64 val;
    int ret;

    puts("--- stack snapshot ---");
    errno = 0;
    while ((ret = bpf_map_get_next_key(cnt_fd, previous, &next)) == 0) {
        __u32 kid = next >> 32;
        __u32 uid = next & 0xffffffff;
        int i;

        if (bpf_map_lookup_elem(cnt_fd, &next, &val) != 0)
            goto advance;

        memset(kframes, 0, sizeof(kframes));
        memset(uframes, 0, sizeof(uframes));
        bpf_map_lookup_elem(stk_fd, &kid, kframes);
        bpf_map_lookup_elem(stk_fd, &uid, uframes);

        printf("[count=%llu]\n", (unsigned long long)val);
        for (i = 0; i < MAX_STACK_DEPTH && kframes[i]; i++)
            printf("  K %llx\n", (unsigned long long)kframes[i]);
        for (i = 0; i < MAX_STACK_DEPTH && uframes[i]; i++)
            printf("  U %llx\n", (unsigned long long)uframes[i]);
        printf("\n");

advance:
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
    struct stacks_bpf *skel = NULL;
    int cnt_fd;
    int stk_fd;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    skel = stacks_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open stacks BPF skeleton\n");
        return 1;
    }

    err = stacks_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load stacks BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    err = stacks_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach stacks BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    cnt_fd = bpf_map__fd(skel->maps.counts);
    stk_fd = bpf_map__fd(skel->maps.stacks);

    puts("Sampling vfs_read stacks; dumping every 5s. Press Ctrl-C to stop.");
    while (!exiting) {
        unsigned int remaining = sleep(5);

        if (exiting)
            break;
        if (remaining != 0)
            continue;

        err = dump_stacks(cnt_fd, stk_fd);
        if (err)
            goto cleanup;
    }

    err = 0;

cleanup:
    stacks_bpf__destroy(skel);
    return err != 0;
}
// ANCHOR_END: book
