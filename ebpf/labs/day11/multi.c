// ANCHOR: book
/*
 * Day 11 — multi: attach one program to every vfs_* function via
 * kprobe.multi, then aggregate hit counts per function ip.
 *
 * The chapter presents lookup_ksym() as "a few-line function you write."
 * This file supplies a complete, runnable implementation: it snapshots
 * /proc/kallsyms once at startup, sorts it by address, and resolves each
 * hit ip to the nearest preceding symbol (the Day 9 technique).
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "multi.skel.h"

struct ksym {
    unsigned long addr;
    char name[96];
};

static struct ksym *ksyms;
static size_t ksym_count;

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

static int ksym_cmp(const void *a, const void *b)
{
    const struct ksym *ka = a;
    const struct ksym *kb = b;

    if (ka->addr < kb->addr)
        return -1;
    if (ka->addr > kb->addr)
        return 1;
    return 0;
}

/*
 * Snapshot /proc/kallsyms into a sorted array. Requires root for real
 * addresses (kptr_restrict zeroes them otherwise). Returns 0 on success.
 */
static int load_ksyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "open /proc/kallsyms: %s\n", strerror(errno));
        return -errno;
    }

    size_t cap = 1 << 16;
    ksyms = malloc(cap * sizeof(*ksyms));
    if (!ksyms) {
        fclose(f);
        return -ENOMEM;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long addr;
        char type;
        char name[96];

        if (sscanf(line, "%lx %c %95s", &addr, &type, name) != 3)
            continue;
        if (addr == 0)
            continue;

        if (ksym_count == cap) {
            cap *= 2;
            struct ksym *grown = realloc(ksyms, cap * sizeof(*ksyms));
            if (!grown) {
                free(ksyms);
                ksyms = NULL;
                fclose(f);
                return -ENOMEM;
            }
            ksyms = grown;
        }

        ksyms[ksym_count].addr = addr;
        snprintf(ksyms[ksym_count].name, sizeof(ksyms[ksym_count].name),
                 "%s", name);
        ksym_count++;
    }
    fclose(f);

    if (ksym_count == 0) {
        fprintf(stderr,
                "no symbols read from /proc/kallsyms (need root?)\n");
        return -ENOENT;
    }

    qsort(ksyms, ksym_count, sizeof(*ksyms), ksym_cmp);
    return 0;
}

/* Nearest symbol at or below addr; falls back to a hex string. */
static const char *lookup_ksym(unsigned long addr)
{
    static char hexbuf[19];
    size_t lo = 0;
    size_t hi = ksym_count;
    size_t best = ksym_count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (ksyms[mid].addr <= addr) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if (best != ksym_count)
        return ksyms[best].name;

    snprintf(hexbuf, sizeof(hexbuf), "0x%lx", addr);
    return hexbuf;
}

static int dump_hits(int map_fd)
{
    __u64 key = 0;
    __u64 next;
    __u64 value;
    const __u64 *prev = NULL;
    int ret;

    puts("--- vfs_* hits ---");
    errno = 0;
    while ((ret = bpf_map_get_next_key(map_fd, prev, &next)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next, &value) == 0)
            printf("%-30s %llu\n", lookup_ksym((unsigned long)next),
                   (unsigned long long)value);
        else if (errno != ENOENT)
            fprintf(stderr, "lookup failed for ip 0x%llx: %s\n",
                    (unsigned long long)next, strerror(errno));

        key = next;
        prev = &key;
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
    struct multi_bpf *skel = NULL;
    int map_fd;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

    err = install_signal_handlers();
    if (err)
        return 1;

    err = load_ksyms();
    if (err)
        return 1;

    skel = multi_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load multi BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    err = multi_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach multi BPF programs: %s\n",
                strerror(-err));
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.hits);
    puts("Counting vfs_* calls across all matching functions; "
         "press Ctrl-C to stop.");
    while (!exiting) {
        unsigned int remaining = sleep(2);

        if (exiting)
            break;
        if (remaining != 0)
            continue;

        err = dump_hits(map_fd);
        if (err)
            goto cleanup;
    }

    err = 0;

cleanup:
    multi_bpf__destroy(skel);
    free(ksyms);
    return err != 0;
}
// ANCHOR_END: book
