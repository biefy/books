// ANCHOR: book
/* Day 15 — CLI for maps owned by a running block loader.
 *
 *   blockcli PIN_DIRECTORY add 10.1.0.0/16
 *   blockcli PIN_DIRECTORY del 10.1.0.0/16
 *   blockcli PIN_DIRECTORY stats
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "block.h"

static char deny_pin[PATH_MAX];
static char stats_pin[PATH_MAX];

static int set_pin_paths(const char *directory)
{
    if (snprintf(deny_pin, sizeof(deny_pin), "%s/deny", directory) >=
            (int)sizeof(deny_pin) ||
        snprintf(stats_pin, sizeof(stats_pin), "%s/stats", directory) >=
            (int)sizeof(stats_pin))
        return -1;
    return 0;
}

static int parse_cidr(const char *text, struct ipv4_lpm_key *out)
{
    char buffer[64];
    char *slash;
    char *end;
    struct in_addr address;
    long prefixlen;

    if (snprintf(buffer, sizeof(buffer), "%s", text) >= (int)sizeof(buffer))
        return -1;
    slash = strchr(buffer, '/');
    if (!slash)
        return -1;
    *slash = '\0';

    errno = 0;
    prefixlen = strtol(slash + 1, &end, 10);
    if (errno || *end != '\0' || prefixlen < 0 || prefixlen > 32)
        return -1;
    if (inet_pton(AF_INET, buffer, &address) != 1)
        return -1;

    out->prefixlen = (__u32)prefixlen;
    out->addr = address.s_addr;
    return 0;
}

static int do_add(const char *cidr)
{
    struct ipv4_lpm_key key = {};
    __u32 value = 1;
    int fd;
    int err = 0;

    if (parse_cidr(cidr, &key)) {
        fprintf(stderr, "bad CIDR: %s\n", cidr);
        return 1;
    }
    fd = bpf_obj_get(deny_pin);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s (is block running?)\n", deny_pin,
                strerror(errno));
        return 1;
    }
    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
        fprintf(stderr, "update failed: %s\n", strerror(errno));
        err = 1;
    } else {
        printf("blocked %s\n", cidr);
    }
    close(fd);
    return err;
}

static int do_del(const char *cidr)
{
    struct ipv4_lpm_key key = {};
    int fd;
    int err = 0;

    if (parse_cidr(cidr, &key)) {
        fprintf(stderr, "bad CIDR: %s\n", cidr);
        return 1;
    }
    fd = bpf_obj_get(deny_pin);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", deny_pin, strerror(errno));
        return 1;
    }
    if (bpf_map_delete_elem(fd, &key)) {
        fprintf(stderr, "delete failed: %s\n", strerror(errno));
        err = 1;
    } else {
        printf("unblocked %s\n", cidr);
    }
    close(fd);
    return err;
}

static int sum_slot(int fd, __u32 key, int cpu_count, __u64 *out)
{
    __u64 *values;
    __u64 total = 0;
    int err = -1;

    values = calloc((size_t)cpu_count, sizeof(*values));
    if (!values)
        return -1;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (int index = 0; index < cpu_count; index++)
            total += values[index];
        *out = total;
        err = 0;
    }
    free(values);
    return err;
}

static int do_stats(void)
{
    int fd = bpf_obj_get(stats_pin);
    int cpu_count = libbpf_num_possible_cpus();
    __u64 pass = 0;
    __u64 drop = 0;
    int err = 0;

    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", stats_pin, strerror(errno));
        return 1;
    }
    if (cpu_count <= 0 || sum_slot(fd, 0, cpu_count, &pass) ||
        sum_slot(fd, 1, cpu_count, &drop)) {
        fprintf(stderr, "failed to read per-CPU statistics\n");
        err = 1;
    } else {
        printf("pass=%llu drop=%llu\n", (unsigned long long)pass,
               (unsigned long long)drop);
    }
    close(fd);
    return err;
}

int main(int argc, char **argv)
{
    if (argc < 3 || set_pin_paths(argv[1])) {
        fprintf(stderr,
                "usage: %s PIN_DIRECTORY add|del CIDR | stats\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[2], "add") && argc == 4)
        return do_add(argv[3]);
    if (!strcmp(argv[2], "del") && argc == 4)
        return do_del(argv[3]);
    if (!strcmp(argv[2], "stats") && argc == 3)
        return do_stats();

    fprintf(stderr, "usage: %s PIN_DIRECTORY add|del CIDR | stats\n",
            argv[0]);
    return 1;
}
// ANCHOR_END: book
