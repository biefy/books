// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} m SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(rej)
{
    __u32 key = 0;
    /* WE WILL EDIT THE BODY BELOW FIVE TIMES */
    __u64 *v = bpf_map_lookup_elem(&m, &key);
    if (!v) return 0;
    *v += 1;
    return 0;
}
// ANCHOR_END: book
