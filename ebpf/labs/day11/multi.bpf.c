// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);     /* function ip */
    __type(value, __u64);   /* count */
} hits SEC(".maps");

SEC("kprobe.multi/vfs_*")
int BPF_KPROBE(on_any_vfs)
{
    __u64 ip = bpf_get_func_ip(ctx);
    __u64 *c = bpf_map_lookup_elem(&hits, &ip);
    if (c) {
        __sync_fetch_and_add(c, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&hits, &ip, &one, BPF_NOEXIST);
    }
    return 0;
}
// ANCHOR_END: book
