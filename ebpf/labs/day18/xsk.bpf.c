// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);    /* xsk fd */
} xsks_map SEC(".maps");

SEC("xdp")
int xsk_redirect(struct xdp_md *ctx)
{
    __u32 q = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &q))
        return bpf_redirect_map(&xsks_map, q, 0);
    return XDP_PASS;
}
// ANCHOR_END: book
