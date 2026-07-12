// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* vmlinux.h carries kernel types and enums but not UAPI #define macros like
 * ETH_P_IP, and <linux/if_ether.h> can't be mixed with vmlinux.h (it
 * redefines struct ethhdr). So define the one EtherType we compare against
 * locally, the way the kernel's own BPF selftests do. */
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);   /* indexed by IP protocol number */
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth + 1 > end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end)
        return XDP_PASS;

    __u32 key = ip->protocol;          /* TCP=6, UDP=17, ICMP=1 */
    __u64 *c = bpf_map_lookup_elem(&counts, &key);
    if (c)
        (*c)++;                        /* per-CPU; no atomic needed */

    return XDP_PASS;
}
// ANCHOR_END: book
