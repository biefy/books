// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "block.h"

/* ETH_P_IP is a UAPI #define, not a BTF enum, so it is absent from vmlinux.h
 * and <linux/if_ether.h> cannot be mixed with vmlinux.h. Define it locally. */
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);    /* arbitrary value; we just check existence */
    __uint(map_flags, BPF_F_NO_PREALLOC);   /* required for LPM */
} deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);  /* [0] = pass, [1] = drop */
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        (*c)++;
}

SEC("xdp")
int xdp_block(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth + 1 > end)
        goto pass;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end)
        goto pass;

    struct ipv4_lpm_key k = { .prefixlen = 32, .addr = ip->saddr };
    if (bpf_map_lookup_elem(&deny, &k)) {
        bump(1);
        return XDP_DROP;
    }

pass:
    bump(0);
    return XDP_PASS;
}
// ANCHOR_END: book
