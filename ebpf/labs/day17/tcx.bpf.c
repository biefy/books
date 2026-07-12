// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* TCX_NEXT (enum tcx_action_base) is a BTF enum, so it comes from vmlinux.h.
 * The terminal TC_ACT_* verdicts are UAPI #defines that vmlinux.h does not
 * carry, and <linux/pkt_cls.h> can't be mixed with vmlinux.h (it redefines
 * struct tc_stats etc.). Define the two we return locally. ETH_P_IP is a UAPI
 * #define too; IPPROTO_UDP already comes from vmlinux.h. */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define ETH_P_IP    0x0800

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        (*c)++;
}

SEC("tcx/ingress")
int counter(struct __sk_buff *skb)
{
    (void)skb;
    bump(0);            /* count all */
    return TCX_NEXT;    /* DEFER: let the next link (firewall) decide */
}

SEC("tcx/ingress")
int firewall(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end)
        return TCX_NEXT;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TCX_NEXT;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end)
        return TCX_NEXT;
    if (ip->protocol == IPPROTO_UDP) {
        bump(1);
        return TC_ACT_SHOT;   /* DECIDE: drop the UDP datagram, stop the chain */
    }
    return TCX_NEXT;          /* DEFER on everything else */
}
// ANCHOR_END: book
