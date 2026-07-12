// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* vmlinux.h does not export these UAPI macros, and <linux/pkt_cls.h> can't be
   mixed with vmlinux.h (it redefines struct tc_stats etc.). So we define the
   handful we need locally, the same way the kernel's own BPF selftests do
   (tools/testing/selftests/bpf/progs/bpf_tracing_net.h). IPPROTO_UDP already
   comes from vmlinux.h. */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define ETH_P_IP    0x0800

char LICENSE[] SEC("license") = "GPL";

/* The ELF section name (SEC) is what `tc filter add ... sec tc_ingress` selects;
   the C function symbol must differ from it, or clang errors with
   "symbol 'tc_ingress' is already defined". */
SEC("tc_ingress")
int mark_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end) return TC_ACT_OK;
    /* Mark packets so userspace iptables can pick them up */
    skb->mark = 0xCAFE;
    return TC_ACT_OK;
}

SEC("tc_egress")
int drop_udp_egress(struct __sk_buff *skb)
{
    /* Drop every UDP packet outbound to demonstrate egress */
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if (eth + 1 > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > end) return TC_ACT_OK;
    if (ip->protocol == IPPROTO_UDP) return TC_ACT_SHOT;
    return TC_ACT_OK;
}
// ANCHOR_END: book
