// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/egress")
int block_udp(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;
    struct iphdr *ip = data;
    if (ip + 1 > end) return 1;       /* allow if can't parse */
    if (ip->protocol == IPPROTO_UDP) return 0;  /* drop UDP */
    return 1;
}
// ANCHOR_END: book
