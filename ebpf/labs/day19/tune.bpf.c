#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* SOL_TCP / TCP_CONGESTION are userspace UAPI #defines, not BTF types, so
 * vmlinux.h does not provide them. Define them here if absent. */
#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

// ANCHOR: prog
SEC("sockops")
int tcp_tune(struct bpf_sock_ops *skops)
{
    if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB ||
        skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        /* Set BBR for connections in this cgroup */
        char cc[] = "bbr";
        bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
    }
    return 0;
}
// ANCHOR_END: prog
