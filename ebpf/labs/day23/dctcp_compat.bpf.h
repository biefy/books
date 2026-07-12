/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * dctcp_compat.bpf.h — minimal kernel networking accessors and constants for
 * the repo-owned Day 23 BPF DCTCP derivative (logged_dctcp.bpf.c).
 *
 * PROVENANCE
 *   The inline accessors and the `min`/`max`/`min_not_zero`/`before` helpers
 *   below are transcribed verbatim from the Linux kernel BPF selftest support
 *   header
 *       tools/testing/selftests/bpf/progs/bpf_tracing_net.h
 *   (SPDX: LGPL-2.1 OR BSD-2-Clause) at released tag v7.1, commit
 *   8cd9520d35a6c38db6567e97dd93b1f11f185dc6.
 *
 *   The macro constants mirror the kernel headers that define them and were
 *   cross-checked against that tree:
 *       TCP_ECN_DEMAND_CWR   include/net/tcp.h   (value 4)
 *       TCP_CONG_NEEDS_ECN   include/net/tcp.h   (value 0x2)
 *       DCTCP_MAX_ALPHA      net/ipv4/tcp_dctcp.c (value 1024)
 *
 *   `tcp_reno_cong_avoid` is the kernel's exported CC routine, declared here as
 *   a kfunc (__ksym) — see the __bpf_kfunc definition at
 *       net/ipv4/tcp_cong.c:496.
 *
 *   Deliberately NOT redefined here (supplied elsewhere, to avoid drift):
 *     - enum constants ICSK_ACK_TIMER, ICSK_ACK_NOW, CA_EVENT_ECN_IS_CE,
 *       CA_EVENT_ECN_NO_CE, CA_EVENT_LOSS, TCP_CA_Recovery, and every struct
 *       layout (tcp_sock, inet_connection_sock, tcp_congestion_ops) come from
 *       the pinned vmlinux.h;
 *     - the bpf_tcp_send_ack() helper comes from bpf_helper_defs.h via
 *       <bpf/bpf_helpers.h>.
 *
 *   Include this header only AFTER vmlinux.h and <bpf/bpf_helpers.h>.
 */
#ifndef PRACTICAL_EBPF_DCTCP_COMPAT_BPF_H
#define PRACTICAL_EBPF_DCTCP_COMPAT_BPF_H

#define TCP_ECN_DEMAND_CWR 4
#define TCP_CONG_NEEDS_ECN 0x2
#define DCTCP_MAX_ALPHA    1024U

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#define min_not_zero(x, y) ({           \
    typeof(x) __x = (x);                \
    typeof(y) __y = (y);                \
    __x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })

static __always_inline bool before(__u32 seq1, __u32 seq2)
{
    return (__s32)(seq1 - seq2) < 0;
}

static __always_inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
    return (struct inet_connection_sock *)sk;
}

static __always_inline void *inet_csk_ca(const struct sock *sk)
{
    return (void *)inet_csk(sk)->icsk_ca_priv;
}

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;

#endif /* PRACTICAL_EBPF_DCTCP_COMPAT_BPF_H */
