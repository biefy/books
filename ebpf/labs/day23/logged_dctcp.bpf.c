// SPDX-License-Identifier: GPL-2.0
/*
 * logged_dctcp.bpf.c — telemetry-instrumented BPF DCTCP congestion control.
 *
 * PROVENANCE
 *   Derived from the Linux kernel's canonical BPF struct_ops DCTCP selftest,
 *       tools/testing/selftests/bpf/progs/bpf_dctcp.c
 *   at tag v7.1 (git describe: v7.1-rc7-271-g424280953322), originally
 *   "Copyright (c) 2019 Facebook", SPDX GPL-2.0.
 *
 *   This repo-owned derivative differs from the upstream selftest as follows:
 *     - It DROPS the selftest-only scaffolding whose only purpose is to
 *       exercise the test harness: the `fallback_cc` fault-injection path in
 *       init, the `sk_stg_map` socket-storage probe, and the `cc_res` /
 *       `tcp_cdg` / `tcp_cdg_res` / `stg_result` / `ebusy_cnt` globals. None of
 *       that is part of the DCTCP algorithm.
 *     - It KEEPS the real DCTCP algorithm unchanged in intent: init, ssthresh,
 *       update_alpha, set_state, cwnd_event, cwnd_undo, and the Reno-tailing
 *       cong_avoid.
 *     - It ADDS a BPF ring buffer and emits one `struct tcp_event` per ACK at
 *       the TOP of bpf_dctcp_update_alpha (the .in_ack_event slot). The emit is
 *       pure observation; the original alpha-update math runs untouched below
 *       it (Day 23).
 *     - It RENAMES the registered algorithm to "bpf_dctcp_log" (13 chars, well
 *       under the 15-usable-char TCP_CA_NAME_MAX-1 cap) and ships a single
 *       vtable variable `dctcp` (the upstream `dctcp_nouse` decoy is dropped).
 *
 *   Kernel accessors/macros not present in vmlinux.h are provided by
 *   dctcp_compat.bpf.h (see its own provenance header).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "logged_dctcp.h"
#include "dctcp_compat.bpf.h"

char _license[] SEC("license") = "GPL";

// ANCHOR: ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
// ANCHOR_END: ringbuf

/* Per-connection DCTCP scratch, overlaid on the socket's inline
 * icsk_ca_priv[104] buffer via inet_csk_ca(sk). 28 bytes, well within cap. */
struct bpf_dctcp {
    __u32 old_delivered;
    __u32 old_delivered_ce;
    __u32 prior_rcv_nxt;
    __u32 dctcp_alpha;
    __u32 next_seq;
    __u32 ce_state;
    __u32 loss_cwnd;
};

static unsigned int dctcp_shift_g = 4;                  /* g = 1/2^4 */
static unsigned int dctcp_alpha_on_init = DCTCP_MAX_ALPHA;

static void dctcp_reset(const struct tcp_sock *tp, struct bpf_dctcp *ca)
{
    ca->next_seq = tp->snd_nxt;

    ca->old_delivered = tp->delivered;
    ca->old_delivered_ce = tp->delivered_ce;
}

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_init, struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct bpf_dctcp *ca = inet_csk_ca(sk);

    ca->prior_rcv_nxt = tp->rcv_nxt;
    ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);
    ca->loss_cwnd = 0;
    ca->ce_state = 0;

    dctcp_reset(tp, ca);
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_dctcp_ssthresh, struct sock *sk)
{
    struct bpf_dctcp *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    ca->loss_cwnd = tp->snd_cwnd;
    return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

// ANCHOR: telemetry
SEC("struct_ops")
void BPF_PROG(bpf_dctcp_update_alpha, struct sock *sk, __u32 flags)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct bpf_dctcp *ca = inet_csk_ca(sk);

    /* --- Day 23 telemetry: one record per ACK, pure read-only observation. */
    struct tcp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->ts_ns     = bpf_ktime_get_ns();
        e->srtt_us   = tp->srtt_us >> 3;   /* srtt is stored in eighths of a us */
        e->cwnd      = tp->snd_cwnd;       /* kernel C uses the tcp_snd_cwnd() accessor */
        e->in_flight = tp->packets_out - (tp->sacked_out + tp->lost_out) +
                       tp->retrans_out;
        e->sk_cookie = (__u64)(unsigned long)sk; /* per-flow id; see chapter note */
        bpf_ringbuf_submit(e, 0);
    }
    /* --- end telemetry; the original DCTCP alpha update runs unchanged below. */

    /* Expired RTT */
    if (!before(tp->snd_una, ca->next_seq)) {
        __u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
        __u32 alpha = ca->dctcp_alpha;

        /* alpha = (1 - g) * alpha + g * F */

        alpha -= min_not_zero(alpha, alpha >> dctcp_shift_g);
        if (delivered_ce) {
            __u32 delivered = tp->delivered - ca->old_delivered;

            /* If dctcp_shift_g == 1, a 32bit value would overflow
             * after 8 M packets.
             */
            delivered_ce <<= (10 - dctcp_shift_g);
            delivered_ce /= max(1U, delivered);

            alpha = min(alpha + delivered_ce, DCTCP_MAX_ALPHA);
        }
        ca->dctcp_alpha = alpha;
        dctcp_reset(tp, ca);
    }
}
// ANCHOR_END: telemetry

static void dctcp_react_to_loss(struct sock *sk)
{
    struct bpf_dctcp *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    ca->loss_cwnd = tp->snd_cwnd;
    tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_state, struct sock *sk, __u8 new_state)
{
    if (new_state == TCP_CA_Recovery &&
        new_state != BPF_CORE_READ_BITFIELD(inet_csk(sk), icsk_ca_state))
        dctcp_react_to_loss(sk);
    /* We handle RTO in bpf_dctcp_cwnd_event to ensure that we perform only
     * one loss-adjustment per RTT.
     */
}

static void dctcp_ece_ack_cwr(struct sock *sk, __u32 ce_state)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (ce_state == 1)
        tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
    else
        tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

/* Minimal DCTCP CE state machine:
 *
 * S:   0 <- last pkt was non-CE
 *      1 <- last pkt was CE
 */
static void dctcp_ece_ack_update(struct sock *sk, enum tcp_ca_event evt,
                                 __u32 *prior_rcv_nxt, __u32 *ce_state)
{
    __u32 new_ce_state = (evt == CA_EVENT_ECN_IS_CE) ? 1 : 0;

    if (*ce_state != new_ce_state) {
        /* CE state has changed, force an immediate ACK to
         * reflect the new CE state. If an ACK was delayed,
         * send that first to reflect the prior CE state.
         */
        if (inet_csk(sk)->icsk_ack.pending & ICSK_ACK_TIMER) {
            dctcp_ece_ack_cwr(sk, *ce_state);
            bpf_tcp_send_ack(sk, *prior_rcv_nxt);
        }
        inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
    }
    *prior_rcv_nxt = tcp_sk(sk)->rcv_nxt;
    *ce_state = new_ce_state;
    dctcp_ece_ack_cwr(sk, new_ce_state);
}

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_cwnd_event, struct sock *sk, enum tcp_ca_event ev)
{
    struct bpf_dctcp *ca = inet_csk_ca(sk);

    switch (ev) {
    case CA_EVENT_ECN_IS_CE:
    case CA_EVENT_ECN_NO_CE:
        dctcp_ece_ack_update(sk, ev, &ca->prior_rcv_nxt, &ca->ce_state);
        break;
    case CA_EVENT_LOSS:
        dctcp_react_to_loss(sk);
        break;
    default:
        /* Don't care for the rest. */
        break;
    }
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_dctcp_cwnd_undo, struct sock *sk)
{
    const struct bpf_dctcp *ca = inet_csk_ca(sk);

    return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

SEC("struct_ops")
void BPF_PROG(bpf_dctcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    tcp_reno_cong_avoid(sk, ack, acked);
}

// ANCHOR: vtable
SEC(".struct_ops")
struct tcp_congestion_ops dctcp = {
    .init         = (void *)bpf_dctcp_init,
    .in_ack_event = (void *)bpf_dctcp_update_alpha,   /* per-ACK telemetry hook */
    .cwnd_event   = (void *)bpf_dctcp_cwnd_event,
    .ssthresh     = (void *)bpf_dctcp_ssthresh,       /* required */
    .cong_avoid   = (void *)bpf_dctcp_cong_avoid,     /* required (or cong_control) */
    .undo_cwnd    = (void *)bpf_dctcp_cwnd_undo,      /* required */
    .set_state    = (void *)bpf_dctcp_state,
    .flags        = TCP_CONG_NEEDS_ECN,
    .name         = "bpf_dctcp_log",
};
// ANCHOR_END: vtable
