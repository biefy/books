#ifndef PRACTICAL_EBPF_LOGGED_DCTCP_H
#define PRACTICAL_EBPF_LOGGED_DCTCP_H

/*
 * Shared ring-buffer record ABI for the Day 23 telemetry DCTCP derivative.
 *
 * The BPF producer (logged_dctcp.bpf.c) and the userspace consumer
 * (logged_dctcp.c) both include this one header so a layout change cannot
 * silently desynchronize the two sides. Ringbuf transports raw bytes, so the
 * struct must be identical on both. Fixed-width integers are spelled with the
 * plain C types that have the required width on every LP64 Linux target the
 * lab supports (BPF is always 64-bit); this avoids pulling <linux/types.h>
 * into the BPF object, which already gets these widths from vmlinux.h.
 */
struct tcp_event {
    unsigned long long ts_ns;     /* bpf_ktime_get_ns() monotonic timestamp   */
    unsigned int       srtt_us;   /* smoothed RTT in microseconds (srtt >> 3) */
    unsigned int       cwnd;      /* snd_cwnd, in segments                     */
    unsigned int       in_flight; /* segments sent but not yet ACKed           */
    unsigned long long sk_cookie; /* per-flow id (kernel socket address)       */
};

#endif /* PRACTICAL_EBPF_LOGGED_DCTCP_H */
