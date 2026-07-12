#ifndef PRACTICAL_EBPF_CAPSTONE_LATENCY_H
#define PRACTICAL_EBPF_CAPSTONE_LATENCY_H

/*
 * Shared layout for the Days 28-30 capstone (Option A reference solution): a
 * generic function-latency tracer. The producer (capstone_latency.bpf.c) and
 * the consumer (capstone_latency.c) include this one header, so a change to any
 * struct cannot silently desynchronise the two sides.
 *
 * Plain C integer types (not __u32/__u64) keep the header identical for the BPF
 * object and the userspace loader, matching the Day 1-3 lab headers.
 */

#define MAX_SLOTS       64 /* one counter per power-of-two latency bucket */
#define MAX_STACK_DEPTH 32 /* frames captured per stack id */
#define TASK_COMM_LEN   16

/*
 * Per-stack latency histogram. slots[i] counts samples whose duration in ns
 * has floor(log2(duration)) == i. There is NO lhist helper for libbpf/CO-RE
 * programs; we build the histogram by hand (see the .bpf.c log2l).
 */
struct hist {
	unsigned long long slots[MAX_SLOTS];
};

/*
 * One outlier record, emitted through the ring buffer for every call whose
 * duration exceeded the configured threshold. The histogram handles the common
 * case for pennies; only the rare outliers pay for a per-event record + stacks.
 */
struct outlier_event {
	unsigned int pid;
	unsigned int tid;
	unsigned long long delta_ns;
	int kstack_id; /* index into the stack-trace map, or <0 on failure */
	int ustack_id;
	char comm[TASK_COMM_LEN];
};

#endif
