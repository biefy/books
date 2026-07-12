// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "capstone_latency.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Load-time configuration (const volatile -> .rodata, set by userspace before
 * load). threshold_ns gates the per-event outlier path; targ_tgid, when
 * nonzero, restricts tracing to one process.
 */
const volatile unsigned long long threshold_ns = 1000000; /* 1 ms */
const volatile unsigned int targ_tgid = 0;		  /* 0 = every task */

/* entry timestamp per thread id, written on fentry, consumed on fexit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, unsigned int);
	__type(value, unsigned long long);
} starts SEC(".maps");

/* kernel/user stack traces, addressed by the id bpf_get_stackid() returns */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(unsigned long long));
} stacks SEC(".maps");

/*
 * Per-stack histogram. PERCPU_HASH so each CPU bumps its own copy of a slot
 * with an ordinary store — no lost counts under contention, no atomics — and
 * userspace sums across CPUs. Keyed by kernel stack id: one distribution per
 * call site (Option A's "histogram bucketed by stack id").
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, unsigned int);
	__type(value, struct hist);
} hists SEC(".maps");

/* outlier events (duration > threshold), one record each */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} outliers SEC(".maps");

/* All-zero template kept in .bss (not on the 512-byte BPF stack) so a new
 * histogram entry can be created without a large stack allocation. */
static struct hist zero_hist;

// ANCHOR: log2
/*
 * Branchless log2 for the histogram slot index. BPF has no libm and the
 * verifier rejects unbounded loops, so we binary-search the bit position with
 * shifts — the canonical idiom from samples/bpf/lwt_len_hist.bpf.c. There is no
 * lhist/hist helper for libbpf programs; this is how you build the bucketing.
 */
static __always_inline unsigned int log2_u32(unsigned int v)
{
	unsigned int r, shift;

	r = (v > 0xFFFF) << 4;
	v >>= r;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);
	return r;
}

/* 64-bit: log2 of the high half + 32, else the low half. */
static __always_inline unsigned int log2l(unsigned long long v)
{
	unsigned int hi = v >> 32;

	if (hi)
		return log2_u32(hi) + 32;
	return log2_u32(v);
}
// ANCHOR_END: log2

/*
 * Entry and exit attach to a kernel function chosen at load time. The SEC names
 * are placeholders; userspace calls bpf_program__set_attach_target() to point
 * both programs at the requested function before load.
 */
SEC("fentry/vfs_read")
int BPF_PROG(on_entry)
{
	unsigned long long id = bpf_get_current_pid_tgid();
	unsigned int tgid = id >> 32;
	unsigned int tid = (unsigned int)id;
	unsigned long long ts;

	if (targ_tgid && tgid != targ_tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &tid, &ts, BPF_ANY);
	return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(on_exit)
{
	unsigned long long id = bpf_get_current_pid_tgid();
	unsigned int tid = (unsigned int)id;
	unsigned long long *tsp, delta, now;
	unsigned int slot, key;
	struct hist *hp;
	int kstack;

	tsp = bpf_map_lookup_elem(&starts, &tid);
	if (!tsp)
		return 0; /* entry was filtered out or missed */
	now = bpf_ktime_get_ns();
	delta = now - *tsp;
	bpf_map_delete_elem(&starts, &tid);

	/* Common-case path: bucket the duration into the per-stack histogram.
	 * One percpu increment, no ring buffer, no wakeup. */
	kstack = bpf_get_stackid(ctx, &stacks, 0);
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1; /* also proves the index bound to the verifier */

	key = (unsigned int)kstack;
	hp = bpf_map_lookup_elem(&hists, &key);
	if (!hp) {
		bpf_map_update_elem(&hists, &key, &zero_hist, BPF_NOEXIST);
		hp = bpf_map_lookup_elem(&hists, &key);
		if (!hp)
			return 0;
	}
	hp->slots[slot]++;

	/* Rare path: outliers additionally emit a full record with stack ids. */
	if (delta > threshold_ns) {
		struct outlier_event *e;

		e = bpf_ringbuf_reserve(&outliers, sizeof(*e), 0);
		if (!e)
			return 0;
		e->pid = id >> 32;
		e->tid = tid;
		e->delta_ns = delta;
		e->kstack_id = kstack;
		e->ustack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
// ANCHOR_END: book
