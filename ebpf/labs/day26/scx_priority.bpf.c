/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Day 26 lab: scx_priority — a repo-owned derivative of the upstream
 * tools/sched_ext/scx_simple that gives scheduling priority to tasks in one
 * chosen cgroup.
 *
 * This is scx_simple's weighted-vtime scheduler with a single surgical change
 * inside enqueue: tasks whose cgroup (or any ancestor) matches a load-time
 * configured kernfs id get a lower vtime (run sooner) and a longer time slice.
 * Everything else — select_cpu, dispatch, running/stopping vtime accounting,
 * the shared vtime-ordered DSQ, the exit path — is unchanged from scx_simple so
 * the diff you study is exactly the priority logic.
 *
 * Derived from tools/sched_ext/scx_simple.bpf.c:
 *   Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 *   Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 *   Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

static u64 vtime_now;
UEI_DEFINE(uei);

// ANCHOR: config
/*
 * The one knob this derivative adds: the full 64-bit kernfs id of the priority
 * cgroup. It is a `const volatile` global, so it lives in .rodata — userspace
 * writes it once between skeleton open and load, and the verifier then treats
 * it as a known constant (a value of 0 dead-code-eliminates the whole priority
 * branch, which is why the userspace driver fails loudly on a 0 id).
 */
const volatile __u64 priority_cgroup_id = 0; /* full kernfs id; set from userspace */

/*
 * scx_bpf_task_cgroup(), bpf_cgroup_ancestor(), and bpf_cgroup_release() all
 * come from <scx/common.bpf.h> (scx_bpf_task_cgroup is a compat macro in
 * <scx/compat.bpf.h>). Do NOT re-declare them with your own `extern ... __ksym;`
 * — that collides with the header and fails to compile. Just call them, as
 * scx_flatcg.bpf.c does.
 */
// ANCHOR_END: config

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We therefore
 * create a separate DSQ with ID 0 that we dispatch to and consume from.
 */
#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0); /* count local queueing */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

// ANCHOR: enqueue
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 vtime = p->scx.dsq_vtime;
	u64 slice = SCX_SLICE_DFL;

	stat_inc(1); /* count global queueing */

	/*
	 * Limit the amount of budget that an idling task can accumulate to one
	 * slice (carried over unchanged from scx_simple). This floor is also
	 * what keeps the priority decrement below bounded: a task can never sit
	 * more than one slice ahead of vtime_now, so it cannot starve the rest
	 * and trip the runnable-task-stall watchdog.
	 */
	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
		vtime = vtime_now - SCX_SLICE_DFL;

	/*
	 * Walk up the cgroup hierarchy looking for the priority cgroup.
	 * bpf_cgroup_ancestor(cgrp, level) returns the ancestor at the given
	 * level (0 = root) as an ACQUIRED reference we must release. We iterate
	 * with bpf_for(), the same idiom scx_flatcg uses: it gives the verifier
	 * a provable bound on a runtime limit (owned->level), which an ordinary
	 * `for` on a memory-read value would not. A match anywhere on the path
	 * (own cgroup or any ancestor) counts, so tasks nested below /priority
	 * inherit priority too.
	 */
	if (priority_cgroup_id) {
		struct cgroup *owned = scx_bpf_task_cgroup(p);
		if (owned) {
			int lvl;
			bpf_for(lvl, 0, owned->level + 1) {
				struct cgroup *anc = bpf_cgroup_ancestor(owned, lvl);
				if (!anc)
					continue;
				if (anc->kn->id == priority_cgroup_id) {
					vtime -= 1000000; /* push 1 ms earlier in queue */
					slice *= 2;	  /* longer time slice */
					bpf_cgroup_release(anc);
					break;
				}
				bpf_cgroup_release(anc);
			}
			bpf_cgroup_release(owned);
		}
	}

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}
// ANCHOR_END: enqueue

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	u64 delta = scale_by_task_weight_inverse(p, SCX_SLICE_DFL - p->scx.slice);

	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + delta);
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	int ret;

	/*
	 * scx_bpf_create_dsq is a KF_SLEEPABLE kfunc, which is why this callback
	 * must be BPF_STRUCT_OPS_SLEEPABLE and not plain BPF_STRUCT_OPS.
	 */
	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret) {
		scx_bpf_error("failed to create DSQ %d (%d)", SHARED_DSQ, ret);
		return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu	= (void *)simple_select_cpu,
	       .enqueue		= (void *)simple_enqueue,
	       .dispatch	= (void *)simple_dispatch,
	       .running		= (void *)simple_running,
	       .stopping	= (void *)simple_stopping,
	       .enable		= (void *)simple_enable,
	       .init		= (void *)simple_init,
	       .exit		= (void *)simple_exit,
	       .name		= "simple");
