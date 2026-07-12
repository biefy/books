// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct val {
    struct task_struct __kptr *task;
    __u64 saved_at_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct val);
} stash SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq)
        return 0;

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;

    /* Initial map upsert with NULL kptr + timestamp */
    struct val v = { .task = NULL, .saved_at_ns = bpf_ktime_get_ns() };
    bpf_map_update_elem(&stash, &tid, &v, BPF_ANY);

    /* Lookup the slot to xchg the kptr in */
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp) {
        bpf_task_release(acq); /* couldn't insert; release manually */
        return 0;
    }

    /* Move acq into the map slot. xchg returns previous occupant. */
    struct task_struct *old = bpf_kptr_xchg(&vp->task, acq);
    if (old)
        bpf_task_release(old);

    return 0;
}

SEC("fexit/filename_unlinkat")
int BPF_PROG(on_unlink2)
{
    /* Genuinely "later": fexit fires on the function's *return*, after the
     * fentry program above has already stashed the task on entry. */
    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp)
        return 0;

    struct task_struct *t = bpf_kptr_xchg(&vp->task, NULL);
    if (!t)
        return 0; /* slot was empty */

    bpf_printk("retrieved pid=%d, was saved %llu ns ago",
               t->pid, bpf_ktime_get_ns() - vp->saved_at_ns);

    bpf_task_release(t);
    return 0;
}
// ANCHOR_END: book
