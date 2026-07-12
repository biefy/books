// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq)
        return 0; /* KF_RET_NULL: refcount may have been 0 */

    bpf_printk("acquired pid=%d", acq->pid);

    bpf_task_release(acq); /* KF_ACQUIRE -> must release on every path */
    return 0;
}
// ANCHOR_END: book
