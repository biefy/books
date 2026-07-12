// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;
extern void bpf_cpumask_set_cpu(__u32 cpu, struct bpf_cpumask *cpumask) __ksym;
extern bool bpf_cpumask_test_cpu(__u32 cpu, const struct cpumask *cpumask) __ksym;

SEC("fentry/filename_unlinkat")
int BPF_PROG(p)
{
    struct bpf_cpumask *m = bpf_cpumask_create();
    if (!m)
        return 0; /* KF_RET_NULL - must check */

    /* Set bits for CPUs 0, 2, 4 */
    bpf_cpumask_set_cpu(0, m);
    bpf_cpumask_set_cpu(2, m);
    bpf_cpumask_set_cpu(4, m);

    /* Test some bits */
    bool b0 = bpf_cpumask_test_cpu(0, (struct cpumask *)m);
    bool b1 = bpf_cpumask_test_cpu(1, (struct cpumask *)m);

    bpf_printk("cpu0=%d cpu1=%d", b0, b1);

    bpf_cpumask_release(m); /* KF_ACQUIRE -> must release */
    return 0;
}
// ANCHOR_END: book
