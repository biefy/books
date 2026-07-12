// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Same logic, three different program types */

SEC("fentry/vfs_read")
int BPF_PROG(via_fentry, struct file *f, char *buf, size_t n, loff_t *pos)
{
    bpf_printk("fentry: f=%p n=%zu", f, n);
    return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(via_kprobe, struct file *f, char *buf, size_t n, loff_t *pos)
{
    bpf_printk("kprobe: f=%p n=%zu", f, n);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int via_tp(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    bpf_printk("tp: fd=%d", fd);
    return 0;
}
// ANCHOR_END: book
