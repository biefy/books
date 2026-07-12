// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "parent.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *task;
    struct parent_event *event;

    task = (struct task_struct *)bpf_get_current_task_btf();
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&event->comm, task, comm);
    BPF_CORE_READ_STR_INTO(&event->parent_comm, task, real_parent, comm);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
// ANCHOR_END: book
