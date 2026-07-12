// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hello.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink, int dfd, struct filename *name)
{
    struct hello_event *event;

    (void)dfd;
    (void)name;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}
// ANCHOR_END: book
