// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "schedlat.h"

char LICENSE[] SEC("license") = "GPL";

/* When was this task last switched OUT (i.e. when did it stop running)? */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);    /* tid */
    __type(value, __u64);  /* timestamp captured on switch-out */
} last_run SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 prev_tid = prev->pid;   /* live ptr deref! */
    __u32 next_tid = next->pid;

    /* Record when prev was scheduled out */
    bpf_map_update_elem(&last_run, &prev_tid, &now, BPF_ANY);

    /* How long was next waiting? */
    __u64 *t = bpf_map_lookup_elem(&last_run, &next_tid);
    if (!t)
        return 0;     /* first time we see next; no wait time */

    __u64 wait = now - *t;
    if (wait < 1000)
        return 0;     /* skip < 1µs noise */

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->prev_pid = prev_tid;
    e->next_pid = next_tid;
    e->wait_ns = wait;
    /* Direct deref of comm[16] — array, not pointer */
    __builtin_memcpy(e->prev_comm, prev->comm, sizeof(e->prev_comm));
    __builtin_memcpy(e->next_comm, next->comm, sizeof(e->next_comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ANCHOR_END: book
