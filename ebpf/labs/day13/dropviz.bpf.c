// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "dropviz.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);   /* deliberately small to demo drops */
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} starts SEC(".maps");

static __always_inline void inc_drops(void)
{
    __u32 z = 0;
    __u64 *c = bpf_map_lookup_elem(&drops, &z);
    if (c)
        (*c)++;
}

SEC("fentry/vfs_read")
int BPF_PROG(on_in, struct file *f, char *buf, size_t n, loff_t *pos)
{
    __u64 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u64 ts = bpf_ktime_get_ns();

    (void)f;
    (void)buf;
    (void)n;
    (void)pos;
    bpf_map_update_elem(&starts, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(on_out, struct file *f, char *buf, size_t n, loff_t *pos,
             ssize_t ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tid = id & 0xffffffff;
    __u64 *ts = bpf_map_lookup_elem(&starts, &tid);
    __u64 dur;
    struct event *e;

    (void)f;
    (void)buf;
    (void)n;
    (void)pos;
    (void)ret;

    if (!ts)
        return 0;
    dur = bpf_ktime_get_ns() - *ts;
    bpf_map_delete_elem(&starts, &tid);

    /* Filter to keep rate sane (comment out to demonstrate drops). */
    if (dur < 5000)
        return 0;     /* skip < 5µs */

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        inc_drops();
        return 0;
    }
    e->pid = id >> 32;
    e->dur = dur;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ANCHOR_END: book
