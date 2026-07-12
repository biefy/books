// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_STACK_DEPTH 64

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);     /* (kstack_id << 32) | ustack_id */
    __type(value, __u64);   /* count */
} counts SEC(".maps");

SEC("fentry/vfs_read")
int BPF_PROG(on_read)
{
    __s64 kid = bpf_get_stackid(ctx, &stacks, 0);
    __s64 uid = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);

    /* Negative return = failure to capture (returns a negative errno:
       -EFAULT/-EEXIST/-ENOMEM, e.g., user stack with no frame ptrs). */
    if (kid < 0 && uid < 0)
        return 0;

    __u64 key = ((__u64)(kid & 0xffffffff) << 32) | (uid & 0xffffffff);
    __u64 *c = bpf_map_lookup_elem(&counts, &key);
    if (c) {
        __sync_fetch_and_add(c, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }
    return 0;
}
// ANCHOR_END: book
