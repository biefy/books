// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count;
    __u64 one = 1;

    count = bpf_map_lookup_elem(&counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return 0;
    }

    if (bpf_map_update_elem(&counts, &pid, &one, BPF_NOEXIST) != 0) {
        /* Another CPU may have inserted the same PID after our lookup. */
        count = bpf_map_lookup_elem(&counts, &pid);
        if (count)
            __sync_fetch_and_add(count, 1);
    }

    return 0;
}
// ANCHOR_END: book
