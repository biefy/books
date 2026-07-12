// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bashspy.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Track the prompt arg per TID so we can read the result on return.
 * For readline, the *return value* is what the user typed —
 * a malloc'd char* the caller frees.
 */

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(on_readline_ret, const char *line)
{
    if (!line) return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->line, sizeof(e->line), line);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ANCHOR_END: book
