// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "openat_path.h"

/* vmlinux.h does not carry the __user sparse annotation. Define it away so
 * the syscall-argument pointer keeps its documentary __user tag and still
 * compiles under -target bpf. */
#ifndef __user
#define __user
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Sleepable fentry — the '.s/' suffix gives access to bpf_copy_from_user. */
SEC("fentry.s/__x64_sys_openat")
int BPF_PROG(on_openat, struct pt_regs *regs)
{
    struct event *e;
    const char __user *upath;
    long ret;

    /* The syscall wrapper passes pt_regs; PARM2 is the path string. */
    upath = (const char __user *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    if (!upath)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* This is the magic — only allowed in sleepable programs: */
    ret = bpf_copy_from_user(e->path, sizeof(e->path) - 1, upath);
    if (ret < 0)
        e->path[0] = 0;   /* couldn't read; emit empty */

    bpf_ringbuf_submit(e, 0);
    return 0;
}
// ANCHOR_END: book
