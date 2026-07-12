// ANCHOR: book
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sum SEC(".maps");

/* helper to get the singleton sum slot */
static __u64 *get_sum(void) {
    __u32 z = 0;
    return bpf_map_lookup_elem(&sum, &z);
}

/* shape 1: constant bound */
SEC("fentry/filename_unlinkat")
int BPF_PROG(loop_const)
{
    __u64 *s = get_sum();
    if (!s) return 0;
    /* The per-iteration helper call keeps clang -O2 from constant-folding
       the loop into a single `*s += 120`. Without it there is no loop left
       for the Verifier to see — and the comparison below would be bogus. */
    for (int i = 0; i < 16; i++)
        *s += bpf_get_prandom_u32();
    return 0;
}

/* shape 4: bpf_loop callback. bpf_loop's ctx argument is
   ARG_PTR_TO_STACK_OR_NULL, so it must point at *stack* memory. Passing the
   raw map-value pointer (a PTR_TO_MAP_VALUE) is rejected:
       R3 type=map_value expected=fp
   so we wrap the map pointer in a small stack struct and pass its address. */
struct cb_ctx { __u64 *s; };
static int cb(__u32 i, void *ctx)
{
    struct cb_ctx *c = ctx;
    *c->s += i;
    return 0;
}

SEC("fentry/filename_unlinkat")
int BPF_PROG(loop_helper)
{
    __u64 *s = get_sum();
    if (!s) return 0;
    struct cb_ctx c = { .s = s };
    bpf_loop(10000, cb, &c, 0);
    return 0;
}
// ANCHOR_END: book
