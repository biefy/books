# Day 8 — Tracepoints, raw vs tp_btf, and how to find them

> **Today's mission:** measure scheduler latency by hooking `sched_switch`. Compare raw tracepoint and tp_btf attach modes. Learn how to discover every tracepoint on your kernel and read its format. Total time: ~75 minutes.

## Why tracepoints when fentry exists?

Fentry attaches to *function entries*. That's perfect when there's a function whose name describes the event you care about (`vfs_read`, `filename_unlinkat`). But many interesting events don't map to a single function — or they're emitted from inside a function that does many things.

**Tracepoints are explicit instrumentation points** added by kernel developers via `TRACE_EVENT(...)` macros. They name the event, specify the data fields, and live forever as part of the kernel's API contract.

When you write a tracer for "every context switch," you don't want to attach to `__schedule` and figure out *which* paths inside it correspond to actual switches. You want `sched_switch` — the tracepoint that fires once per actual switch with `prev` and `next` already determined.

Tracepoints exist for: scheduler events, block I/O, networking, memory allocation, filesystem operations, syscalls, and many more.

## The three BPF-facing ways to attach to a tracepoint

For tracepoint events, BPF has three related section families:

![Raw vs tp_btf](diagrams/day08_raw_vs_tp_btf.png)

**Regular tracepoint** (`SEC("tracepoint/group/event")`) gives you a struct of *copied bytes* — whatever fields the tracepoint definition chose to copy out. Stable across kernel versions because the tracepoint format is part of the kernel's API.

**Raw tracepoint** (`SEC("raw_tracepoint/event")`) gives you raw positional arguments in `struct bpf_raw_tracepoint_args`. It avoids the copied event struct, but you unpack by index and lose typed-argument ergonomics.

**tp_btf** (`SEC("tp_btf/event")`) gives you the original *typed kernel pointers* the tracepoint received as arguments. You can dereference fields directly when the pointer is valid for the callback. Same hook, more power.

Same event, three BPF-facing interfaces. The kernel dispatches whichever listener types are attached:

![Tracepoint dispatch](diagrams/day08_dispatch.png)

When a tracepoint fires, regular `tracepoint/...` listeners get the copied event struct, `raw_tracepoint/...` listeners get raw argument slots, and `tp_btf/...` listeners get typed arguments. Cost is bounded: the event-struct copy only happens for regular tracepoint listeners.

> ### There are no Dumb Questions
>
> **Q: If tp_btf is strictly better, why does raw tracepoint still exist?**
>
> A: Three reasons. First, history — raw tracepoints predate BTF. Second, raw tracepoints work on kernels without BTF (rare today, but possible). Third, raw tracepoint structs are explicitly *stable* — `prev_comm` will always be a 16-byte char array; the kernel maintainers commit to that. tp_btf gives you live `task_struct *`, but `task_struct` itself isn't stable across versions (you'd need CO-RE for any field access).
>
> **Q: How do tracepoints differ from kprobe?**
>
> A: Tracepoints are *explicitly placed* by kernel developers as part of the kernel's API. Their format is stable. Kprobes are *dynamic* — you can attach to any function, but the function isn't part of any contract; it can be renamed, removed, or have its signature change in the next release.
>
> **Q: What about `raw_tracepoint` (with the underscore)?**
>
> A: That's the raw positional-argument mode: `ctx->args[0]`, `ctx->args[1]`, and so on. It is distinct from `SEC("tracepoint/...")`, which receives a copied event struct. `tp_btf` supersedes raw tracepoints for most new code on BTF-enabled kernels because it gives typed arguments instead of positional slots.

## How to find tracepoints on your kernel

```bash
# All tracepoints, grouped by subsystem:
ls /sys/kernel/tracing/events/

# All sched events:
ls /sys/kernel/tracing/events/sched/

# Format of a specific tracepoint (the struct you'd get from raw):
cat /sys/kernel/tracing/events/sched/sched_switch/format
```

Or, less ergonomically but BPF-aware:

```bash
sudo bpftool perf list  # tracepoints active on this system
```

Common families you should know about:

![Tracepoint families](diagrams/day08_tracepoint_families.png)

> ### Sharpen your pencil
>
> A workload runs slowly. You want to see *which tasks* the scheduler is preempting. You could:
>
> 1. fentry on `__schedule()`.
> 2. Raw tracepoint on `sched_switch`.
> 3. tp_btf on `sched_switch`.
>
> Which gives you the cleanest data with least friction?
>
> .  
> .  
> .
>
> **Answer:** (3). `__schedule` runs for many reasons; you'd have to figure out which calls are switches. Raw `sched_switch` gives you the right event but only copied fields (no access to e.g. `prev->mm`). tp_btf gives you live `task_struct *prev, *next` — read whatever you want.

## tp_btf signature — how to know the arguments

For an fentry program, the function's signature is in BTF — straightforward. For a tp_btf program, the *tracepoint's* signature is what matters. Tracepoints are defined via `TRACE_EVENT()` macros, and the args are the parameters declared there.

Look in `include/trace/events/sched.h`:

```c
TRACE_EVENT(sched_switch,
    TP_PROTO(bool preempt,
             struct task_struct *prev,
             struct task_struct *next,
             unsigned int prev_state),
    ...
);
```

So your tp_btf program is:

```c
SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
```

Four args matching the `TP_PROTO` (the trailing `prev_state` was added in 5.14).

For tracepoints whose `TP_PROTO` you don't know offhand, `bpftool btf dump file /sys/kernel/btf/vmlinux | grep btf_trace_sched_switch` will show you the typedef.

---

## The lab

### `schedlat.bpf.c` — measure scheduling latency per task

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* When was this task last scheduled in? */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);    /* tid */
    __type(value, __u64);  /* timestamp when scheduled in */
} last_run SEC(".maps");

struct event {
    __u32 prev_pid;
    __u32 next_pid;
    __u64 wait_ns;     /* how long next was waiting */
    char prev_comm[16];
    char next_comm[16];
};

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
```

### What's new

- **`SEC("tp_btf/sched_switch")`** — tp_btf attach. Args match `TP_PROTO` of `sched_switch`.
- **Direct deref of `prev->pid`, `next->pid`, `prev->comm`** — works because `prev` and `next` are `PTR_TO_BTF_ID` (live, typed kernel pointers).
- **The pattern is more interesting than a single function tracer.** We're tracking *every* task. The map fills up to one entry per active TID and naturally bounds itself (active TIDs ≪ max_entries on most systems).
- **`if (wait < 1000) return 0;`** — filter sub-µs noise. The kernel switches frequently enough that without filtering, you'd flood the ringbuf.

### `schedlat.c` — userspace consumer

Same pattern. Print:

```c
printf("%s [%u] waited %llu µs after %s [%u]\n",
       e->next_comm, e->next_pid, e->wait_ns / 1000,
       e->prev_comm, e->prev_pid);
```

### Run

```bash
make
sudo ./schedlat 2>&1 | head -50
```

Expected: a stream of switches with wait times, e.g.:

```
firefox [4001] waited 152 µs after kworker/u8:2 [42]
chromium [5002] waited 89 µs after firefox [4001]
...
```

Spikes (> 1ms) often correlate with workload, lock contention, scheduler decisions worth investigating.

---

## What to break, in order

### Break 1 — Convert to regular tracepoint

```c
SEC("tracepoint/sched/sched_switch")
int on_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 prev_tid = ctx->prev_pid;
    __u32 next_tid = ctx->next_pid;
    /* ... no struct task_struct * available ... */
}
```

This compiles and works for `prev_pid`, `next_pid`, `prev_comm`, `next_comm` (all in the copied struct). But there's no way to reach `prev->real_parent`, `prev->cgroup`, `prev->mm`, etc. — those live in the `task_struct`, and a regular tracepoint only hands you the copied event fields, not the live pointer.

For most tracers, tp_btf is more ergonomic. Reach for regular `tracepoint/...` only when:
- You explicitly want stability (the raw struct format won't change).
- The kernel doesn't have BTF (rare; pre-5.4).
- You want to be portable across BPF runtimes that lack BTF awareness.

### Break 2 — Attach to a non-existent tracepoint

```c
SEC("tp_btf/this_tracepoint_is_not_real")
```

Load fails:

```
libbpf: prog 'on_switch': failed to find kernel BTF type ID of 'this_tracepoint_is_not_real'
```

The tracepoint name is verified against kernel BTF. Typo-proof.

### Break 3 — Wrong signature

```c
SEC("tp_btf/sched_switch")
int BPF_PROG(p, struct task_struct *prev, struct task_struct *next)
{ /* missing 'bool preempt' first arg */ }
```

Loads, runs, but `prev` is actually `bool preempt` cast to a pointer — garbage. Direct deref segfaults the BPF program (Verifier kills the run).

The Verifier *should* catch this if you compile against the right BTF — but if it doesn't, the symptom is "program loads but data is wrong." Always check `TP_PROTO`.

### Break 4 — Use BPF_CORE_READ when direct deref would do

```c
__u32 next_tid = BPF_CORE_READ(next, pid);   /* helper-call-based */
```

Works. Slower than direct deref (~50ns extra for the helper call). For trusted, well-typed pointers like `next` here, direct deref is preferred.

But: if `next` could be NULL or invalid, `BPF_CORE_READ` returns 0 instead of crashing. So for edges where you're chasing a chain (`next->mm->start_brk`), prefer `BPF_CORE_READ` so any NULL hop is silently zero-handled.

---

## What to read in the kernel

- **`include/trace/events/sched.h`** — definitions of all sched/* tracepoints. Search `TRACE_EVENT(sched_switch`. The macro expands into a *lot* of code, but the `TP_PROTO` is the contract.
- **`include/linux/tracepoint.h`** — the macro machinery. Skim. Note `DECLARE_TRACE` and `__DECLARE_TRACE`.
- **`kernel/tracepoint.c`** — what happens when a tracepoint fires. The function `__DO_TRACE` walks the registered probe list.
- **`kernel/trace/bpf_trace.c`** — search `bpf_get_raw_tracepoint`. This is how BPF programs attach to raw tracepoints. `tp_btf` goes through the same raw-tracepoint path (`BPF_TRACE_RAW_TP`): the link is set up via `bpf_raw_tracepoint_open` / `bpf_get_raw_tracepoint`, just with BTF-typed arguments.
- **`tools/testing/selftests/bpf/progs/test_tp_btf.c`** — official examples using tp_btf.

---

## Bullet Points

- **Tracepoints** are explicit instrumentation hooks placed by kernel devs; their format is stable across versions.
- Tracepoint events have three BPF section families: `tracepoint/...` (copied struct), `raw_tracepoint/...` (raw positional args), and `tp_btf/...` (typed BTF args).
- **Use tp_btf for new code.** Same hook, lower overhead, full field access via direct deref.
- The `TP_PROTO(...)` of a tracepoint defines your tp_btf BPF program's argument list.
- Discover tracepoints in `/sys/kernel/tracing/events/`.
- Common families: `sched/*`, `block/*`, `net/*`, `syscalls/*`, `kmem/*`, `filemap/*`.
- Prefer fentry over `tracepoint/syscalls/sys_enter_xxx` (faster on the syscall path).
- Direct deref works on tp_btf args; `BPF_CORE_READ` for chains where any hop could be NULL.

---

## Check question

You attach a tp_btf to `sched_switch`. Inside your program, you save `prev` (a `task_struct *`) into a hash map for use later. Will dereferencing it later still work?

<details>
<summary>Click to reveal answer</summary>

**Answer:** No. The pointer was *trusted* during the tracepoint callback because the kernel handed it to you with a guarantee that the task is alive for the duration of the callback. Once the callback returns, that guarantee is gone — the task may be freed. Storing the raw pointer for later use is a use-after-free risk and the Verifier rejects it. To save a reference safely, you'd use `bpf_task_acquire` (a kfunc — Day 20) which atomically takes a refcount, then `bpf_task_release` later. Or, simpler: store *fields* (pid, comm) rather than the pointer.

</details>

---

## Tomorrow

Day 9: stack traces. `BPF_MAP_TYPE_STACK_TRACE`, `bpf_get_stackid`, kernel vs user stacks, and how to fold output for flame graphs.
