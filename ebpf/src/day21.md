# Day 21 — kptrs in maps: cross-invocation refcounted state

> **Today's mission:** save a `task_struct *` into a hash map at one event, retrieve it later in another, and use the fields — all with refcounts that the verifier proves correct end to end. Total time: ~75 minutes.

## The problem with raw pointers

Yesterday's lab acquired and released a kernel pointer within a single BPF program invocation. That's safe because the resource's lifetime is bounded by the function call.

But often you need to **save** a pointer across invocations. Examples:

- A tracing program that tags an outgoing connection with the originating task, looks the task up later when the connection completes.
- A sched_ext program that remembers a task's last-seen state across enqueue and dispatch.
- A networking program that associates an L2 socket with the parent process.

Naively saving a `task_struct *` into a hash map fails:

```
verifier: cannot reference object of type task_struct in this map
```

The verifier doesn't trust that the pointer will remain valid. The task could be freed between the save and the read; reading would be a use-after-free.

## kptrs: refcounted pointer slots

The solution is **`__kptr`** — a struct annotation that tells the verifier "this slot holds a refcounted kernel pointer; track it like the kfunc machinery does, but stored persistently in a map."

```c
struct val {
    struct task_struct __kptr *t;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct val);
} stash SEC(".maps");
```

![kptr](diagrams/day21_kptr.png)

The `__kptr` annotation modifies the field: the verifier and the BPF runtime both treat that 8-byte slot as a refcounted pointer that may be NULL or may hold a valid kernel object. The runtime knows how to release it (via the kptr's registered destructor) when the map entry is deleted.

Two flavors:

- **`__kptr`** — the slot owns a refcount. Inserting must consume an acquired reference; reading must take ownership atomically. (Older code may use `__kptr_ref`, but that spelling was removed — current libbpf in `tools/lib/bpf/bpf_helpers.h` defines only `__kptr` and `__kptr_untrusted`.)
- **`__kptr_untrusted`** — the slot holds an untrusted pointer (no refcount, no liveness guarantee). Useful for some niche cases. Read-only after store; can't be dereferenced safely.

We focus on `__kptr` (refcounted).

## How operations work: the xchg-only API

The only legal operations on a `__kptr` slot are via **`bpf_kptr_xchg`**:

```c
struct task_struct *bpf_kptr_xchg(struct task_struct **dst, struct task_struct *new);
```

It atomically swaps `*dst` with `new` and returns the old value. Plain stores (`v->t = ptr;`) are rejected — the verifier disallows them because they bypass the xchg's atomic semantics.

The ref-tracking rules:

1. To **store** an acquired pointer into the slot: `bpf_kptr_xchg(&v->t, acq)`. The verifier transfers the ref id from `acq` (your local variable) to the map slot. The slot now owns the refcount.
2. The **return value** of `bpf_kptr_xchg` is the previous occupant. **You must release it.** If non-NULL, call `bpf_task_release(old)`.
3. To **take** the pointer out: `bpf_kptr_xchg(&v->t, NULL)` — atomic-take, leaving slot empty. The returned pointer carries a fresh ref id you must release later.
4. **If the map entry is deleted** while the slot is non-NULL, the kernel automatically calls the registered destructor (`bpf_task_release` for tasks) on the slot's pointer. No manual cleanup needed; you can't leak by deleting.

![kptr lifecycle](diagrams/day21_kptr_lifecycle.png)

The implementation: **`bpf_kptr_xchg`** at `kernel/bpf/helpers.c:1731`. Trivially short — it's just `xchg()`. The complexity lives in the verifier (which tracks the ref id transfer) and in the field-management code that knows how to free a kptr at map-entry-delete time (`kernel/bpf/btf.c`'s `btf_record` infrastructure).

## Multiple kptrs in one value struct

You can have multiple kptr fields in the same value:

```c
struct val {
    struct task_struct __kptr *task;
    struct cgroup       __kptr *cg;
    __u64 saved_at_ns;
};
```

Each is exchanged independently. The kernel knows about each via the value type's BTF — when the map entry is destroyed, *every* kptr field is released. The non-kptr fields (`saved_at_ns`) are plain memory; no special handling.

## What you can store

Any kernel object that has a **registered kptr destructor** — installed via `register_btf_id_dtor_kfuncs` (the table-building call lives in `kernel/bpf/btf.c`, and each subsystem registers its own pairs). As of 7.x the registered set is:

- `struct task_struct __kptr *` — released by `bpf_task_release` (registered in `kernel/bpf/helpers.c`).
- `struct cgroup __kptr *` — released by `bpf_cgroup_release` (`kernel/bpf/helpers.c`).
- `struct bpf_cpumask __kptr *` — released by `bpf_cpumask_release` (`kernel/bpf/cpumask.c`).
- `struct sk_buff __kptr *` — released by `bpf_kfree_skb_dtor` (`net/sched/bpf_qdisc.c`).
- `struct bpf_crypto_ctx __kptr *` — released by the crypto dtor (`kernel/bpf/crypto.c`).

Note: `struct sock` and `struct nf_conn` have acquire/release **kfuncs** (`bpf_sk_release`, `bpf_ct_release` — both `KF_RELEASE`), but those are *not* registered as kptr destructors, so you can't currently stash them in a `__kptr` map slot. Acquire/release within a single program works; cross-invocation map storage does not.

The list grows with each kernel release. Check `Documentation/bpf/kfuncs.rst` for the current set.

## The lab

```c
/* task_assoc.bpf.c */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct val {
    struct task_struct __kptr *task;
    __u64 saved_at_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct val);
} stash SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq) return 0;

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;

    /* Initial map upsert with NULL kptr + timestamp */
    struct val v = { .task = NULL, .saved_at_ns = bpf_ktime_get_ns() };
    bpf_map_update_elem(&stash, &tid, &v, BPF_ANY);

    /* Lookup the slot to xchg the kptr in */
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp) {
        bpf_task_release(acq);  /* couldn't insert; release manually */
        return 0;
    }

    /* Move acq into the map slot. xchg returns previous occupant. */
    struct task_struct *old = bpf_kptr_xchg(&vp->task, acq);
    if (old)
        bpf_task_release(old);

    return 0;
}

SEC("fexit/filename_unlinkat")
int BPF_PROG(on_unlink2)
{
    /* Genuinely "later": fexit fires on the function's *return*, after the
     * fentry program above has already stashed the task on entry. */
    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp) return 0;

    struct task_struct *t = bpf_kptr_xchg(&vp->task, NULL);
    if (!t) return 0;  /* slot was empty */

    bpf_printk("retrieved pid=%d, was saved %llu ns ago",
               t->pid, bpf_ktime_get_ns() - vp->saved_at_ns);

    bpf_task_release(t);
    return 0;
}
```

Build and run:

```bash
make
sudo ./task_assoc &
touch /tmp/x && rm /tmp/x       # fentry stashes on entry, fexit retrieves on return
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You'll see one line per `filename_unlinkat` showing the retrieved task and elapsed time.

When you're done watching, stop the loader so the fentry/fexit programs detach:

```bash
sudo pkill -f task_assoc       # or, since it's job 1: kill %1
```

## What to break

### Plain store

```c
vp->task = acq;
```

Verifier rejects with a distinct message — not the leak-class `Unreleased reference` of the next two items, but:

```
store to referenced kptr disallowed
```

The kptr field can only be assigned via `bpf_kptr_xchg`. Plain stores don't go through the atomic exchange that the runtime uses to track lifetimes; allowing them would let a refcount leak by overwriting. (The check lives in `check_map_kptr_access` — `kernel/bpf/verifier.c:4747` — which rejects any non-load store class targeting a `BPF_KPTR_REF` field with `-EACCES`.)

### Forget to release the previous occupant

```c
bpf_kptr_xchg(&vp->task, acq);
/* discarded the return value */
```

Verifier rejects with `Unreleased reference id=N alloc_insn=M`. The xchg returned a (possibly non-NULL) old value with its own ref id; discarding that id is a leak.

The pattern is always:

```c
struct task_struct *old = bpf_kptr_xchg(&vp->task, acq);
if (old) bpf_task_release(old);
```

### Forget to release the retrieved kptr

```c
struct task_struct *t = bpf_kptr_xchg(&vp->task, NULL);
if (!t) return 0;
return 0;     /* leak: t still holds a refcount */
```

Rejected at exit: `Unreleased reference id=N alloc_insn=M`.

### Map deletion releases automatically

When userspace deletes a map entry whose kptr slot is still **populated**, the kernel runs the registered destructor (`bpf_task_release` for tasks) on the slot's pointer at `bpf_obj_free_fields` time. No leak, no manual cleanup — and if your program terminates abnormally, userspace can drain the map and the kernel still frees every stashed task.

The trouble with demonstrating this in the lab as written: the fexit handler already `bpf_kptr_xchg`'s the slot back to NULL on return (lines 162–168), so by the time any userspace delete runs, the slot is empty and deletion frees nothing. To actually see the destructor fire, **temporarily comment out the fexit retrieval (lines 162–168)** so entries stay populated, then delete them from userspace:

```c
/* userspace — fd and key are real, not placeholders */
int fd = bpf_map__fd(skel->maps.stash);

/* tid is a per-rm-process key you don't know a priori, so iterate: */
__u32 key = 0, next;
struct val v;
while (bpf_map_get_next_key(fd, &key, &next) == 0) {
    bpf_map_lookup_and_delete_elem(fd, &next, &v);   /* delete fires the kptr dtor */
    key = next;
}
```

Observe the destructor firing — in a second terminal, before you delete:

```bash
sudo bpftrace -e 'kprobe:bpf_task_release { @releases = count(); printf("dtor fired\n"); }'
```

Expected result: `@releases` increments once per deleted **populated** slot — that is the kernel invoking the registered kptr destructor on your behalf. Without the kptr machinery you would leak one task refcount per stashed entry.

Caveat: this same probe also fires on the explicit `bpf_task_release(t)` in the fexit path, so either disable that path (the comment-out above) or compare counts to isolate the map-delete releases. Alternatively, dump the live slots first with `sudo bpftool map dump pinned /sys/fs/bpf/stash` (if you pin the map) to confirm they're populated before the delete.

## What to read in the kernel

- **`kernel/bpf/helpers.c:1731`** — `bpf_kptr_xchg`. The implementation. Tiny — three lines of `xchg()` plus return. The complexity is in the type checking, not the runtime.

- **`kernel/bpf/btf.c`** — search `BPF_KPTR_REF`. The field-record infrastructure. When you declare a value type with `__kptr`, the kernel parses the BTF and builds a `btf_record` describing each kptr field. The destructor is looked up at parse time and stored.

- **`kernel/bpf/btf.c:4072`** — `btf_parse_fields`. Walks struct fields, identifies kptrs (and other special types like spinlocks, lists), builds the record. Read this to understand what makes a struct field "special."

- **`kernel/bpf/syscall.c`** — search `bpf_obj_free_fields`. The destructor walker. When a map entry is deleted, this iterates the value's `btf_record` and calls each kptr's release function. This is what frees your kptrs at map-delete time.

- **`kernel/bpf/verifier.c`** — search `mark_btf_ld_reg`. How the verifier types kptr fields at use sites. Trace through `check_kfunc_call` for the acquire/release reference-tracking logic.

- **`tools/testing/selftests/bpf/progs/cpumask_*.c`** — extensive kptr tests, including kptr-in-map patterns.

## Bullet Points

- **kptrs** let BPF programs store refcounted kernel pointers in maps across invocations.
- Annotation: **`__kptr`** in the value struct.
- All access via **`bpf_kptr_xchg`** (atomic exchange). Plain stores rejected.
- xchg returns the old value — **you must release if non-NULL**.
- Map deletion **automatically releases** stored kptrs (registered destructor invoked).
- Verifier statically tracks reference state across stores and lookups.
- Multiple kptrs per value are independent — each released individually on map delete.
- Supported types (registered kptr destructors): task_struct, cgroup, bpf_cpumask, sk_buff, bpf_crypto_ctx; more added each release. (sock/nf_conn have release kfuncs but aren't registered kptr dtors.)

## Check question

You xchg a new task into a map slot but don't capture the return value. The slot was previously empty. Why does the verifier still reject this?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Because the verifier doesn't know statically that the slot was empty. Even if your program logic guarantees the slot was just initialized to NULL, the verifier has to assume the slot might hold a previously-stored kptr (e.g., from another concurrent invocation that ran in a different CPU context — the lookup-then-xchg pattern is only "atomic" at the xchg, not over the whole sequence).

So `bpf_kptr_xchg(&v->t, acq)` may return a non-NULL refcounted pointer, and the verifier requires every possible non-NULL return to be released. The check is conservative (over-rejects in cases where you happen to know the slot was empty) but it's the only way to be sound — the alternative is "trust the programmer's analysis" which has historically gone badly for kernel safety.

The runtime cost is a no-op when the slot is empty: `bpf_task_release(NULL)` is a NULL-check-then-skip, ~1 ns. The verifier requirement adds zero runtime cost; it just demands you write the conditional.

</details>

---

## Tomorrow

Day 22: struct_ops. Replace a kernel function-pointer table with BPF programs.
