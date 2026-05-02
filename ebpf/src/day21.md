# Day 21 — kptrs in maps: cross-invocation refcounted state

> **Today's mission:** save a `task_struct *` into a hash map at one event, retrieve it later, and use the data — all with refcounts that the verifier proves are correct. Total time: ~75 minutes.

## The problem with raw pointers

Yesterday's kfunc lab acquired and released within one program invocation. But sometimes you want to **save** the pointer across invocations: e.g., associate a task with a connection at `sock_alloc`, retrieve it at `sock_close`.

Saving a raw `task_struct *` into a map fails:

```
verifier: cannot reference object of type X in this map
```

The verifier doesn't trust that the pointer will remain valid. The task could be freed before you read it back.

## kptr: refcounted pointer slots

![kptr](diagrams/day21_kptr.png)

The map's value type contains a special slot:

```c
struct val {
    struct task_struct __kptr *t;
};
```

The `__kptr` annotation tells the verifier: this slot holds a refcounted kernel pointer. Operations are limited to:

- **Atomic exchange**: `bpf_kptr_xchg(slot, new_value)` returns the old value (which you must release).
- **Atomic-take**: `bpf_kptr_xchg(slot, NULL)` to take the value out for use.

Plain stores (`v->t = acq;`) are rejected.

## End-to-end lifecycle

![kptr lifecycle](diagrams/day21_kptr_lifecycle.png)

The pattern:

1. Acquire the task.
2. xchg into the map slot — verifier transfers the refcount from your local ref id to the map's ownership.
3. Lookup later in another invocation.
4. xchg out (with NULL replacement) — verifier creates a new local ref id.
5. Use the task fields.
6. Release.

If the map slot is overwritten without you taking the previous value, the verifier rejects — you'd leak the old refcount.

> ### There are no Dumb Questions
>
> **Q: What happens if the map entry is deleted while a kptr is in it?**
>
> A: The kernel detects this and calls the appropriate release function (registered with the kptr type). For tasks, that's `bpf_task_release`. The refcount drops correctly even if userspace deletes the map entry.
>
> **Q: Can I store kptrs in arrays as well as hashes?**
>
> A: Yes — `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_HASH`, and most other map types support kptr fields. The kernel handles release-on-deletion uniformly.
>
> **Q: Can I have multiple kptrs in one value struct?**
>
> A: Yes:
> ```c
> struct val {
>     struct task_struct __kptr *t;
>     struct cgroup __kptr *cg;
> };
> ```
> Each slot is exchanged independently with `bpf_kptr_xchg`.

## The lab

### `task_assoc.bpf.c`

```c
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
    __type(key, __u32);     /* tid */
    __type(value, struct val);
} stash SEC(".maps");

SEC("fentry/do_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq) return 0;

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct val v = { .task = NULL, .saved_at_ns = bpf_ktime_get_ns() };
    bpf_map_update_elem(&stash, &tid, &v, BPF_ANY);

    /* lookup the slot to xchg the kptr in */
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp) {
        bpf_task_release(acq);
        return 0;
    }
    struct task_struct *old = bpf_kptr_xchg(&vp->task, acq);
    if (old)
        bpf_task_release(old);     /* shouldn't happen on first insert */

    return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(on_unlink2)
{
    /* Pretend this is a "later" invocation that retrieves the saved task */
    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct val *vp = bpf_map_lookup_elem(&stash, &tid);
    if (!vp) return 0;

    struct task_struct *t = bpf_kptr_xchg(&vp->task, NULL);
    if (!t) return 0;

    bpf_printk("retrieved pid=%d, was saved %llu ns ago",
               t->pid, bpf_ktime_get_ns() - vp->saved_at_ns);
    bpf_task_release(t);
    return 0;
}
```

### Run

```bash
make
sudo ./task_assoc &
touch /tmp/x && rm /tmp/x
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

The two programs are both attached; the second pulls the kptr saved by the first.

---

## What to break, in order

### Break 1 — Plain store

```c
vp->task = acq;
```

Rejected: `cannot store kptr without xchg`.

### Break 2 — Forget to release the old value

```c
bpf_kptr_xchg(&vp->task, acq);
/* what was in the slot before? */
```

Verifier rejects with `unreleased reference` — `bpf_kptr_xchg` returned the old value (potentially non-NULL), which you discarded without releasing. Always:

```c
struct task_struct *old = bpf_kptr_xchg(&vp->task, acq);
if (old) bpf_task_release(old);
```

### Break 3 — Don't release the retrieved kptr

```c
struct task_struct *t = bpf_kptr_xchg(&vp->task, NULL);
if (!t) return 0;
return 0;     /* leak */
```

Rejected: `unreleased reference id=N`.

### Break 4 — Map deletion releases automatically

Add a userspace loop that deletes map entries:

```c
bpf_map_delete_elem(fd, &tid);
```

The kernel sees the kptr in the deleted entry and calls `bpf_task_release` for you. No leak.

---

## What to read in the kernel

- **`kernel/bpf/syscall.c`** — search `bpf_kptr_xchg`. The atomic exchange implementation.
- **`kernel/bpf/btf.c`** — search `BTF_FIELD_KPTR`. How the verifier identifies kptr fields in map values.
- **`kernel/bpf/verifier.c`** — search `mark_btf_ld_reg`. How the verifier types kptrs at use sites.

---

## Bullet Points

- **kptrs** let BPF programs store refcounted kernel pointers in maps across invocations.
- Annotated with `__kptr` in the value struct.
- All access via **`bpf_kptr_xchg`** (atomic exchange).
- xchg returns the old value, which you must release if non-NULL.
- Map deletion automatically releases stored kptrs.
- Verifier statically tracks reference state across stores and lookups.

---

## Check question

You xchg a new task into a map slot but don't check the return. The slot was previously empty. What happens?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Verifier load fails. Even though the slot was empty (xchg returns NULL), the verifier doesn't know that statically — it has to assume xchg returns *some* refcounted pointer. You must capture the return and call release if non-NULL. The check is a runtime no-op when slot was empty (NULL release path), but the static check forces correctness for the case when the slot wasn't empty.

</details>

---

## Tomorrow

Day 22: struct_ops. Replace a kernel vtable with BPF programs. We'll load a TCP congestion control algorithm.
