# Day 20 — kfuncs: the modern kernel-extension mechanism

> **Today's mission:** call a kfunc from BPF, understand acquire/release semantics, and know why new BPF features arrive as kfuncs rather than helpers. Total time: ~75 minutes.

> **Phase 4 starts here.** Days 20–24 cover the modern primitives that distinguish 2024+ BPF from 2019 BPF: kfuncs, kptrs, struct_ops, and BTF spelunking.

## Helpers stopped growing

Helpers (`bpf_get_current_pid_tgid`, `bpf_map_lookup_elem`, etc.) are **frozen UAPI**. The list is in `include/uapi/linux/bpf.h` as `enum bpf_func_id`. The kernel community decided around 2022 that the helper list won't grow further — instead, new BPF capabilities ship as **kfuncs**.

![helper vs kfunc](diagrams/day20_kfunc_helper.png)

A kfunc is just a kernel function exposed to BPF via BTF + a registration call. It looks like a regular C function. The differences are operational, not syntactic:

- **Discovery**: by name, against kernel BTF, at load time. Helpers are by enum, fixed at compile time.
- **Stability**: kfuncs are **not UAPI**. They can change signature or be removed; programs using the old shape break.
- **Reach**: kfuncs can access types and operations helpers can't (because helpers can't grow).
- **Lifetime semantics**: the verifier enforces acquire/release tracking via metadata on each kfunc.

## Acquire and release

Many kfuncs return refcounted resources. The verifier tracks each one and refuses program load if you forget to release.

![acquire/release](diagrams/day20_acquire_release.png)

The first kfunc you'll meet is `bpf_task_acquire`:

```c
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
```

`bpf_task_acquire` takes a refcount on the task. `bpf_task_release` returns it. Forget the release and the verifier rejects:

```
unreleased reference id=1
```

Call release twice and the verifier rejects:

```
release on non-acquired reference
```

This is checked at *load time* — runtime is safe.

> ### There are no Dumb Questions
>
> **Q: Why are kfuncs better than helpers if they break compatibility?**
>
> A: Two reasons. First, kfuncs let kernel maintainers refactor freely without UAPI commitments — keeps internal evolution healthy. Second, programs that use a kfunc just need to be recompiled (or have their `__ksym` declarations adjusted) — that's manageable. Frozen helpers create permanent maintenance burden in the kernel.
>
> **Q: How do I find which kfuncs exist on my kernel?**
>
> A: We dedicate Day 24 to exactly this. Short version: `bpftool btf dump` and look for `FUNC` entries that aren't internal-use; or `Documentation/bpf/kfuncs.rst` lists the major categories.
>
> **Q: Are there kfuncs for every program type?**
>
> A: No — kfuncs are **registered for specific program types**. A kfunc registered for tracing won't be available in XDP. The verifier checks at call sites.

## The lab

### `kfunc_demo.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("fentry/do_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq) return 0;

    /* now we hold a refcount; the task is guaranteed alive */
    bpf_printk("acquired pid=%d", acq->pid);

    bpf_task_release(acq);
    return 0;
}
```

### Run

```bash
make
sudo ./kfunc_demo &
touch /tmp/x && rm /tmp/x
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You'll see `acquired pid=N` per delete.

---

## What to break, in order

### Break 1 — Forget release

Comment out `bpf_task_release(acq);`. Verifier rejects at load:

```
Unreleased reference id=1, alloc_insn=2
```

The number tells you which acquire was leaked. Multiple acquires in a program get unique ids.

### Break 2 — Release without acquire

```c
bpf_task_release(cur);  /* cur isn't acquired */
```

Rejected: `release on non-acquired reference`.

### Break 3 — Conditional release

```c
if (acq->pid > 1000)
    bpf_task_release(acq);
return 0;
```

Verifier rejects — there's an exit path where `acq` is leaked. Verifier requires release on **every** path.

Fix: release before any conditional return:

```c
__u32 pid = acq->pid;
bpf_task_release(acq);
if (pid > 1000) return 0;
```

### Break 4 — Use the wrong release function

```c
bpf_task_release(acq);
bpf_task_release(acq);  /* twice */
```

Rejected: `release on non-acquired reference` (the first release closed the id; the second has nothing to release).

---

## What to read in the kernel

- **`Documentation/bpf/kfuncs.rst`** — official categories: KF_RELEASE, KF_ACQUIRE, KF_TRUSTED_ARGS, KF_RCU, KF_SLEEPABLE.
- **`kernel/bpf/helpers.c`** — search `BTF_KFUNCS_START`. Each block registers a set of kfuncs.
- **`kernel/bpf/cpumask.c`** — search `bpf_cpumask_create`. A self-contained kfunc family worth reading in full.
- **`tools/testing/selftests/bpf/progs/test_task_kfunc*.c`** — test programs.

---

## Bullet Points

- **kfuncs** are in-tree kernel functions exposed to BPF via BTF and registration. Not UAPI.
- Declared in BPF code with `extern T name(args) __ksym;`.
- The verifier enforces **acquire/release lifetimes** for kfuncs marked KF_ACQUIRE.
- New BPF features (cpumask, dynptr, lists) ship as kfuncs, not helpers.
- Per-program-type registration; not all kfuncs are available everywhere.

---

## Check question

Why does the verifier check release lifetimes statically rather than at runtime?

.  
.  
.

**Answer:** Static checking is fast and total. A runtime ref-leak detector would either (a) impose per-call overhead or (b) only catch leaks after the fact (not preventing them). Static analysis catches every leak at load time, before the program ever runs. The verifier already tracks every register's type, so adding reference-id tracking is a small extension. Trade-off: programs with conditional release require explicit care from the writer.

---

## Tomorrow

Day 21: store an acquired kptr in a map across program invocations. Refcounted state that survives across calls.
