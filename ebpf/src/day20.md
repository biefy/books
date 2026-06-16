# Day 20 — kfuncs: the modern kernel-extension mechanism

> **Today's mission:** call a kfunc from BPF, understand the acquire/release reference-counting semantics that the verifier enforces, and know why new BPF features ship as kfuncs rather than helpers. Total time: ~75 minutes.

> **Phase 4 starts here.** Days 20–24 cover the modern primitives that distinguish 2024+ BPF from the older days: kfuncs, kptrs, struct_ops, and BTF spelunking.

## Why kfuncs exist

For years, the way BPF programs called kernel functionality was **helpers**: a frozen list of functions in `include/uapi/linux/bpf.h`'s `enum bpf_func_id`. Each helper had a fixed UAPI number, a fixed signature, and a forever-stable contract. Adding one was a lifetime commitment.

By ~2022 the kernel community decided that contract was too costly. Adding a helper meant:

1. New UAPI number (forever burned).
2. New code in `bpf_helpers.h` userspace headers.
3. Per-program-type allowance updates.
4. Documentation that has to live forever.
5. **Inability to evolve the signature** — if the kernel needed to change the function's signature, BPF programs using the helper broke.

**The community decided to stop adding helpers.** New BPF capabilities now ship as **kfuncs** — kernel functions exposed to BPF *not via UAPI*, with the explicit understanding that they're allowed to evolve.

![helper vs kfunc](diagrams/day20_kfunc_helper.png)

## What a kfunc is

A regular C function in the kernel, marked with `__bpf_kfunc`, registered against a `BTF_KFUNCS_START`/`BTF_KFUNCS_END` block, and resolved by name (against kernel BTF) at BPF program load time.

```c
/* In kernel/bpf/helpers.c — line 2733 */
__bpf_kfunc struct task_struct *bpf_task_acquire(struct task_struct *p)
{
    /* take a refcount on p */
    if (refcount_inc_not_zero(&p->rcu_users))
        return p;
    return NULL;
}

/* line 2744 */
__bpf_kfunc void bpf_task_release(struct task_struct *p)
{
    put_task_struct_rcu_user(p);
}

/* And later, registered: */
BTF_KFUNCS_START(generic_btf_ids)
BTF_ID_FLAGS(func, bpf_task_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_task_release, KF_RELEASE)
/* ... */
BTF_KFUNCS_END(generic_btf_ids)

register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &kfunc_set);
```

The flags annotate the function's behavior for the verifier:

- **`KF_ACQUIRE`** — returns a refcounted resource. Verifier tracks it; you must release.
- **`KF_RELEASE`** — releases a previously-acquired resource. Verifier marks the ref id closed.
- **`KF_TRUSTED_ARGS`** — argument pointers must be `PTR_TO_BTF_ID | PTR_TRUSTED` (not from arbitrary load).
- **`KF_RCU`** — argument is RCU-protected; valid for the duration of the program's RCU read section.
- **`KF_SLEEPABLE`** — only callable from sleepable BPF programs.
- **`KF_RET_NULL`** — return value may be NULL; the verifier requires checking.

These flags are how the verifier knows what safety properties to check.

## Calling a kfunc from BPF

Declare it in your BPF source as an extern with `__ksym`:

```c
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
```

The `__ksym` attribute tells libbpf "look this up by name in the kernel's BTF at load time." If the name doesn't resolve, the load fails — no silent miss.

Use:

```c
struct task_struct *cur = bpf_get_current_task_btf();
struct task_struct *acq = bpf_task_acquire(cur);
if (!acq) return 0;             // KF_RET_NULL: must check

/* now we hold a refcount on acq; verifier knows ref id #1 is open */

bpf_printk("acquired pid=%d", acq->pid);

bpf_task_release(acq);          // closes ref id #1
return 0;
```

## The verifier's reference tracking

The single most important kfunc-related verifier behavior is the **acquire/release lifetime check**.

![acquire/release](diagrams/day20_acquire_release.png)

When you call a `KF_ACQUIRE` function, the verifier:
1. Creates a fresh **reference id** (an integer, e.g., id #1).
2. Marks the return-value register with that id.
3. Tracks the id through your program's flow: copies, branches, stores into maps.
4. **At every program exit point**, requires the id to be either released or transferred to a place where the kernel can release it (e.g., a kptr-typed map slot).

If you forget to release on any path:

```
Unreleased reference id=1 alloc_insn=2
```

If you release a non-acquired pointer:

```
kfunc bpf_task_release#0 reference has not been acquired before
```

If you release twice:

```
kfunc bpf_task_release#0 reference has not been acquired before
```

(The second release sees the ref id as already closed; same error.)

These are checked **at load time**, not runtime — runtime is safe.

### Why reference tracking is necessary

Kernel objects (tasks, sockets, files, dentries) have refcounts. A BPF program that takes a reference but never releases it leaks kernel memory. A program that releases a reference it didn't acquire crashes the kernel by corrupting refcounts.

Without verifier-time tracking, BPF would inherit all the refcount-management bugs of normal kernel C code. The static check makes BPF safer than hand-written kernel C in this dimension.

## Per-program-type registration

Not every kfunc is available in every BPF program type. The registration is **explicit**:

```c
register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &generic_kfunc_set);
register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &cpumask_kfunc_set);
```

Tracing programs (`fentry`, `fexit`, etc.) get the generic set. struct_ops programs get the cpumask set. XDP also gets the generic set (it's registered for `BPF_PROG_TYPE_XDP` too), so `bpf_task_acquire` *does* load in an XDP program — but it's semantically meaningless there, because XDP runs in NIC-driver softirq context with no meaningful `current` task. The cpumask family, by contrast, is registered only for TRACING/STRUCT_OPS/SYSCALL, so calling `bpf_cpumask_create` from XDP genuinely fails the verifier with `calling kernel function bpf_cpumask_create is not allowed`.

## Discovery: what kfuncs exist?

Three approaches:

1. **Kernel source.** Grep `BTF_KFUNCS_START` blocks in `kernel/bpf/` and elsewhere:

   ```bash
   cd ~/code/linux
   grep -rn 'BTF_KFUNCS_START' kernel/bpf net/ drivers/ | head
   ```

   Each block lists kfuncs in one logical family.

2. **Documentation.** `Documentation/bpf/kfuncs.rst` lists categories: cpumask, dynptr, lists, refcount, task, etc.

3. **bpftool BTF dump:**

   ```bash
   sudo bpftool btf dump file /sys/kernel/btf/vmlinux | grep "FUNC.*bpf_" | head -30
   ```

   Filters all `FUNC` entries with `bpf_` prefix. Many are kfuncs (and many are helpers, mixed in).

Day 24 covers BTF spelunking in detail.

## The lab

```c
/* kfunc_demo.bpf.c */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *cur = bpf_get_current_task_btf();
    struct task_struct *acq = bpf_task_acquire(cur);
    if (!acq) return 0;

    bpf_printk("acquired pid=%d", acq->pid);

    bpf_task_release(acq);
    return 0;
}
```

Build, load, attach, observe:

```bash
make
sudo ./kfunc_demo &                              # loads + attaches the fentry
sudo cat /sys/kernel/debug/tracing/trace_pipe &  # stream events live
for i in 1 2 3; do touch /tmp/x$i && rm /tmp/x$i; done
```

You should see one `acquired pid=N` line per delete:

```
            rm-12345   [001] ...1   842.713604: bpf_trace_printk: acquired pid=12345
            rm-12348   [000] ...1   842.714902: bpf_trace_printk: acquired pid=12348
            rm-12351   [001] ...1   842.716071: bpf_trace_printk: acquired pid=12351
```

`filename_unlinkat` fires once per `rm`, so the count of lines matches the number of deletes. The loader must stay backgrounded while you observe — killing it detaches the fentry. When done, tear everything down:

```bash
sudo pkill -f trace_pipe   # stop the streaming cat
sudo pkill kfunc_demo      # detach the fentry (loader was started with sudo)
```

## What to break

### Forget release

Comment out `bpf_task_release(acq)`. Verifier rejects:

```
Unreleased reference id=1 alloc_insn=2
```

The number tells you which acquire was leaked (multiple acquires get distinct ids).

### Conditional release

```c
if (acq->pid > 1000)
    bpf_task_release(acq);
return 0;
```

Verifier rejects — there's an exit path (when `pid <= 1000`) where the ref is leaked. The rejection is the same class of leak error as the forget-release case:

```
Unreleased reference id=1 alloc_insn=2
```

The id is `1` because there is only a single acquire in this program. The verifier requires release on **every** exit path. Fix: release before any conditional return:

```c
__u32 pid = acq->pid;
bpf_task_release(acq);
if (pid > 1000) return 0;
```

### Double release

```c
bpf_task_release(acq);
bpf_task_release(acq);
```

Rejected: the second call sees the id as already closed.

### Call a kfunc the program type isn't allowed

```c
extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cm) __ksym;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct bpf_cpumask *cm = bpf_cpumask_create();
    if (cm) bpf_cpumask_release(cm);
    return XDP_PASS;
}
```

Unlike the three breaks above, this one **can't** be reproduced by editing the fentry lab — cpumask kfuncs *are* allowed for tracing programs, so the edit has to be a separate, complete XDP object with its own loader (the program above is loadable as written). The cpumask kfunc family is registered only for TRACING, STRUCT_OPS, and SYSCALL program types (`kernel/bpf/cpumask.c`), **not** XDP. The verifier rejects at the call site — before it ever reaches the return-path or reference-leak checks — with:

```
calling kernel function bpf_cpumask_create is not allowed
```

(Note: the generic set — including `bpf_task_acquire` — *is* registered for XDP, so that one would load; it's just meaningless there. The cpumask family is the one that genuinely isn't in XDP's allowance set.)

## What to read in the kernel

- **`Documentation/bpf/kfuncs.rst`** — official categories and flags. Read top to bottom; ~10 pages. The reference for what each KF_* flag means.

- **`kernel/bpf/helpers.c:2733`** and surrounding — `bpf_task_acquire`, `bpf_task_release`, and friends. Real kfunc implementations. Note the `__bpf_kfunc` annotation and how short these are — kfuncs are usually thin wrappers around kernel APIs.

- **`kernel/bpf/helpers.c:4703`** — `BTF_KFUNCS_START(generic_btf_ids)`. The big "general purpose" kfunc set. Skim the list — it's the catalog of what a tracing program can call.

- **`kernel/bpf/cpumask.c`** — a *complete* kfunc family in one file (~530 lines). Read top to bottom. Notice the pattern: short C functions + a `BTF_KFUNCS_START` block + a `register_btf_kfunc_id_set` call at module init. This is the template for adding new kfuncs.

- **`kernel/bpf/btf.c:8996`** — `register_btf_kfunc_id_set`. The registration entry. Short function (~50 lines). Note the per-`enum bpf_prog_type` registration.

- **`kernel/bpf/verifier.c`** — search `KF_ACQUIRE`. The verifier check that creates a new ref id. Trace forward to see how `acquire_reference_state` interacts with `release_reference_state`.

- **`tools/testing/selftests/bpf/progs/task_kfunc_*.c`** — test programs exercising every aspect of acquire/release/store-in-map. Real, working examples.

## Bullet Points

- **kfuncs** are in-tree kernel functions exposed to BPF via BTF. Not UAPI; **can evolve**.
- Marked **`__bpf_kfunc`**, registered in **`BTF_KFUNCS_START`** blocks.
- **`KF_ACQUIRE`** / **`KF_RELEASE`** flags drive verifier reference-tracking.
- Declare in BPF code with **`extern T name(args) __ksym;`**.
- The verifier statically tracks reference lifetimes — leaks are rejected at load time.
- **Per-program-type registration:** not all kfuncs everywhere.
- Discover: kernel source `BTF_KFUNCS_START`, `Documentation/bpf/kfuncs.rst`, `bpftool btf dump`.
- New BPF features (cpumask, dynptr, lists, refcount, ...) ship as kfuncs, not helpers.

## Check question

Why does the verifier check release lifetimes statically rather than at runtime?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Static checking is **fast** and **total**. A runtime ref-leak detector would either (a) impose per-call overhead on every BPF program (fail at scale where BPF is in the data path), or (b) only catch leaks after the fact, which is too late — by then the leak has already happened and the kernel resource is unrecoverable.

Static analysis catches every leak at load time, before the program ever runs. The cost is paid by the **author** (writing release-correct code) instead of by every kernel that runs the program. The verifier already tracks every register's type, so adding reference-id tracking is a small extension of the existing analysis. The tradeoff is well-understood: more friction at load time in exchange for guaranteed safety at runtime.

The same principle drives the rest of the verifier — bounds checks, pointer types, register typing — all done statically. BPF's safety story is: prove it before running it.

</details>

---

## Tomorrow

Day 21: store an acquired kptr in a map across program invocations.
