# Day 24 — BTF spelunking: finding and using kfuncs you haven't met

> **Today's mission:** find a kfunc on your kernel that you've never used, read its signature from BTF, write a program that calls it. Total time: ~75 minutes. End of Phase 4.

## Why discoverability matters

The kernel has **hundreds** of kfuncs. They're partially documented in `Documentation/bpf/kfuncs.rst` but the doc is incomplete and lags behind the kernel. The authoritative source is **BTF in your running kernel**.

Today's skill: navigate that authoritative source.

![BTF kinds](diagrams/day24_btf_kinds.png)

## How BTF describes the kernel

BTF is a compact debug-info-like format describing every type in the kernel and every (selected) function. It lives in:

- **`/sys/kernel/btf/vmlinux`** — the running kernel's BTF (~5–10 MB binary blob). Generated at kernel build via `pahole` consuming DWARF.
- **`/sys/kernel/btf/<module>`** — per-module BTF for loadable kernel modules.

Every type, struct, enum, function, and variable the kernel exposes is in there. BPF programs reference kernel symbols **by name** against BTF; libbpf and the verifier resolve the names to BTF entries at load time.

For kfuncs specifically, BTF holds:

- The function's name (string).
- Its signature: argument types, return type.
- Source-file annotations.

You can dump BTF in human-readable form with `bpftool`:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux | head -20
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -30   # as a C header
```

## Three approaches to finding a kfunc

![kfunc discovery](diagrams/day24_kfunc_discovery.png)

### 1. Search kernel source for `BTF_KFUNCS_START`

Each kfunc family is declared in a block:

```bash
cd ~/code/linux
grep -rn 'BTF_KFUNCS_START' kernel/bpf net/ drivers/ 2>/dev/null
```

You'll see ~30+ hits. Each block looks like:

```c
BTF_KFUNCS_START(generic_kfunc_set)
BTF_ID_FLAGS(func, bpf_obj_new_impl, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_obj_drop_impl, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_refcount_acquire_impl, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_list_push_front_impl)
/* ... */
BTF_KFUNCS_END(generic_kfunc_set)
```

This tells you what kfuncs exist and their flags (`KF_ACQUIRE`, `KF_RELEASE`, `KF_RCU`, `KF_TRUSTED_ARGS`, etc.). Kernel source is the source of truth.

### 2. Dump kernel BTF and search for FUNC entries

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux \
    | grep "FUNC.*name=bpf_" | head -20
```

Filters all `FUNC` BTF kinds where the name starts with `bpf_`. You'll see thousands. Many are kfuncs; many are helpers; many are internal kernel functions exposed for other reasons. To narrow down to kfuncs, cross-reference with the source method.

### 3. Documentation

`Documentation/bpf/kfuncs.rst` lists categories: cpumask, dynptr, lists, refcount, task, etc. Get the names from there, then look up signatures in BTF for the latest details. The doc is a useful tour map but not an inventory.

## Reading a kfunc signature from BTF

Once you have a name (say, `bpf_cpumask_create`), get the signature:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c \
    | grep -B2 -A5 'bpf_cpumask_create'
```

Output:

```c
struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
```

That's exactly what you'd write in your BPF source.

For more complex signatures (multiple args, struct returns):

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux \
    | awk '/FUNC.*name=bpf_dynptr_from_skb/{f=1} f{print; if(/^$/){exit}}'
```

(Show the FUNC line and the lines describing its prototype.)

## A complete example: `bpf_cpumask_*`

`bpf_cpumask_*` is a family of kfuncs for working with CPU masks (one bit per CPU). Useful for: scheduler hints, CPU affinity inspection, sched_ext.

The family is defined at `kernel/bpf/cpumask.c`. Read the file's `BTF_KFUNCS_START` block to see what's available:

```c
BTF_KFUNCS_START(cpumask_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_cpumask_create, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cpumask_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_cpumask_acquire, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_cpumask_first, KF_RCU)
BTF_ID_FLAGS(func, bpf_cpumask_setall)
BTF_ID_FLAGS(func, bpf_cpumask_set_cpu)
BTF_ID_FLAGS(func, bpf_cpumask_clear_cpu)
BTF_ID_FLAGS(func, bpf_cpumask_test_cpu)
BTF_ID_FLAGS(func, bpf_cpumask_or, KF_RCU)
BTF_ID_FLAGS(func, bpf_cpumask_equal, KF_RCU)
/* ... */
BTF_KFUNCS_END(cpumask_kfunc_btf_ids)
```

Each is a regular C function in the same file. Read the `__bpf_kfunc` definitions to see what they actually do.

### Using them

```c
/* cpumask_demo.bpf.c */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;
extern void bpf_cpumask_set_cpu(__u32 cpu, struct bpf_cpumask *cpumask) __ksym;
extern bool bpf_cpumask_test_cpu(__u32 cpu, const struct cpumask *cpumask) __ksym;

SEC("fentry/filename_unlinkat")
int BPF_PROG(p)
{
    struct bpf_cpumask *m = bpf_cpumask_create();
    if (!m) return 0;       /* KF_RET_NULL — must check */

    /* Set bits for CPUs 0, 2, 4 */
    bpf_cpumask_set_cpu(0, m);
    bpf_cpumask_set_cpu(2, m);
    bpf_cpumask_set_cpu(4, m);

    /* Test some bits */
    bool b0 = bpf_cpumask_test_cpu(0, (struct cpumask *)m);
    bool b1 = bpf_cpumask_test_cpu(1, (struct cpumask *)m);

    bpf_printk("cpu0=%d cpu1=%d", b0, b1);

    bpf_cpumask_release(m);  /* KF_ACQUIRE → must release */
    return 0;
}
```

Note the cast `(struct cpumask *)m` — `bpf_cpumask_test_cpu` takes the *base* type (`struct cpumask`), not the BPF-specific wrapper (`bpf_cpumask`). The verifier accepts the cast because `bpf_cpumask` embeds `cpumask` as its first field. This idiom shows up across the kfunc family.

### Run

```bash
make
sudo ./cpumask_demo &
touch /tmp/x && rm /tmp/x
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Output: `cpu0=1 cpu1=0`.

## What to break

### Forget release

```c
struct bpf_cpumask *m = bpf_cpumask_create();
/* ... use ... */
return 0;   /* without bpf_cpumask_release */
```

Verifier rejects: `Unreleased reference id=1 alloc_insn=M`. `bpf_cpumask_create` is `KF_ACQUIRE`; the rules from Day 20 apply.

### Use a kfunc not registered for your program type

Try `bpf_cpumask_create` from an XDP program:

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct bpf_cpumask *m = bpf_cpumask_create();
    /* ... */
}
```

Verifier rejects: `calling kernel function bpf_cpumask_create is not allowed`. Check `kernel/bpf/cpumask.c`'s registration:

```c
register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &cpumask_kfunc_set);
register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &cpumask_kfunc_set);
register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &cpumask_kfunc_set);
```

Cpumask is registered for tracing, struct_ops, and syscall — not XDP. The verifier knows.

### Discover a new family

Try `bpf_dynptr_*`:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep 'bpf_dynptr'
```

You'll see `bpf_dynptr_data`, `bpf_dynptr_read`, `bpf_dynptr_write`, `bpf_dynptr_from_skb`, etc. These let BPF programs handle variable-size buffers safely. Try one in a program; the kfunc family is a good way to learn the dynptr pattern (a verifier-tracked variable-size pointer).

## What to read in the kernel

- **`Documentation/bpf/kfuncs.rst`** — the official tour. Read end to end. ~10 pages.

- **`kernel/bpf/cpumask.c`** — full kfunc family in one file (~700 lines). Read top to bottom. The structure is:
  1. Implementation — `__bpf_kfunc` functions.
  2. ID list — `BTF_KFUNCS_START` block.
  3. `register_btf_kfunc_id_set` calls at module init.

  This is the **template** for adding kfuncs. If you ever want to add one, this is what your patch will look like.

- **`kernel/bpf/helpers.c`** — search `BTF_KFUNCS_START`. The biggest set of generic kfuncs (`generic_btf_ids`, `common_btf_ids`). Skim to know the catalog.

- **`kernel/sched/ext.c`** — sched_ext registers many sched-specific kfuncs. The eBPF book's Day 25–27 use these.

- **`tools/lib/bpf/btf.c`** — userspace BTF library. The `btf__find_by_name_kind` function is what libbpf uses to resolve `__ksym` references at load time.

- **`include/linux/btf.h`** — `struct btf_type`, `BTF_KIND_*`. The vocabulary of BTF.

- **`bpftool` source** at `tools/bpf/bpftool/btf.c` — useful to read just to learn what BTF queries are easy from the CLI.

## Bullet Points

- **Discover kfuncs** via: kernel source `BTF_KFUNCS_START` blocks, `bpftool btf dump`, or `Documentation/bpf/kfuncs.rst`.
- **Signatures** come from BTF; declare in BPF code with `extern T name(args) __ksym;`.
- **Acquire/release** semantics from Day 20 apply uniformly — every kfunc family follows the same model.
- **Per-program-type registration**: not all kfuncs are everywhere; the verifier rejects unregistered combinations.
- The kernel's kfunc set grows release-by-release; check `bpftool feature probe` for what's available.
- **`bpftool btf dump file ... format c`** gives you C-style declarations you can paste into your BPF source.

## Check question

You write `extern int my_fn(int x) __ksym;` and reference `my_fn`. The kernel doesn't have a kfunc by that name. What happens at compile time vs at load time?

<details>
<summary>Click to reveal answer</summary>

**Answer:** **Compile time succeeds.** The `__ksym` attribute is a marker for libbpf, not a compile-time check; the C compiler treats `extern` as "this exists somewhere." The reference compiles fine into a relocation entry in the `.bpf.o` file (saying "I need a symbol named `my_fn`").

**At load time, libbpf fails:** `libbpf: cannot find kernel BTF type ID of 'my_fn'`. libbpf walks the program's relocations, looks up each `__ksym` reference against the running kernel's BTF, and aborts if the name doesn't resolve.

This is the right design: `__ksym` references are resolved at runtime against the *target* kernel's BTF, not at compile time against the *build* kernel. That's how you compile once and run on multiple kernels with potentially different kfunc availability — a kernel that has the kfunc loads your program; a kernel that doesn't returns the descriptive error.

For graceful degradation across kernel versions, combine `__ksym` with `bpf_core_type_exists()` checks — your program tests at runtime whether the kfunc is available and skips the call if not.

</details>

---

## End of Phase 4

You can now use kfuncs, store kptrs in maps, write struct_ops modules, instrument them with ringbuf, and discover new kfuncs by reading BTF. That's the modern BPF surface as of 2026.

Phase 5 (Days 25–30) is the frontier — sched_ext, BPF schedulers, and a capstone project.
