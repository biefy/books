# Day 3 — CO-RE: read `task->real_parent->tgid` and survive a kernel upgrade

> **Today's mission:** read the parent PID of every process that calls `unlink`. Do it in a way that runs unchanged on the kernel you compiled against *and* on next year's kernel after the layout drifts. Total time: ~75 minutes.

## The fragile pre-CO-RE world

Before CO-RE existed, BPF tracing programs had two ugly choices:

1. **bcc-style runtime compilation.** Ship the BPF source as a string. The userspace tool detects the running kernel, calls Clang at runtime against the *current* kernel's headers, compiles the program then and there, loads it. Slow startup (Clang takes ~seconds), needs Clang+headers on every target machine, and breaks subtly when headers don't match a running kernel built from a slightly different config.

2. **Hardcoded offsets.** Read kernel struct fields with `bpf_probe_read_kernel(&out, sizeof(out), (char *)task + 1872)`. Works on exactly the kernel you derived `1872` from. Breaks the moment that struct grows a field.

Both options are why pre-2020 BPF tooling felt brittle. CO-RE killed both.

## What CO-RE actually does

You write field accesses by *name*:

```c
__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
```

The compiler emits an instruction that loads a value at offset `0xC0RE0001` (a placeholder — Clang fills the actual relocation index there). Alongside the instruction, it emits a **CO-RE relocation record** that says: *"the offset I just used is bogus; at load time, look up the byte offset of `task_struct.real_parent` in the target kernel's BTF and patch this instruction with the real value."*

When libbpf loads the program, it walks every CO-RE relocation, looks up the field by name in `/sys/kernel/btf/vmlinux`, computes the offset, and patches the instruction. Same `.o` file, different patched offsets per kernel.

![CO-RE relocation across two kernels](diagrams/day03_core_relocation.png)

This is why your Day 1 program's `BPF_PROG(on_unlink, int dfd, struct filename *name)` worked without you knowing the byte offset of *anything* — every kernel-type access went through this name-based relocation.

> ### There are no Dumb Questions
>
> **Q: Why doesn't C just do this normally? My userspace programs include kernel headers and read fields by name.**
>
> A: Userspace `#include <linux/sched.h>` reads the *headers from when you compiled*. If the running kernel has a different layout, you crash or read wrong bytes — that's why people warn against using kernel headers from outside `/proc`. CO-RE inverts the model: you build BPF programs as if struct layouts are *unknown* until load time, then libbpf resolves them against ground truth.
>
> **Q: What if a field doesn't exist on the target kernel?**
>
> A: There are CO-RE primitives for that:
> - `bpf_core_field_exists(task->real_parent)` — returns 1 if the field exists, 0 otherwise.
> - `bpf_core_type_exists(struct foo)` — same for whole types.
> - `bpf_core_enum_value_exists(...)` — same for enum members.
>
> If you check existence and skip access, libbpf will *also* patch the access instruction to a no-op when the field is missing. You can ship one program that gracefully degrades across kernel versions.
>
> **Q: Are direct typed-pointer derefs the same as `BPF_CORE_READ`?**
>
> A: Almost. With BTF and the right program type, the Verifier accepts `task->real_parent->tgid` and the compiler emits CO-RE-relocated instructions. The difference is fault-handling: `BPF_CORE_READ` expands to `bpf_probe_read_kernel`, which fault-tolerates bad pointers (returns -EFAULT instead of taking down the BPF program); direct deref of a `PTR_TO_BTF_ID` is faster but assumes the pointer is valid. For arguments handed to you by the kernel (fentry params, `bpf_get_current_task_btf()`), direct deref is fine. For pointers reached through several hops, prefer `BPF_CORE_READ` so a NULL hop is reported, not crashed on.

> ### Sharpen your pencil
>
> Your Day 2 program reads `bpf_get_current_pid_tgid() >> 32` to get the PID. That doesn't go through CO-RE — there's no struct field involved. But the BPF program still has to know it's running on Linux x86_64 vs ARM64. What handles that abstraction?
>
> .  
> .  
> .
>
> **Answer:** the helper itself. `bpf_get_current_pid_tgid` is implemented in `kernel/bpf/helpers.c` and is called the same way regardless of arch. Architecture-specific work happens *inside* the kernel implementation. CO-RE is for accessing kernel data structures whose *layout* differs across kernel versions, not for arch-portable helper calls.

---

## Meet the cast

### `bpf_get_current_task_btf` — typed access to `current`

Returns a `struct task_struct *` with the BTF type tag attached. The Verifier knows it's a valid kernel pointer. You can deref fields directly. Cheaper than `bpf_get_current_task` (the older variant that returned an opaque `u64` you had to cast).

### `BPF_CORE_READ(task, a, b, c)` — chained CO-RE-aware reads

Expands to a series of `bpf_probe_read_kernel` calls walking each pointer hop, with CO-RE relocations on each field access. Equivalent to:

```c
struct task_struct *p1 = task;
struct task_struct *p2;
__u32 result;
bpf_probe_read_kernel(&p2, sizeof(p2), &p1->real_parent);  // CO-RE: real_parent offset
bpf_probe_read_kernel(&result, sizeof(result), &p2->tgid); // CO-RE: tgid offset
```

The macro saves you that boilerplate and fault-handles each hop.

![Field chain](diagrams/day03_field_chain.png)

### `BPF_CORE_READ_INTO(dst, src, a, b, c)`

Same thing but writes the final value into `*dst` instead of returning it. Use when the field is larger than 8 bytes (e.g., reading `task->comm[16]` into a buffer).

### `BPF_CORE_READ_STR_INTO(dst, src, a, b, c)`

Reads a NUL-terminated string. Bounds the read at `sizeof(dst)`. Returns the actual length copied.

---

## The lab

### `parent.bpf.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char pcomm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/filename_unlinkat")
int BPF_PROG(on_unlink)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent;
    struct event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&e->comm, task, comm);
    BPF_CORE_READ_STR_INTO(&e->pcomm, task, real_parent, comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

What's new:

- `bpf_get_current_task_btf()` returns a typed `struct task_struct *`. Its proto's return type is `RET_PTR_TO_BTF_ID_TRUSTED`, so the Verifier marks the register a trusted, non-NULL `PTR_TO_BTF_ID` — you can deref its fields directly with no NULL check.
- `BPF_CORE_READ(task, real_parent, tgid)` — three-arg form. Walks `task → real_parent → tgid`. Each hop is a CO-RE-relocated read.
- `BPF_CORE_READ_STR_INTO(&e->comm, task, comm)` — reads `task->comm` (a 16-byte char array, not a pointer). Note `comm` is the last arg; for non-pointer fields you don't need a final `*` deref hop.

### Userspace `parent.c`

Same skeleton + ringbuf consumer pattern as Day 1. Print:

```c
printf("PID %d (%s) ppid %d (%s) deleted a file\n",
       e->pid, e->comm, e->ppid, e->pcomm);
```

### Run it

```bash
make
sudo ./parent &
touch /tmp/x && rm /tmp/x
```

Expected:

```
PID 24501 (rm) ppid 24450 (bash) deleted a file
```

We backgrounded the consumer with `&`, so stop it before moving on (otherwise it keeps polling the ringbuf and printing into the shell while you run the inspect/break steps):

```bash
sudo pkill -f ./parent
```

(Or, mirroring Day 1, run `sudo ./parent` in the foreground in one terminal, do the `touch /tmp/x && rm /tmp/x` in a second terminal, and Ctrl-C the consumer when done.)

---

## Inspect what CO-RE actually emitted

This is the most important step today. You need to *see* the relocations to believe they exist.

Disassemble the object with relocations interleaved (the `-r` flag is what makes the CO-RE records appear — `-d` alone never prints them):

```bash
llvm-objdump -dr parent.bpf.o | grep CO-RE
```

Recent LLVM annotates the BPF disassembly with the CO-RE relocation records read from the object's `.BTF.ext` section. You'll see one line per kernel-field access:

```
0000000000000060:  CO-RE <byte_off> [13] struct task_struct::real_parent
00000000000000a0:  CO-RE <byte_off> [13] struct task_struct::tgid
00000000000000e8:  CO-RE <byte_off> [13] struct task_struct::comm
```

(addresses and the type index `[13]` vary by build). Drop the `| grep CO-RE` to see the full disassembly: the load instruction just above each relocation carries the **compile-time** byte offset Clang baked in — e.g. `r1 = 0xae0` for `real_parent` — *not* a placeholder like `0x0`. libbpf rewrites that immediate at load time if the running kernel's layout differs. CO-RE relocation records live in the ELF section `.BTF.ext` (the object also has `.BTF`, `.rel.BTF`, and `.rel.BTF.ext`); there is no `.relo.btf` section.

To inspect the embedded types instead:

```bash
bpftool btf dump file parent.bpf.o
```

You'll see your `struct event`, your maps, and references to kernel types like `task_struct.real_parent`.

> **Aside — shipping minimal BTF.** `bpftool gen min_core_btf /sys/kernel/btf/vmlinux min.btf parent.bpf.o` writes a minimal BTF file containing only the types your program references (it prints nothing to stdout). That's for *portability* — shipping a tiny BTF alongside your `.o` for kernels without `/sys/kernel/btf/vmlinux` — not for inspecting relocations.

To watch the relocations get applied at load time, you need **libbpf's own debug log**, not the kernel verifier log. The two are different: `.kernel_log_level` feeds `bpf_attr.log_level`, which controls the in-kernel *verifier* log (a disassembled, post-relocation instruction dump plus verifier state). CO-RE patching happens in libbpf userspace *before* the `BPF_PROG_LOAD` syscall, so the verifier log contains no `CO-RE` string and no relocation provenance — grepping it for `CO-RE` finds nothing.

The patching messages come out of libbpf's print callback at the `LIBBPF_DEBUG` level. Easiest from the shell — load with bpftool's `-d` flag (which sets libbpf to `LIBBPF_DEBUG`) and grep for the relocation lines:

```bash
sudo bpftool -d prog load parent.bpf.o /sys/fs/bpf/parent 2>&1 | grep relo
sudo rm -f /sys/fs/bpf/parent   # clean up the pin
```

You'll see lines like `prog 'on_unlink': relo #N: ... patched insn ...`. From C, register a print callback and raise the level before open/load:

```c
static int dbg(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    return vfprintf(stderr, fmt, ap);
}
// in main(), before parent_bpf__open():
libbpf_set_print(dbg);
```

Note libbpf's *default* print callback only emits `WARN` to stderr; the `INFO`/`DEBUG` relocation lines are suppressed unless you install your own callback or use a debug-enabled loader.

---

## What to break, in order

### Break 1 — Use a non-existent field

Add this line:

```c
__u32 fake = BPF_CORE_READ(task, this_field_does_not_exist);
```

You might expect this to compile and only blow up at load time. It doesn't — the build fails immediately:

```
error: no member named 'this_field_does_not_exist' in 'struct task_struct'
```

Here's why: `BPF_CORE_READ` doesn't reference fields by an opaque name string. It expands to the *real* C member-access expression (`task->this_field_does_not_exist`) wrapped in `__builtin_preserve_access_index`, and Clang type-checks that member against the `struct task_struct` in your `vmlinux.h`. A name that exists in no BTF at all is a plain C error. (`bpf_core_field_exists(task->this_field_does_not_exist)` fails the same way — it also emits the member-access expression.)

So to exercise the genuine load-time **relocation-failure** path — the one that prints

```
libbpf: prog 'on_unlink': relo #N: failed to relocate ...
```

you need a field that *exists in your build's BTF/`vmlinux.h` but is absent on the **target** kernel*. The realistic way to trigger it is to compile against a newer `vmlinux.h` and load on an older kernel that lacks the field.

For the graceful-degradation demo, use a field that actually exists so the program compiles, and gate it on `bpf_core_field_exists`:

```c
__u32 fake = 0;
if (bpf_core_field_exists(task->pid))
    fake = BPF_CORE_READ(task, pid);
```

The point of `bpf_core_field_exists` is fields that *appear or disappear across kernel versions*: libbpf evaluates the check at load time against the target kernel's BTF and patches the branch to a no-op when the field is absent, so a single `.o` runs on kernels that have or lack the field. It is **not** a way to reference a name that exists in no BTF at all.

### Break 2 — Direct deref vs `BPF_CORE_READ`

Replace the macro form with direct deref:

```c
e->ppid = task->real_parent->tgid;
```

Compiles. Verifier accepts. Runs. **Faster** than `BPF_CORE_READ` because no `bpf_probe_read_kernel` call.

But: if `task->real_parent` were ever NULL (it's not for real processes, but if you used a different field that could be NULL), this would crash the BPF program at runtime — actually, the Verifier won't let it crash; it'll terminate the program early. Either way you lose the event. `BPF_CORE_READ` returns a default 0 on bad pointers, which is usually what you want for telemetry.

For Day 3, both forms work. Internalize: **direct deref for kernel-handed-to-you trusted pointers, `BPF_CORE_READ` for chains where any hop could fail.**

### Break 3 — Forget `#include <bpf/bpf_core_read.h>`

`BPF_CORE_READ` is undefined; compile fails. Trivial, but worth noting: BPF helper headers are split across `bpf_helpers.h` (general), `bpf_tracing.h` (BPF_PROG, ctx unpacking, PT_REGS_*), `bpf_core_read.h` (CO-RE macros). Forget any of them and the failure mode is "macro X not defined."

---

## What to read in the kernel

- **`tools/lib/bpf/relo_core.c`** — the CO-RE engine in userspace. `bpf_core_calc_relo_insn` computes the relocation value from target-kernel BTF, and `bpf_core_patch_insn` writes it into the instruction's offset/immediate. ~300 lines, accessible if you know what to look for.
- **`tools/lib/bpf/btf.c`** — read `btf__find_by_name_kind`. This is how libbpf finds types in BTF by name. CO-RE is built on top of it.
- **`tools/lib/bpf/bpf_core_read.h`** — search `BPF_CORE_READ`. The macros expand to a chain of `bpf_core_read` (kernel-side) calls; reading them once eliminates magic.
- **`include/linux/btf.h`** — see `struct btf_type` and the `BTF_KIND_*` enums. BTF has only ~12 kinds (int, ptr, array, struct, union, enum, fwd, typedef, volatile, const, restrict, func, ...). Skim.

---

## Bullet Points

- **CO-RE = Compile Once, Run Everywhere.** Field offsets are resolved at load time using target-kernel BTF.
- **Use `BPF_CORE_READ(a, b, c, d)`** to chain field accesses through pointer hops with fault-handling on each hop.
- **Use direct deref** (`task->real_parent->tgid`) when the pointer chain is trusted and you want speed.
- **Handle missing fields with `bpf_core_field_exists`** — libbpf will patch the access to a no-op when the field is absent.
- **`bpf_get_current_task_btf()`** returns a typed `task_struct *` you can deref directly.
- BTF kinds you'll meet: `STRUCT`, `UNION`, `ENUM`, `INT`, `PTR`, `ARRAY`, `FUNC`, `TYPEDEF`. About 12 total.

---

## Check question

You compile your program against kernel A. Field `task_struct.real_parent` is at offset 1872. You ship the `.o` to a machine running kernel B where the same field is at offset 1920. Your program does `BPF_CORE_READ(task, real_parent, tgid)`. Walk through what happens at load time.

<details>
<summary>Click to reveal answer</summary>

**Answer:** libbpf opens `/sys/kernel/btf/vmlinux` on kernel B, parses it, finds the type `task_struct` and its field `real_parent`, computes byte offset 1920. It walks every CO-RE relocation in your `.o`. For the `real_parent` access, it overwrites the placeholder offset (the `0xC0RE...` immediate the compiler emitted) with `1920`. Same for `tgid`. Then `BPF_PROG_LOAD` is called with the patched instructions. The Verifier accepts. The program runs, reading the correct fields on kernel B.

</details>

---

## Tomorrow

Day 4: meet the Verifier properly. We'll spend a whole day deliberately tripping over `PTR_TO_MAP_VALUE_OR_NULL` rejections in five different shapes — because every BPF programmer, no matter how senior, hits this error monthly. The goal: stop being surprised by the rejection and start reading the log fluently.
