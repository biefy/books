# Day 25 — sched_ext: a BPF scheduler in 30 minutes

> **Today's mission:** load `scx_simple` on your system, watch it actually scheduling tasks, understand the basic enqueue/dispatch cycle. Total time: ~75 minutes.

> **Phase 5 starts here.** Days 25–30 are about the frontier. You'll run a BPF scheduler, modify it, then build a capstone project of your choosing. By Day 30, you've shipped one substantial piece of BPF work.

## What sched_ext is

The Linux scheduler decides *which task runs on which CPU at which time*. Until 2024, this logic lived entirely in the kernel — `kernel/sched/fair.c` (CFS), with policy hardcoded. To change it required a kernel patch, kernel rebuild, reboot, hope.

**sched_ext** (merged into 6.12, Oct 2024) makes the scheduler pluggable via BPF. You write a struct_ops module against `struct sched_ext_ops`. Loading it activates your scheduler. Unloading reverts to CFS.

![sched_ext overview](diagrams/day25_sched_ext.png)

The watchdog is what makes this shippable. A faulty BPF scheduler that fails to dispatch tasks would freeze the system. The kernel monitors: if any task waits > 30 seconds without dispatch, the BPF scheduler is ejected and CFS takes over.

## The core cycle: enqueue → DSQ → dispatch

![DSQ cycle](diagrams/day25_dsq_cycle.png)

The BPF scheduler implements callbacks for two main events:

- **`enqueue(task, flags)`** — a task becomes runnable. You decide *where to put it*. Most BPF schedulers put tasks in **DSQs** (Dispatch Queues).
- **`dispatch(cpu, prev)`** — a CPU is going idle and needs a task to run next. You decide *which task to give it* (typically by pulling from a DSQ).

DSQs are FIFO queues managed by the kernel. You don't implement them; you consume the API: `scx_bpf_dispatch(p, dsq_id, slice, flags)` to enqueue, `scx_bpf_consume(dsq_id)` to pull.

Built-in DSQs:
- `SCX_DSQ_GLOBAL` — single queue, all CPUs.
- `SCX_DSQ_LOCAL` — per-CPU queue.

Custom DSQs: create with `scx_bpf_create_dsq(id, node)`.

## The lab — run scx_simple

`scx_simple` is the "hello world" of sched_ext: a BPF scheduler that just dispatches everything to a single global queue.

### Build the kernel's sched_ext examples

```bash
cd ~/code/linux/tools/sched_ext
make
ls
# scx_simple  scx_central  scx_flatcg  scx_userland  ...
```

### Run scx_simple

```bash
sudo ./scx_simple
```

You'll see periodic stats output:
```
local=12345 global=0 ...
```

Your system is **now scheduled by BPF**. Run something that exercises scheduling:

```bash
# in another terminal:
stress-ng --cpu 4 --timeout 30
```

Watch system responsiveness. With `scx_simple`, basic responsiveness is preserved (it's a working scheduler) but you're not getting CFS's fair-share guarantees — it's literally a global queue.

### What's running

Read `tools/sched_ext/scx_simple.bpf.c`:

```c
SEC("struct_ops/simple_enqueue")
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 vtime = p->scx.dsq_vtime;
    /* Place in global DSQ */
    scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
}

SEC("struct_ops/simple_dispatch")
void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_consume(SHARED_DSQ);
}

/* ... init, exit, vtable ... */
```

That's the whole scheduler. ~30 lines of BPF. Plus userspace plumbing in `scx_simple.c` (~200 lines).

### Stop it

Ctrl-C. Watchdog detects exit; CFS takes over. Re-test with `stress-ng` — now you're back to default behavior.

> ### There are no Dumb Questions
>
> **Q: Did I just replace the kernel's scheduler with my own code?**
>
> A: Yes. Specifically, `scx_simple` is now scheduling every task on your system that hits the scheduler hot path. Your shell, your browser if it's running, kernel threads — everything goes through enqueue/dispatch in BPF.
>
> **Q: This sounds dangerous.**
>
> A: The watchdog is the safety net. If your scheduler stalls — fails to dispatch any task to a CPU for 30s — the kernel ejects it and re-enables CFS. Worst case, a 30-second freeze, then recovery. Don't ship to production without testing under load and adverse conditions.
>
> **Q: What about real-time tasks, kthreads, kworkers?**
>
> A: BPF schedulers handle them all by default. You can opt out specific tasks (e.g., per-CPU kthreads) via `scx_bpf_select_cpu_dfl` to fall back to default placement.

---

## What to break, in order

### Break 1 — Don't dispatch

Comment out `scx_bpf_consume(SHARED_DSQ)` in `simple_dispatch`. The CPU has nothing to run; tasks pile up in the queue. After ~30s, watchdog ejects.

You'll see `dmesg`:
```
sched_ext: BPF scheduler "simple" disabled by watchdog
```

System recovers. **Don't break the dispatch loop in production.**

### Break 2 — Always dispatch with vtime=0

Set `vtime = 0` in `simple_enqueue`. Every task has the same priority. Long-running tasks dominate; interactive tasks lag. CFS's vtime accounting is the simplest fairness mechanism; copying it is the path of least surprise.

### Break 3 — Add per-CPU DSQs

Replace `SHARED_DSQ` with per-CPU DSQs. Each CPU pulls from its own. No cross-CPU contention but no automatic load balancing — manually rebalance in `dispatch` when own DSQ empty.

This is what `scx_central` does (Day 27).

### Break 4 — Add a tracepoint

Inside `simple_enqueue`, emit to ringbuf:

```c
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (e) { e->pid = p->pid; ...; bpf_ringbuf_submit(e, 0); }
```

You're now observing every scheduler decision in real-time. Throughput consideration: at high task-switch rates (1M+/sec), even a few ns per emit becomes meaningful. Filter aggressively or aggregate in BPF.

---

## What to read in the kernel

- **`kernel/sched/ext.c`** — the framework. ~5000 lines. **Read the file's top comment** for the design overview. Don't try to read the whole thing today.
- **`kernel/sched/ext_idle.c`** — the idle CPU integration.
- **`tools/sched_ext/scx_simple.bpf.c`** — read in full.
- **`tools/sched_ext/include/scx/common.bpf.h`** — kfunc declarations and helpers.
- **`Documentation/scheduler/sched-ext.rst`** — official guide.

---

## Bullet Points

- **sched_ext** lets BPF programs implement Linux schedulers via `struct sched_ext_ops` (struct_ops).
- Two main callbacks: **`enqueue`** (task becomes runnable) and **`dispatch`** (CPU needs a task).
- **DSQs** are kernel-managed dispatch queues; built-in ones are `SCX_DSQ_GLOBAL` and `SCX_DSQ_LOCAL`.
- **Watchdog** ejects stalled BPF schedulers (no dispatch in 30s) and falls back to CFS.
- `scx_simple` is the minimal example; `scx_central`, `scx_flatcg` are richer.
- Loading scx is a system-wide operation — affects every task.

---

## Check question

What guarantees that loading a BPF scheduler doesn't permanently freeze your machine?

.  
.  
.

**Answer:** The 30-second dispatch watchdog. The kernel monitors task wait times; if any task has been runnable but not dispatched for 30 seconds, the framework concludes the BPF scheduler is broken and ejects it, re-enabling CFS. Recovery is automatic. The watchdog is hardcoded into `kernel/sched/ext.c`'s safety logic and is not bypassable from BPF. This is the design that makes BPF scheduling practical — without it, no one would risk loading user code into the scheduler hot path.

---

## Tomorrow

Day 26: modify `scx_simple` to prioritize a specific cgroup. See your changes affect a real workload.
