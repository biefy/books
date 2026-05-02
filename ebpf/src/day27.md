# Day 27 — scx_central: read a real BPF scheduler

> **Today's mission:** read `scx_central.bpf.c` — a production-grade BPF scheduler with central-dispatch architecture. Understand the patterns experienced sched_ext authors use. Total time: ~75 minutes. Reading-heavy, not coding-heavy.

## Why read this one

`scx_simple` is illustrative but trivial. `scx_central` is the next step up: realistic. It handles per-CPU dispatch queues, cross-CPU coordination, central scheduling decisions, and the kinds of details you'd hit on day one of writing a real scheduler.

Reading code that someone else wrote — *and understanding why they wrote it that way* — is a separate skill from writing your own. Today is for that.

## DSQ patterns

![DSQ patterns](diagrams/day27_dsq_patterns.png)

Three architectures show up across the in-tree examples:

1. **Global DSQ** — `scx_simple`. One queue, all CPUs.
2. **Per-CPU DSQs** — each CPU pulls from its own.
3. **Central DSQ** — one CPU dispatches for all others.

`scx_central` is option 3 with a twist: a designated CPU runs all dispatch logic; other CPUs only consume. This sounds like a bottleneck — and it is — but it lets you put complex policy in one place without per-CPU coordination.

## What to read

Open `tools/sched_ext/scx_central.bpf.c`. ~350 lines. Walk through it in this order:

### 1. Global state

Look at the maps and globals near the top:

```c
const volatile s32 central_cpu;        /* which CPU is "central" */
const volatile u32 nr_cpu_ids;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(value, struct cpu_state);
    __uint(max_entries, 1);
} cpu_state SEC(".maps");
```

`central_cpu` is set from userspace at attach time. `cpu_state` is per-CPU local state.

### 2. The init callback

```c
SEC("struct_ops/central_init")
s32 BPF_STRUCT_OPS(central_init)
{
    return scx_bpf_create_dsq(FALLBACK_DSQ, -1);
}
```

Just creates a fallback DSQ. The work happens later.

### 3. The select_cpu callback

```c
SEC("struct_ops/central_select_cpu")
s32 BPF_STRUCT_OPS(central_select_cpu, struct task_struct *p, ...)
{
    /* always pick central_cpu */
    return central_cpu;
}
```

When a task wakes, route it to the central CPU. The central CPU will then enqueue and dispatch.

### 4. The enqueue callback

```c
SEC("struct_ops/central_enqueue")
void BPF_STRUCT_OPS(central_enqueue, struct task_struct *p, u64 enq_flags)
{
    /* push into a single DSQ that the central CPU consumes */
    scx_bpf_dispatch(p, FALLBACK_DSQ, SCX_SLICE_INF, enq_flags);
    bpf_kick_cpu(central_cpu, 0);   /* wake central CPU if asleep */
}
```

`bpf_kick_cpu` is a kfunc that triggers an IPI to the named CPU. This is how you ensure the central CPU dispatches when work appears.

### 5. The dispatch callback

```c
SEC("struct_ops/central_dispatch")
void BPF_STRUCT_OPS(central_dispatch, s32 cpu, struct task_struct *prev)
{
    if (cpu != central_cpu) return;     /* only central decides */

    bpf_for(i, 0, nr_cpu_ids) {
        struct task_struct *p = scx_bpf_consume(FALLBACK_DSQ);
        if (!p) break;
        /* dispatch p to CPU `i` */
    }
}
```

The pattern: only `central_cpu`'s call into `dispatch` actually does work. Others receive the kick from enqueue and drop into idle.

### 6. The vtable

```c
SEC(".struct_ops.link")
struct sched_ext_ops central_ops = {
    .select_cpu = (void *)central_select_cpu,
    .enqueue = (void *)central_enqueue,
    .dispatch = (void *)central_dispatch,
    .init = (void *)central_init,
    .name = "central",
};
```

`SEC(".struct_ops.link")` is a newer variant that creates a link FD (lifecycle bound, like tcx).

> ### There are no Dumb Questions
>
> **Q: Why would anyone want a single-CPU bottleneck for scheduling?**
>
> A: Centralization simplifies policy. If you want anti-thrashing, latency-priority queues, gang scheduling, or any decision that requires global state, central architecture means you don't need cross-CPU locking. Cost is a single CPU's worth of overhead — measurable but bounded.
>
> **Q: How does `scx_central` avoid the watchdog?**
>
> A: The central CPU keeps dispatching. As long as it's not stalled itself (e.g., looping), tasks get dispatched promptly. If the central CPU somehow stalls (e.g., infinite loop in your BPF), watchdog ejects.
>
> **Q: Is `scx_central` actually production-deployable?**
>
> A: It's an example, not a production scheduler. Real schedulers (Meta's `scx_layered`, others) are richer — multiple priority queues, energy awareness, NUMA topology. But the patterns in `scx_central` (per-CPU select, central dispatch, kick) generalize.

## What about scx_flatcg?

If you have appetite for more reading, open `tools/sched_ext/scx_flatcg.bpf.c`. ~600 lines. Same shape but cgroup-aware: each cgroup gets its own DSQ; vtime is per-cgroup; dispatch picks the cgroup with the lowest vtime first.

This is closer to how a real "fair-share + isolation" scheduler looks.

## Bullet Points

- `scx_central` shows the **central-dispatch** pattern: one CPU makes all scheduling decisions.
- `scx_bpf_kick_cpu(cpu, 0)` triggers an IPI to wake a CPU.
- `SEC(".struct_ops.link")` (vs `.struct_ops`) creates link-managed scheduler instances.
- Read order: globals → init → select_cpu → enqueue → dispatch → vtable.
- `scx_flatcg` is the next step up — cgroup-aware fair-share with per-cgroup DSQs.

---

## Check question

In `scx_central`, every task wake-up is routed to `central_cpu`. Why doesn't this catastrophically increase wake-up latency?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Because `select_cpu` returning `central_cpu` doesn't actually run the task there — it just routes the *enqueue* and *dispatch* logic to that CPU. The task itself is dispatched (in the dispatch callback's loop) to whichever CPU has capacity. The central CPU is a **policy** bottleneck, not a **mechanism** bottleneck. The task ultimately runs on a peer CPU; only the decision is centralized.

</details>

---

## Tomorrow

Day 28–30: capstone. Pick one project, build it, ship it.
