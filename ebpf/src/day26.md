# Day 26 — Modify scx_simple: priority for one cgroup

> **Today's mission:** make a custom variant of `scx_simple` that gives priority to tasks in a chosen cgroup. Watch a workload in that cgroup get scheduled preferentially. Total time: ~75 minutes.

## Why this exercise

Yesterday you ran a stranger's BPF scheduler. Today you change one and observe the effect. This is the most important sched_ext skill: small, surgical modifications.

Goal: tasks in `/sys/fs/cgroup/priority` get a 2x time slice and lower vtime (so they run earlier).

## What we'll change

`scx_simple.bpf.c` already uses `vtime`-ordered dispatch — earlier vtime = sooner run. We add:

1. Detect if the task's cgroup contains a marker (e.g., a configured cgroup ID).
2. If yes, decrement vtime (push earlier in queue).
3. Pass a longer slice on dispatch.

## The lab

### Pick a cgroup

```bash
sudo mkdir /sys/fs/cgroup/priority
cat /sys/fs/cgroup/priority/cgroup.id    # note this number
# put a shell into it:
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
```

### Modify `scx_simple.bpf.c`

```c
/* Make the priority cgroup ID configurable from userspace */
const volatile __u64 priority_cgroup_id = 0;

SEC("struct_ops/simple_enqueue")
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 vtime = p->scx.dsq_vtime;
    u64 slice = SCX_SLICE_DFL;

    /* Walk up the cgroup hierarchy looking for the priority cg */
    if (priority_cgroup_id) {
        struct cgroup *cg = scx_bpf_task_cgroup(p);
        if (cg && cg->kn->id == priority_cgroup_id) {
            vtime -= 1000000;  /* push earlier */
            slice *= 2;        /* longer slice */
        }
    }

    scx_bpf_dispatch_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}
```

Userspace `scx_simple.c`:

```c
/* before attach: */
skel->rodata->priority_cgroup_id = read_cgroup_id("/sys/fs/cgroup/priority");
```

### Run and measure

```bash
sudo ./scx_priority &

# Heavy load (in normal cgroup):
stress-ng --cpu 8 --timeout 30 &

# In the priority cgroup, run a benchmark:
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
sysbench --threads=1 --cpu-max-prime=20000 cpu run
```

Compare with stock `scx_simple`. Your priority cgroup's sysbench should complete faster despite the competing stress-ng load.

---

## What to break, in order

### Break 1 — Walk the cgroup hierarchy

Tasks may be in *child* cgroups of `/priority`. Walk up:

```c
struct cgroup *cg = scx_bpf_task_cgroup(p);
while (cg) {
    if (cg->kn->id == priority_cgroup_id) { /* match */ break; }
    cg = cg->parent;
    /* careful: bounded walk for verifier */
}
```

The verifier requires bounded loops; cap at, say, 8 levels. Most cgroup hierarchies are shallow.

### Break 2 — Negative vtime

Decrementing vtime by a large value can underflow. The vtime is a u64; signed math doesn't apply. Bound your decrement to reasonable values, or use a separate priority queue.

### Break 3 — Don't break the watchdog

Make sure even priority tasks get dispatched promptly. Don't, e.g., refuse to enqueue them. Watchdog will eject your scheduler.

### Break 4 — Per-cgroup DSQ

Instead of vtime tricks, give the priority cgroup its own DSQ that you consume from first:

```c
scx_bpf_create_dsq(PRIO_DSQ, -1);

/* enqueue: */
if (priority) scx_bpf_dispatch(p, PRIO_DSQ, slice, enq_flags);
else          scx_bpf_dispatch(p, SHARED_DSQ, slice, enq_flags);

/* dispatch: */
if (scx_bpf_consume(PRIO_DSQ)) return;
scx_bpf_consume(SHARED_DSQ);
```

This is more deterministic than vtime tricks. Closer to how production schedulers work.

---

## What to read in the kernel

- **`kernel/sched/ext.c`** — search `scx_bpf_dispatch` and `scx_bpf_consume` to see how DSQ ops bind to internals.
- **`tools/sched_ext/scx_central.bpf.c`** — production-grade example with multi-DSQ.
- **`tools/sched_ext/scx_flatcg.bpf.c`** — cgroup-aware scheduler. Read after today.

---

## Bullet Points

- Modifying a sched_ext example is the fastest way to learn the API.
- **Vtime tricks** (decrement to push earlier) work but are fragile.
- **Per-cgroup DSQs** are cleaner: separate queue per priority class.
- The watchdog catches mistakes — develop in confidence.
- Test under realistic load, not just stress-ng — interactivity matters.

---

## Check question

If your priority cgroup gets too much CPU (starves other tasks for >30s), what happens?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Watchdog ejects your scheduler. Other tasks have been runnable but undispatched (because you kept favoring priority tasks). System reverts to CFS, fairness restored. The watchdog enforces a minimum service guarantee: no matter how clever your policy, every runnable task must dispatch within 30 seconds.

</details>

---

## Tomorrow

Day 27: read `scx_central` — production-grade BPF scheduler with multiple DSQs, per-CPU patterns, and central-dispatch architecture.
