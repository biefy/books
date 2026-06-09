# Day 26 — Modify scx_simple: priority for one cgroup

> **Today's mission:** make a custom variant of `scx_simple` that gives scheduling priority to tasks in a chosen cgroup. Watch a workload in that cgroup get preferential treatment under load. Total time: ~75 minutes.

## Why this exercise

Yesterday you ran a stranger's BPF scheduler. Today you change one and observe the effect. This is the most important sched_ext skill: **small, surgical modifications to a working scheduler**.

The goal is to get comfortable with the iteration loop:

1. Edit one callback.
2. Compile, load.
3. Generate a workload.
4. Observe the effect with measurements.
5. Tune; iterate.

Today's specific modification: tasks in `/sys/fs/cgroup/priority` get a 2× time slice and lower vtime (so they run earlier). Tasks elsewhere use the default.

## Setting up the priority cgroup

```bash
sudo mkdir /sys/fs/cgroup/priority
stat -c %i /sys/fs/cgroup/priority     # cgroup's kernfs inode — part of the ID we'll match against

# Put a shell into it (subprocess inheritance)
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
echo $$    # this shell now lives in /priority
```

Anything spawned from this shell will be in `/priority` until you move it back.

## The modification

Two files to change: `tools/sched_ext/scx_simple.bpf.c` and the userspace driver `tools/sched_ext/scx_simple.c`.

### BPF side: read a config variable, branch on cgroup

```c
/* near the top of scx_simple.bpf.c */
const volatile __u64 priority_cgroup_id = 0;   /* full kernfs id; set from userspace */

extern struct cgroup *scx_bpf_task_cgroup(struct task_struct *p) __ksym;
extern struct cgroup *bpf_cgroup_ancestor(struct cgroup *cgrp, int level) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 vtime = p->scx.dsq_vtime;
    u64 slice = SCX_SLICE_DFL;

    /* Walk up the cgroup hierarchy looking for the priority cgroup.
     * bpf_cgroup_ancestor(cgrp, level) returns the ancestor at the given
     * level (0 = root), as an ACQUIRED reference we must release. We iterate
     * with bpf_for(), the same idiom scx_flatcg uses: it gives the verifier a
     * provable bound on a runtime limit (owned->level), which an ordinary
     * `for` on a memory-read value would not. */
    if (priority_cgroup_id) {
        struct cgroup *owned = scx_bpf_task_cgroup(p);
        if (owned) {
            int lvl;
            bpf_for(lvl, 0, owned->level + 1) {
                struct cgroup *anc = bpf_cgroup_ancestor(owned, lvl);
                if (!anc)
                    continue;
                if (anc->kn->id == priority_cgroup_id) {
                    vtime -= 1000000;   /* push 1 ms earlier in queue */
                    slice *= 2;          /* longer time slice */
                    bpf_cgroup_release(anc);
                    break;
                }
                bpf_cgroup_release(anc);
            }
            bpf_cgroup_release(owned);
        }
    }

    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}
```

Two effects:
- **Lower vtime** = pushed earlier in the vtime-ordered DSQ; runs sooner.
- **Longer slice** = more CPU time per scheduling round before being preempted.

The hierarchy walk uses `bpf_cgroup_ancestor()` rather than a hand-rolled `cg = cg->parent` loop. There's a reason: `struct cgroup` has **no `parent` field** — the parent link lives at `cgrp->self.parent` as a `cgroup_subsys_state *`, not a `cgroup *`. Dereferencing a nonexistent `cg->parent` won't even compile against the real headers, and a manual pointer-chasing walk is hard to make the verifier accept. `bpf_cgroup_ancestor(cgrp, level)` is the idiomatic kfunc: it returns the ancestor at a given depth as an acquired reference (release it with `bpf_cgroup_release`). We drive it with `bpf_for(lvl, 0, owned->level + 1)` — the same pattern `scx_flatcg.bpf.c` uses. `bpf_for()` (from `bpf_experimental.h`) gives the verifier a provable iteration bound even though the limit (`owned->level`) is a runtime value read from memory; a plain `for` comparing against `owned->level` would be rejected.

### Userspace side: pass the cgroup ID

In `scx_simple.c`, before `scx_simple__attach()`:

```c
#include <fcntl.h>
#include <sys/stat.h>

/* The BPF side matches against cgrp->kn->id, the full 64-bit kernfs id:
 * (generation << 32) | inode. stat()'s st_ino only gives the low 32 bits,
 * so it MISMATCHES whenever the kernfs generation/high bits are nonzero.
 * Use name_to_handle_at(), whose file handle for a cgroupfs path encodes
 * exactly that 64-bit id. */
__u64 read_cgroup_id(const char *path) {
    struct {
        struct file_handle fh;
        __u64 id;
    } h = { .fh = { .handle_bytes = sizeof(__u64) } };
    int mount_id;

    if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) < 0)
        return 0;
    return h.id;
}

skel->rodata->priority_cgroup_id = read_cgroup_id("/sys/fs/cgroup/priority");
fprintf(stderr, "priority cgroup id = %llu\n", skel->rodata->priority_cgroup_id);
```

(`rodata->priority_cgroup_id` is the userspace handle for the BPF program's `const volatile __u64 priority_cgroup_id` — settable before load, read-only after.)

### Build and run

```bash
cd ~/code/linux/tools/sched_ext
make
sudo ./scx_simple &

# Heavy load (no cgroup membership):
stress-ng --cpu 8 --timeout 60 &

# In the priority cgroup, run a benchmark:
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
sysbench --threads=1 --cpu-max-prime=20000 cpu run

# Compare to running WITHOUT the priority modification (revert and re-test).
```

Your sysbench in the priority cgroup should complete faster than baseline despite the competing stress-ng.

### Measure

```bash
# Latency / fairness measurement
schedtool -p 0 -- sysbench --threads=8 --cpu-max-prime=20000 cpu run

# Per-cgroup CPU usage
cat /sys/fs/cgroup/priority/cpu.stat
cat /sys/fs/cgroup/cpu.stat
```

Compute the throughput ratio. With the priority modification, the priority cgroup should get noticeably more CPU under contention.

## What to break, in order

### Walk the cgroup hierarchy correctly

If your priority cgroup contains *child* cgroups (e.g., `/priority/work` and `/priority/play`), tasks in those children should also count. The `bpf_cgroup_ancestor` walk above handles this — it checks every ancestor from the task's own cgroup up to the root, so a match at the `/priority` level still triggers for tasks nested below it. **Test with a child cgroup**: create `/priority/work`, put a task there, verify the priority logic still triggers.

### Negative vtime

```c
vtime -= 1000000000;     /* huge decrement */
```

Decrementing by a large value can underflow `u64`. The vtime is a u64; signed math doesn't apply. Symptom: tasks in the priority cgroup get insanely-low vtime, scheduled forever to the exclusion of others; watchdog ejects after 30s.

Bound your decrement to reasonable values, or use a separate priority queue. (See "alternative: per-cgroup DSQs" below.)

### Don't break the watchdog

Make sure even priority tasks get dispatched promptly. Don't, e.g., refuse to enqueue them. Don't loop in dispatch waiting for "the right" task. The watchdog catches stalls regardless of *why* they happened.

### Per-cgroup DSQ — a cleaner alternative

Instead of vtime tricks, give the priority cgroup its own DSQ that you consume from first:

```c
#define PRIO_DSQ 1ULL

/* init creates a DSQ, and scx_bpf_create_dsq is a sleepable kfunc, so the
 * callback MUST use BPF_STRUCT_OPS_SLEEPABLE — a plain BPF_STRUCT_OPS init
 * won't load. */
s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    return scx_bpf_create_dsq(PRIO_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    u64 vtime = p->scx.dsq_vtime;
    bool priority = false;

    if (priority_cgroup_id) {
        struct cgroup *owned = scx_bpf_task_cgroup(p);
        if (owned) {
            int lvl;
            bpf_for(lvl, 0, owned->level + 1) {
                struct cgroup *anc = bpf_cgroup_ancestor(owned, lvl);
                if (!anc)
                    continue;
                if (anc->kn->id == priority_cgroup_id)
                    priority = true;
                bpf_cgroup_release(anc);
                if (priority)
                    break;
            }
            bpf_cgroup_release(owned);
        }
    }

    if (priority)
        scx_bpf_dsq_insert(p, PRIO_DSQ, SCX_SLICE_DFL, enq_flags);
    else
        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Priority queue first */
    if (scx_bpf_dsq_move_to_local(PRIO_DSQ, 0)) return;
    /* Fall back to default queue */
    scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}
```

This is more deterministic than vtime tricks. Closer to how production schedulers work — strict priority lanes plus a default lane.

## What to read in the kernel

- **`kernel/sched/ext.c`** — search `scx_bpf_dsq_insert` and `scx_bpf_dsq_move_to_local` to see how DSQ ops bind to internals. The functions are kfuncs registered for `BPF_PROG_TYPE_STRUCT_OPS` with sched_ext-specific properties.

- **`kernel/sched/ext.c`** — search `scx_bpf_task_cgroup`. The kfunc that returns a task's cgroup pointer.

- **`tools/sched_ext/scx_central.bpf.c`** — production-grade example with multi-DSQ. Read after today's exercise.

- **`tools/sched_ext/scx_flatcg.bpf.c`** — cgroup-aware scheduler. Read this if you're interested in how production sched_ext schedulers handle cgroups at scale.

- **`include/linux/cgroup-defs.h`** — `struct cgroup` definition. Note that there is **no `parent` field**; the parent is `cgrp->self.parent` (a `cgroup_subsys_state *`). The fields you commonly deref from BPF are `cgrp->kn->id` (the full 64-bit kernfs id) and `cgrp->level`.

- **`Documentation/scheduler/sched-ext.rst`** — particularly the section on cgroup integration.

## Bullet Points

- Modifying a sched_ext example is the fastest way to learn the API in depth.
- **`scx_bpf_task_cgroup(p)`** returns an acquired cgroup reference; walk ancestors with **`bpf_cgroup_ancestor(cgrp, level)`** (each returns an acquired ref), then release every ref with `bpf_cgroup_release()`. `struct cgroup` has no `parent` field, so don't hand-roll a `cg->parent` walk.
- **Match on the full 64-bit `cgrp->kn->id`** — `st_ino` alone is only the low 32 bits and mismatches when the kernfs generation bits are set; read the id with `name_to_handle_at()` in userspace.
- An init callback that calls a sleepable kfunc like `scx_bpf_create_dsq` must be **`BPF_STRUCT_OPS_SLEEPABLE`**, not plain `BPF_STRUCT_OPS`.
- **Vtime tricks** (decrement to push earlier) work but are fragile.
- **Per-cgroup DSQs** are cleaner: separate priority lane consumed first.
- The watchdog catches mistakes — develop with confidence.
- Test under realistic load (`stress-ng` + benchmarks), not just synthetic timings.

## Check question

If your priority cgroup gets *too much* CPU (starves other tasks for >30s), what happens?

<details>
<summary>Click to reveal answer</summary>

**Answer:** **The watchdog ejects your scheduler.** Other tasks have been runnable but undispatched (because you kept favoring priority tasks). The 30-second watchdog detects this and reverts to CFS. Fairness is restored automatically; the priority logic is gone until you reload.

The watchdog enforces a **minimum service guarantee**: no matter how clever your prioritization policy, every runnable task on the system must be dispatched within 30 seconds. If your policy can't meet that, your scheduler is rejected.

This is good. It means you can experiment aggressively — try aggressive prioritization, see the watchdog kick in, refine. The recovery loop is short. In production schedulers (`scx_layered`, `scx_lavd`), aging logic explicitly bounds how long any task can wait, ensuring the watchdog never fires; that aging code is what distinguishes a "tested example" from a production scheduler.

</details>

---

## Tomorrow

Day 27: read `scx_central` — production-grade BPF scheduler with central-dispatch architecture.
