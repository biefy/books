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
/* near the top of scx_simple.bpf.c — which already #includes <scx/common.bpf.h> */
const volatile __u64 priority_cgroup_id = 0;   /* full kernfs id; set from userspace */

/* scx_bpf_task_cgroup(), bpf_cgroup_ancestor(), and bpf_cgroup_release() all
 * come from <scx/common.bpf.h> (scx_bpf_task_cgroup is a compat macro). Don't
 * re-declare them with your own `extern ... __ksym;` — that collides with the
 * header and fails to compile. Just call them, as scx_flatcg.bpf.c does. */

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

The hierarchy walk uses `bpf_cgroup_ancestor()` rather than a hand-rolled `cg = cg->parent` loop. There's a reason: `struct cgroup` has **no `parent` field** — the parent link lives at `cgrp->self.parent` as a `cgroup_subsys_state *`, not a `cgroup *`. Dereferencing a nonexistent `cg->parent` won't even compile against the real headers, and a manual pointer-chasing walk is hard to make the verifier accept. `bpf_cgroup_ancestor(cgrp, level)` is the idiomatic kfunc: it returns the ancestor at a given depth as an acquired reference (release it with `bpf_cgroup_release`). We drive it with `bpf_for(lvl, 0, owned->level + 1)` — the same pattern `scx_flatcg.bpf.c` uses. `bpf_for()` gives the verifier a provable iteration bound even though the limit (`owned->level`) is a runtime value read from memory; a plain `for` comparing against `owned->level` would be rejected. You don't need to add any include for it: `<scx/common.bpf.h>` (already included by `scx_simple.bpf.c`) pulls `bpf_for` in transitively — exactly as `scx_flatcg.bpf.c` uses it with no `bpf_experimental.h` include. (Adding `#include <bpf/bpf_experimental.h>` yourself actually breaks the scx build: that header isn't on the sched_ext include path and clang fails with `'bpf/bpf_experimental.h' file not found`.)

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

**Confirm the printed id is NON-ZERO** — it should look like:

```
priority cgroup id = 12046204
```

If it prints `0`, `name_to_handle_at()` failed (wrong path, or the directory isn't on cgroup2). Verify `/sys/fs/cgroup/priority` exists and `mount | grep cgroup2` lists `/sys/fs/cgroup`. A `0` here silently disables the entire feature, because the BPF side gates everything behind `if (priority_cgroup_id)` — you'd see no scheduling effect and be unable to tell "my change didn't help" from "the code never ran." To fail loudly instead, add before `scx_simple__attach()`:

```c
if (skel->rodata->priority_cgroup_id == 0) {
    fprintf(stderr, "FATAL: could not read priority cgroup id; "
                    "create /sys/fs/cgroup/priority first\n");
    return 1;
}
```

### Build and run

**Prerequisites.** This step needs three non-default tools — install them first:

```bash
sudo apt-get install -y stress-ng sysbench   # load generator + CPU benchmark
```

(It also assumes the kernel built at `~/code/linux` with sched_ext enabled, established on earlier days.)

```bash
cd ~/code/linux/tools/sched_ext
make
sudo ./scx_simple &

# The "Setting up" section moved THIS shell into /priority. Move it back to the
# root cgroup first, so the heavy load below inherits root (NOT /priority) —
# otherwise BOTH the load and the benchmark run in /priority and there is no
# contrast to observe.
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs

# Heavy load (root cgroup, NOT /priority):
stress-ng --cpu 8 --timeout 60 &

# Prove the split before benchmarking:
cat /proc/$(pgrep -n stress-ng)/cgroup    # expect 0::/   (stress-ng in root)
cat /proc/$$/cgroup                        # expect 0::/   (shell still in root)

# NOW move this shell into the priority cgroup and run the benchmark:
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
cat /proc/$$/cgroup                        # expect 0::/priority
sysbench --threads=1 --cpu-max-prime=20000 cpu run

# Compare to running WITHOUT the priority modification (revert and re-test).
```

The two `cat /proc/.../cgroup` lines are the contrast check: the load shows `0::/` while the benchmark shell shows `0::/priority`. Your sysbench in the priority cgroup should complete faster than baseline despite the competing stress-ng.

### Measure

Measure throughput directly — run the same benchmark once from inside `/priority` and once from the root cgroup, both while `stress-ng` loads the box, and compare the `events per second` lines. (Don't wrap it in `schedtool -p N`: that sets a real-time policy, which moves the task OUT of the sched_ext class entirely, so it would no longer exercise your cgroup-priority logic.)

```bash
stress-ng --cpu 8 --timeout 60 &

# Run A — inside the priority cgroup:
echo $$ | sudo tee /sys/fs/cgroup/priority/cgroup.procs
sysbench --threads=8 --cpu-max-prime=20000 cpu run | grep -E 'events per second|total time'

# Run B — back in the root cgroup:
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs
sysbench --threads=8 --cpu-max-prime=20000 cpu run | grep -E 'events per second|total time'
```

Under contention, Run A (in `/priority`) should report a noticeably higher `events per second` than Run B. Cross-check with the per-cgroup CPU accounting:

```bash
cat /sys/fs/cgroup/priority/cpu.stat
cat /sys/fs/cgroup/cpu.stat
```

Compare the `usage_usec` fields — `/priority` should have accumulated more CPU time:

```
usage_usec 20946205000
user_usec 16795163000
system_usec 4151042000
...
```

With the priority modification, the priority cgroup gets noticeably more CPU under contention; without it the two runs should be roughly equal.

## What to break, in order

### Walk the cgroup hierarchy correctly

If your priority cgroup contains *child* cgroups (e.g., `/priority/work` and `/priority/play`), tasks in those children should also count. The `bpf_cgroup_ancestor` walk above handles this — it checks every ancestor from the task's own cgroup up to the root, so a match at the `/priority` level still triggers for tasks nested below it.

**To *verify* it triggers, give the matched branch a direct observable.** Throughput alone is too noisy to confirm a nested match. Add a `bpf_printk` inside the matched-ancestor branch in `simple_enqueue`, right before the `break`:

```c
if (anc->kn->id == priority_cgroup_id) {
    vtime -= 1000000;
    slice *= 2;
    bpf_printk("prio match: comm=%s\n", p->comm);   /* observe the hit */
    bpf_cgroup_release(anc);
    break;
}
```

Then create the child cgroup, run a task in it, and watch the trace:

```bash
sudo mkdir -p /sys/fs/cgroup/priority/work
echo $$ | sudo tee /sys/fs/cgroup/priority/work/cgroup.procs
sudo cat /sys/kernel/debug/tracing/trace_pipe &
sysbench --threads=1 --cpu-max-prime=20000 cpu run
```

Expect `trace_pipe` to print a line like `prio match: comm=sysbench` for the task spawned in `/priority/work`, confirming the ancestor walk matched at the parent (`/priority`) level for the nested task. (`p->comm` is the right field for the task name.) If you'd rather not print on the hot path, increment a file-scope counter — `u64 prio_hits = 0;` then `prio_hits++;` in the branch — and read it with `sudo bpftool map dump name scx_simp.bss`; the count should climb once the nested task is enqueued.

### Negative vtime

```c
vtime -= 1000000000;     /* huge decrement */
```

Decrementing by a large value can underflow `u64`. The vtime is a u64; signed math doesn't apply. Symptom: tasks in the priority cgroup get insanely-low vtime, scheduled forever to the exclusion of others; watchdog ejects after 30s.

**To confirm the watchdog actually fired** (rather than the box just being slow), watch two things. The backgrounded `scx_simple` process exits on its own and prints an exit reason to its terminal. On the kernel side, run this in another terminal to catch the disable message:

```bash
sudo dmesg -w | grep sched_ext
```

Within ~30s of the stall you'll see a line of the form:

```
sched_ext: BPF scheduler "simple" disabled (runnable task stall ...)
```

The exact reason text varies by kernel version (a non-stall fault shows `(runtime error)` instead), but the `BPF scheduler "..." disabled` shape is constant. If `scx_simple` is still running and no such line appears, the watchdog has *not* ejected — the box is just slow.

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
    /* This snippet REPLACES the stock simple_init, so it must still create
     * SHARED_DSQ. SHARED_DSQ (#defined as 0 in scx_simple.bpf.c) is a
     * user-created DSQ — id 0 routes through find_user_dsq, not a built-in
     * global DSQ — so inserting into it without creating it first triggers a
     * scx_bpf_error and the scheduler is ejected on the first non-priority
     * enqueue. Create both. */
    s32 ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
    if (ret)
        return ret;
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
