# Day 23 — Traffic control: qdiscs, classes, fq_codel

> **Today's mission:** understand the egress qdisc, fix bufferbloat, see how `tc` is structured. Total time: ~75 minutes.

![qdiscs](diagrams/day23_qdisc.png)

## What a qdisc is

A queueing discipline. Sits between the IP layer and the driver. Decides:
- which packet goes next,
- when to drop,
- when to delay,
- how to spread among multiple flows.

Day 3 mentioned them; today we go deep.

## The default: fq_codel

Default since 4.12 (and a sensible default for almost all workloads). Combines:

- **SFQ (Stochastic Fair Queueing)**: per-flow buckets, round-robin between them. No flow can starve others.
- **CoDel (Controlled Delay)**: AQM that drops packets when queue latency exceeds a target (~5ms). Solves bufferbloat.

```bash
tc qdisc show dev eth0
# qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1518 target 5ms ce_threshold 4ms
```

## Bufferbloat

Big buffers + no drops = unbounded latency. `fq_codel` and friends prevent this by deliberately dropping early when latency rises.

Test:
```bash
# baseline
ping -c 10 8.8.8.8

# saturate uplink in another terminal:
iperf3 -c some-server -t 60 &

# ping again — note RTT explosion if your qdisc doesn't manage queue
ping -c 10 8.8.8.8

# install fq_codel if not there:
sudo tc qdisc replace dev eth0 root fq_codel

# rerun ping; should stay reasonable
```

## Hierarchical: HTB

```bash
sudo tc qdisc add dev eth0 root handle 1: htb default 30
sudo tc class add dev eth0 parent 1: classid 1:1 htb rate 100mbit
sudo tc class add dev eth0 parent 1:1 classid 1:10 htb rate 30mbit
sudo tc class add dev eth0 parent 1:1 classid 1:20 htb rate 50mbit
sudo tc class add dev eth0 parent 1:1 classid 1:30 htb rate 20mbit
sudo tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
    match ip dport 22 0xffff flowid 1:10
```

Now SSH gets up to 30Mbit, default traffic 20Mbit, etc.

## What to read in the kernel

- **`net/sched/sch_fq_codel.c`** — fq_codel.
- **`net/sched/sch_fq.c`** — fq (BBR-friendly pacing).
- **`net/sched/sch_htb.c`** — HTB.
- **`net/sched/sch_generic.c`** — qdisc_run, sch_direct_xmit.
- **`Documentation/networking/sch_*.rst`**.

## Bullet Points

- qdiscs sit between IP and driver; drop/delay/reorder packets.
- **fq_codel** is the modern default. Solves bufferbloat.
- **HTB/HFSC/cake** for hierarchical rate limits.
- **clsact** is a hook scaffold for tc-bpf, no queueing.
- Inspect with `tc -s qdisc show dev DEV`.

## Check question

You set `tc qdisc replace dev eth0 root pfifo_fast` and saturate uplink. SSH becomes unresponsive. Why?

.  
.  
.

**Answer:** pfifo_fast is drop-tail with three priority bands but no flow isolation and no AQM. Bulk transfer fills the buffer; SSH packets queue behind, waiting for the bulk to drain. Latency goes from ms to seconds. fq_codel solves both: per-flow isolation prevents bulk from starving SSH; CoDel-driven drops prevent latency runaway. Restore: `tc qdisc replace dev eth0 root fq_codel`.

## Tomorrow

Day 24: SO_REUSEPORT.
