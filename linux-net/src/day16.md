# Day 16 — TCP congestion control: CUBIC, BBR, the framework

> **Today's mission:** swap CC algorithms on a connection, observe the difference. Total time: ~75 minutes.

## What CC is, in one paragraph

Every TCP connection has a **congestion window** (cwnd) limiting how much data can be in flight before an ACK. The CC algorithm decides how cwnd grows on success and shrinks on loss. Different algorithms target different goals: throughput (CUBIC), delay (BBR), datacenter-aware (DCTCP), etc.

## The framework

![CC framework](diagrams/day16_cc.png)

`struct tcp_congestion_ops` is the vtable each algorithm implements. Defined in `include/net/tcp.h`. Each algorithm's `init`, `ssthresh`, `cong_avoid`, etc. functions get called at the right TCP events.

Algorithms register at module load via `tcp_register_congestion_control`. List them:

```bash
sysctl net.ipv4.tcp_available_congestion_control
# reno cubic bbr bbr2 dctcp ...
```

## Switch CC

System-wide:
```bash
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
```

Per-connection:
```c
setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 3);
```

Per-route:
```bash
sudo ip route change 10.0.0.0/24 via 192.168.1.1 congctl bbr
```

## Today's experiment

```bash
# Run iperf3 with CUBIC vs BBR:
iperf3 -s &
iperf3 -c 127.0.0.1 -C cubic -t 30
iperf3 -c 127.0.0.1 -C bbr -t 30

# Trace cwnd growth:
sudo bpftrace -e '
kprobe:tcp_write_xmit {
  $tp = (struct tcp_sock *)arg0;
  @cwnd = lhist($tp->snd_cwnd, 0, 1000, 50);
}
interval:s:10 { exit }'
```

You'll see different cwnd distributions per algorithm.

## What to read in the kernel

- **`include/net/tcp.h`** — `struct tcp_congestion_ops`.
- **`net/ipv4/tcp_cong.c`** — registration framework.
- **`net/ipv4/tcp_cubic.c`** — CUBIC (default for many years).
- **`net/ipv4/tcp_bbr.c`** — BBR.
- **`Documentation/networking/cc-algorithms.rst`** — guide.

## Bullet Points

- TCP CC is a kernel framework with multiple plug-in algorithms.
- Switch via sysctl, sockopt, or per-route.
- **CUBIC** — loss-based, aggressive growth on success.
- **BBR** — delay-based, models bottleneck bandwidth.
- **DCTCP** — datacenter, ECN-based.
- Each algorithm is a kernel module. Add new ones without rebuilding the kernel.

## Check question

Why doesn't the kernel just always use BBR (since it's newer)?

<details>
<summary>Click to reveal answer</summary>

**Answer:** BBR is delay-based — it estimates path bandwidth and RTT and paces accordingly. On networks where the bottleneck is at a buffer that's also serving other CUBIC flows, BBR is unfriendly: it underestimates the real BDP, takes more share than fairness would give, and can starve CUBIC neighbors. Use BBR when *all* flows on the path are BBR-aware (modern public clouds), or for explicit pacing-friendly use cases. CUBIC remains the default because it's been validated across the public internet for two decades.

</details>

## Tomorrow

Day 17: TCP retransmission and recovery.
