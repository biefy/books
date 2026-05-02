# Day 30 — Capstone: trace one packet end to end

> **Mission:** pick one real packet from your system. Trace it through every kernel layer. Write up what you saw. ~3-4 hours total.

## The exercise

Capture one packet (TCP request, TCP response, UDP, ICMP — your choice). Trace its path through the kernel from:

1. NIC RX (or socket TX, if outbound).
2. NAPI poll / sendmsg.
3. GRO (RX) / GSO (TX).
4. eth_type_trans / IP header build.
5. ip_rcv / ip_queue_xmit.
6. Netfilter PRE_ROUTING / POST_ROUTING.
7. Routing decision.
8. Conntrack.
9. tc/qdisc.
10. Socket layer.
11. Application.

![packet path overview](diagrams/day30_capstone.png)

The deliverable is a one-page document showing each stage with:
- The kernel function that runs.
- The data structure(s) involved.
- The cost (CPU time) you measured.

## Tools at your disposal

- **`trace-cmd`** with `function_graph` for the full call tree.
- **`perf trace`** for event-level visibility.
- **`bpftrace`** one-liners for targeted measurements.
- **`tcpdump`** for the wire-level view.
- **`ss -tipsm`** for socket-level state.
- **`/proc/net/*`**, `/proc/sys/net/*`.

## A specific suggested experiment

```bash
# 1. Pick a fresh TCP connection
nc -l 9999 &

# 2. Start a wide trace
sudo trace-cmd record -p function_graph \
    -g netif_receive_skb \
    -g tcp_sendmsg \
    -e net:* \
    -e tcp:* \
    -e skb:kfree_skb \
    sleep 10

# 3. In another terminal, send one packet:
echo "hello" | nc -q 1 localhost 9999

# 4. Stop record, analyze:
sudo trace-cmd report > /tmp/packet_trace.txt
head -100 /tmp/packet_trace.txt
```

Annotate the trace with what each line is doing. That annotated trace is your capstone.

## What's not covered

In 30 days you skipped over:
- **rxrpc** (AFS-style transport).
- **SCTP** (rare, but interesting).
- **DCCP** (mostly historical).
- **RDS, Tipc, Sun RPC** — niche.
- **Bluetooth** (`net/bluetooth/`).
- **CAN bus** (`net/can/`).
- **NFC** (`net/nfc/`).
- **L2TP, PPP, X.25, etc.** — legacy.

If your work touches one of these, you can apply the same methodology — read source, trace with tools, observe — to learn it.

## After Day 30

Real fluency comes from working on the stack, not just reading it. Pick one of:

- **Submit a fix.** Look at the netdev mailing list, find a `Reported-by` you can verify, propose a fix.
- **Write a tool.** Use the BPF skills (the BPF plan, if you take it after this) to build a tracer for something you want to know.
- **Optimize a workload.** Take a real perf problem you face — high latency, drops, packet reordering — and use what you learned to diagnose and fix.

Welcome to the kernel networking community.
