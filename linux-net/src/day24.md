# Day 24 — SO_REUSEPORT and socket steering

> **Today's mission:** scale a server across cores by binding multiple sockets to the same port. Total time: ~60 minutes.

![SO_REUSEPORT](diagrams/day24_reuseport.png)

## The problem it solves

Single-threaded servers don't scale. Multi-threaded servers with one accepting socket suffer from contention on the accept queue. Pre-fork servers worked but were heavy.

`SO_REUSEPORT` (Linux 3.9, 2013) lets multiple sockets bind to the same `(IP, port)`. The kernel hashes incoming SYNs across them, distributing connections across worker processes/threads.

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
int opt = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
bind(sock, ...);
listen(sock, ...);
```

Each worker creates its own listening socket; all bind to `:80`; kernel deals.

## How the kernel picks

Default: `__inet_lookup_listener` finds the bind table entry, then `reuseport_select_sock` hashes the 4-tuple `(src_ip, src_port, dst_ip, dst_port)` modulo N reuseport sockets.

Same client always lands on the same worker → connection affinity.

## BPF-based steering

```c
setsockopt(sock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
```

A BPF program decides which reuseport socket gets each SYN. Use cases: shard by URL hash (HTTP), CPU affinity, custom load balancing. The BPF program type is `SK_REUSEPORT`.

## Today's experiment

```bash
# Trivial reuseport server (2 workers):
cat << 'EOF' > /tmp/srv.py
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(("0.0.0.0", 8080))
s.listen(64)
print(f"worker {os.getpid()} listening")
while True:
    c, _ = s.accept()
    c.send(f"from {os.getpid()}\n".encode())
    c.close()
EOF

python3 /tmp/srv.py &
python3 /tmp/srv.py &

# Hit it many times, see different PIDs respond:
for i in $(seq 1 10); do echo | nc -q 1 localhost 8080; done
```

You'll see the load split across the two PIDs.

## What to read in the kernel

- **`net/core/sock_reuseport.c`** — reuseport machinery.
- **`net/ipv4/inet_hashtables.c`** — `__inet_lookup_listener`.
- **`net/core/filter.c`** — `sk_reuseport_*` BPF helpers.

## Bullet Points

- `SO_REUSEPORT` lets multiple listeners share `(IP, port)`.
- Kernel hashes 4-tuple to pick a listener (deterministic per flow).
- **BPF program** can override the picker (`SO_ATTACH_REUSEPORT_EBPF`).
- Modern web servers (nginx, envoy) use it for multi-process scaling.
- Note: workers must check `SO_REUSEPORT` before bind, all from same UID (security).

## Check question

If a worker process exits, what happens to its in-flight SYNs that were already hashed to it?

<details>
<summary>Click to reveal answer</summary>

**Answer:** They're routed to the surviving workers via the kernel's reuseport group lookup at `__inet_lookup_listener` time. The hash function changes implicitly when a socket is removed from the group, so flows previously hitting the dead worker re-hash to a survivor. Connections that had completed `accept()` on the dead worker but weren't fully closed get an RST when the socket is closed (the dying process's FD table tear-down).

</details>

## Tomorrow

Day 25: kTLS.
