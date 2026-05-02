# Day 13 — The socket layer: `struct sock`

> **Today's mission:** understand the kernel side of `socket()`, `bind()`, `listen()`, `connect()`. See how `struct sock` sits underneath every networking syscall. Total time: ~75 minutes.

> **Phase 3 starts here.** Days 13–19 cover L4: sockets, UDP, TCP state machine, congestion control, retransmission, sockopts, epoll/io_uring.

## What `struct sock` is

A polymorphic descriptor for "any socket." Every protocol's specific socket type embeds it as the first field:

![struct sock](diagrams/day13_sock.png)

```c
struct inet_sock { struct sock sk; ... };
struct inet_connection_sock { struct inet_sock icsk_inet; ... };
struct tcp_sock { struct inet_connection_sock inet_conn; ... };
struct udp_sock { struct inet_sock inet; ... };
```

Cast helpers (`tcp_sk(sk)`, `udp_sk(sk)`, `inet_sk(sk)`) walk the embeddings. Polymorphism via `sk->sk_prot` (function pointer table per protocol).

## Lifecycle

![socket lifecycle](diagrams/day13_socket_lifecycle.png)

`socket(AF_INET, SOCK_STREAM, 0)`:
1. `sock_alloc` allocates a `struct socket` (the kernel's wrapper that ties FD ↔ sk).
2. `inet_create` populates fields, allocates a `tcp_sock`.
3. `tcp_init_sock` sets TCP-specific state.

`bind`: `inet_bind` → `inet_csk_get_port` reserves the port in `inet_listen_hashinfo`.

`listen`: marks the sock as accepting; new connections get queued.

`accept`: pops a completed connection from the accept queue; returns a new `sock`.

`connect`: builds a SYN, sends it, transitions to SYN_SENT, etc.

## Today's experiment

```bash
# Inspect socket state
ss -tan

# Per-socket TCP info
ss -ti     # rtt, cwnd, retrans, etc.
ss -tim    # plus memory accounting

# Find which kernel struct backs a socket
sudo bpftrace -e 'fentry:tcp_init_sock { printf("init_sock %p\n", args->sk); }' &
nc -l 9999 &
sudo killall bpftrace
```

## What to read in the kernel

- **`include/net/sock.h`** — `struct sock`. Field by field.
- **`include/net/inet_sock.h`** — `struct inet_sock`.
- **`net/socket.c`** — `socket`, `bind`, `connect` syscall handlers.
- **`net/ipv4/af_inet.c`** — `inet_create`, `inet_bind`, the AF_INET protocol family.
- **`net/ipv4/tcp.c`** — `tcp_init_sock`.

## Bullet Points

- All sockets descend from `struct sock`; specialized types embed it as first field.
- Polymorphism via `sk->sk_prot` — function pointer table per protocol.
- Bind tables (`inet_listen_hashinfo`, `inet_ehash`) are **per-netns**.
- Per-socket queues: `sk_receive_queue` (ingress), `sk_write_queue` (egress).

## Check question

Why do `struct tcp_sock` and `struct udp_sock` both embed `struct inet_sock` as their first field, rather than just `struct sock`?

.  
.  
.

**Answer:** `inet_sock` adds IPv4/IPv6-common fields (rcv_saddr, daddr, sport, dport, ttl, etc.) that any IP-based protocol needs. By inheriting from `inet_sock`, TCP and UDP both share these fields without duplication. UNIX sockets (`struct unix_sock`) skip `inet_sock` and embed `sock` directly because they don't have IP semantics.

## Tomorrow

Day 14: UDP — the simpler protocol.
