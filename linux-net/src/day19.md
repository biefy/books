# Day 19 — epoll and io_uring for sockets

> **Today's mission:** understand how userspace efficiently waits on many sockets. Total time: ~75 minutes.

![epoll vs io_uring](diagrams/day19_epoll_iouring.png)

## epoll (the workhorse)

```c
int epfd = epoll_create1(0);

struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = sock };
epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

struct epoll_event events[64];
int n = epoll_wait(epfd, events, 64, 100);
```

Levels:
- **Level-triggered (LT)**: notifies as long as the FD is ready. Default. Easy to use.
- **Edge-triggered (ET)**: notifies once when state changes. Faster but you must drain to EAGAIN.

`EPOLLEXCLUSIVE`: when multiple workers wait on the same FD, only one gets woken per event. Eliminates thundering herd.

Source: `fs/eventpoll.c`. The implementation uses an RB-tree for the FD set and a ready list for notifications.

## io_uring

Submit operations as SQEs (Submission Queue Entries); kernel reports completions via CQEs.

```c
struct io_uring ring;
io_uring_queue_init(256, &ring, 0);

struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sock, buf, sizeof(buf), 0);
io_uring_submit(&ring);

struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);
// cqe->res = bytes received
io_uring_cqe_seen(&ring, cqe);
```

For sockets specifically: `IORING_OP_RECV/SEND`, `RECVMSG/SENDMSG`, `ACCEPT`, `CONNECT`, **`RECVMSG_MULTISHOT`** (5.18+, single submission, many completions).

**Zero-copy variants**: `IORING_OP_SEND_ZC` / `SENDMSG_ZC` — kernel pins user pages and DMAs without copying.

Source: `io_uring/`. Read `io_uring/net.c` for socket ops.

## Today's experiment

```bash
# epoll wakeup tracking:
sudo bpftrace -e '
fentry:eventpoll_*  { @[func] = count(); }
interval:s:5 { print(@); clear(@) }'

# Try with a busy server:
nginx &
ab -n 10000 -c 100 http://127.0.0.1/
```

Try a small io_uring example using `liburing`:

```bash
sudo apt install liburing-dev
# Use one of the examples from /usr/share/doc/liburing/examples
```

## What to read in the kernel

- **`fs/eventpoll.c`** — epoll implementation.
- **`io_uring/io_uring.c`** — io_uring main.
- **`io_uring/net.c`** — socket-specific ops.
- **`Documentation/networking/io_uring.rst`** — official guide.

## Bullet Points

- **epoll** = O(1) registration + O(events) wait. LT default; ET for high-perf. EPOLLEXCLUSIVE avoids thundering herd.
- **io_uring** = batched submit/complete; supports multishot recv (one submission, many completions).
- **Zero-copy** is io_uring-specific (`IORING_OP_SEND_ZC`).
- For most servers in 2026, epoll is still fine. io_uring shines at very high throughput / batch-heavy workloads.

## Check question

Why is `EPOLLEXCLUSIVE` important for accepting connections in a multi-worker server?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Without it, when a SYN arrives at a listening socket, all N workers waiting on that socket via epoll get woken; N-1 immediately call `accept` and return EAGAIN; only one succeeds. That's "thundering herd" — wasted wakeups, scheduling churn. `EPOLLEXCLUSIVE` (added 4.5) tells the kernel to wake only one waiter per event. Linux's `SO_REUSEPORT` (Day 24) is a more powerful alternative — multiple sockets sharing the listening port, kernel hashes incoming SYNs across them deterministically.

</details>

## End of Phase 3

You can now read the L4 stack: socket lifecycles, UDP, TCP states + CC + retrans, sockopts, the modern wait APIs.

Phase 4 (Days 20–26) goes into the kernel's network subsystems: netfilter, conntrack, traffic control, kTLS, MPTCP.
