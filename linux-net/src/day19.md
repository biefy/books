# Day 19 — epoll and io_uring for sockets

> **Today's mission:** understand how userspace efficiently waits on many sockets, and why io_uring is taking over from epoll for the highest-throughput servers. Total time: ~75 minutes.

## The problem they solve

A naive blocking server handles one client at a time. To handle many, you can:

1. **Fork a process per client** (Apache prefork, ~early-2000s style). Heavy.
2. **Spawn a thread per client** (1:1 threading). Lighter than processes but still ~MB per client and lots of context switches.
3. **Use one thread for many clients with non-blocking I/O.** Read/write only when ready; never block on individual sockets. *Now you need to know which socket is ready.*

That last bullet is what `epoll` and `io_uring` solve — but with totally different mechanics.

![epoll vs io_uring](diagrams/day19_epoll_iouring.png)

## epoll — the readiness model

The mental model: *"Tell me when this FD is ready for I/O. I'll do the syscall myself."*

```c
int epfd = epoll_create1(0);

struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = sock };
epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

struct epoll_event events[64];
int n = epoll_wait(epfd, events, 64, 100);
for (int i = 0; i < n; i++) {
    /* events[i].data.fd is ready — go read/write it */
}
```

Three syscalls:
- **`epoll_create1`** (`fs/eventpoll.c:2200`): create an epoll instance (a kernel object referenced by the returned FD).
- **`epoll_ctl`** (`fs/eventpoll.c:2385`): ADD, MOD, or DEL an FD from the instance.
- **`epoll_wait`** (`fs/eventpoll.c:2467`): block until one or more registered FDs become ready, or until the timeout.

### Internals

The epoll instance has:
- A red-black tree of registered FDs (for O(log N) ADD/DEL).
- A linked list of *ready* FDs (the "rdllist").
- A wait queue for blocked `epoll_wait` callers.

When you ADD an FD, epoll registers a callback on the FD's wait queue (the same wait queue `recvmsg` would block on). The callback is `ep_poll_callback` (`fs/eventpoll.c:1249`). When the FD becomes ready (e.g., data arrives), the kernel wakes the callback, which moves the FD into rdllist and wakes any `epoll_wait` waiters.

### Level-triggered vs edge-triggered

- **Level-triggered (LT, default):** epoll_wait reports the FD as long as it's ready. Read what you can, leave the rest; epoll_wait will report it again next time.
- **Edge-triggered (ET, `EPOLLET` flag):** epoll_wait reports the FD only when its readiness *changes* (e.g., went from "no data" to "data arrived"). You must drain the FD until you get `EAGAIN`, or you'll miss subsequent data.

ET is faster (fewer wake-ups) but more error-prone. LT is what you want unless you know exactly why ET helps.

### `EPOLLEXCLUSIVE` — solving thundering herd

Default semantics: when an event fires on an FD that has multiple `epoll_wait` waiters, *all* of them wake. For an `accept` socket shared by N workers, this means the SYN wakes all N — N-1 immediately call accept, get `EAGAIN`, go back to sleep. Wasted wake-ups.

`EPOLLEXCLUSIVE` (added 4.5) tells epoll: wake only one waiter per event. The kernel walks the wait queue and stops at the first responsive thread. Modern multi-process servers should use it.

(Aside: `SO_REUSEPORT` — Day 24 — is a more powerful alternative. Each worker has its own listening socket; the kernel hashes incoming SYNs across them, so each worker's epoll only ever sees SYNs that were destined for *it*.)

## io_uring — the completion model

The mental model: *"Do this network operation for me. Tell me when it's done."*

io_uring inverts the syscall model. Userspace and kernel share two memory-mapped ring buffers:

- **Submission Queue (SQ)**: userspace pushes Submission Queue Entries (SQEs) describing work to do.
- **Completion Queue (CQ)**: kernel pushes Completion Queue Entries (CQEs) when work finishes.

```c
struct io_uring ring;
io_uring_queue_init(256, &ring, 0);

struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sock_fd, buf, sizeof(buf), 0);
io_uring_submit(&ring);

struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);
/* cqe->res = bytes received (or negative errno) */
io_uring_cqe_seen(&ring, cqe);
```

Compared to epoll:

- **Epoll: 2 syscalls per I/O** (epoll_wait + recv).
- **io_uring: 1 syscall per batch** (submit, optionally batched with many SQEs at once). Or *zero* syscalls in steady state with kernel polling mode (`IORING_SETUP_SQPOLL`) — kernel thread polls the SQ.

For request rates above ~100k/sec, this matters. For lower rates, the difference is invisible.

### Network operations in io_uring

`io_uring/net.c` has the kernel-side implementations. Common ops (in `enum io_uring_op`):

- **`IORING_OP_RECV` / `SEND`** (`io_uring_prep_recv` / `io_uring_prep_send`) — equivalent to recv()/send() but submitted async.
- **`IORING_OP_RECVMSG` / `SENDMSG`** — equivalent to recvmsg()/sendmsg(); supports control messages, scatter-gather.
- **`IORING_OP_ACCEPT`** — async accept(). One CQE per accepted connection.
- **`IORING_OP_CONNECT`** — async connect(). CQE on completion.

### Multishot recv (5.18+)

`IORING_RECV_MULTISHOT` flag: one SQE submission, *many* CQEs as data arrives. The kernel keeps the recv "armed" — every time data is available it produces another CQE. Saves the per-recv submission cost; effectively turns recv into a streaming operation.

### Provided buffers (5.19+)

Instead of providing a buffer with each recv, register a pool of buffers. Recvs draw from the pool when ready. Reduces buffer allocation churn for high-rate servers.

### Zero-copy send (6.0+)

`IORING_OP_SEND_ZC` / `IORING_OP_SENDMSG_ZC` — kernel pins user pages and DMAs the data to the NIC without copying. Two CQEs per send:

1. The first when the kernel queues the send.
2. The second when the user pages are no longer in use (you can free/reuse the buffer).

Significantly higher throughput for big transfers; more complex flow control.

## When to choose which

For most servers, **epoll is fine**. It's been the standard for two decades; the implementation is mature; the API is small enough to use correctly. Notable users: nginx, redis, node.js (via libuv), most Python/Go/Rust async runtimes.

**io_uring shines** when:
- Sustained > 100k operations/sec per thread.
- You're already doing batched I/O (e.g., a database fsync alongside sends).
- You want zero-copy send for large transfers.
- You can pay the development complexity (bigger API surface, more failure modes).

Notable io_uring adopters: ScyllaDB, some experimental nginx forks, some Kubernetes runtimes, parts of QEMU. Adoption is growing but slowly — epoll's "just works" reputation is hard to beat.

## Today's experiment

### epoll wakeup tracking

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_epoll_wait { @waits = count(); }
tracepoint:syscalls:sys_exit_epoll_wait  { @returns = hist(args->ret); }
interval:s:5 { print(@waits); print(@returns); clear(@waits); clear(@returns) }'

# In another terminal: hammer a server
nginx &
ab -n 100000 -c 100 http://127.0.0.1/   # if you have apache-bench
```

Watch how often epoll_wait returns and how many events per call.

### Try a small io_uring example

```bash
sudo apt install liburing-dev
# Sample: hostname pings via io_uring. From the liburing examples directory.
ls /usr/share/doc/liburing/examples/
```

Or write a minimal accept loop:

```c
#include <liburing.h>
/* ... use io_uring_prep_accept on a listening socket, batch many ... */
```

The liburing API is friendly; the underlying io_uring syscalls (`io_uring_setup`, `io_uring_enter`, `io_uring_register`) are wrapped.

## What to read in the kernel

- **`fs/eventpoll.c:2200`** — `epoll_create1`. Tiny wrapper that allocates an `eventpoll` struct, gets an FD. Read the struct definition above this; that's the per-instance state.

- **`fs/eventpoll.c:2385`** — `epoll_ctl`. The ADD/MOD/DEL dispatcher. Notice how `EPOLL_CTL_ADD` calls `ep_insert` which registers the wait-queue callback on the target FD. *That's where the magic happens* — once the callback is registered, the FD reports readiness to epoll automatically.

- **`fs/eventpoll.c:1938`** — `ep_poll`. The wait path. Read end to end (~150 lines). Notice how it handles spurious wakes, the busy-loop fast path for low-latency cases, and how it dequeues from the rdllist.

- **`fs/eventpoll.c:1765`** — `ep_send_events`. Copies the ready list to the user's `epoll_event` array. For LT, re-arms the FD if still ready. For ET, doesn't.

- **`fs/eventpoll.c:1249`** — `ep_poll_callback`. The wait-queue callback that gets called when a registered FD becomes ready. Short (~50 lines). This is where readiness gets translated into an epoll event.

- **`io_uring/io_uring.c`** — io_uring main. Big file (~5000 lines). Don't read straight; trace specific ops. Key entry: `io_uring_enter` syscall handler.

- **`io_uring/net.c`** — networking ops. `io_send_setup` (line 349), `io_sendmsg_setup` (line 395), and the corresponding completion handlers. Read these to see how a SUBMIT_QUEUE_ENTRY translates to a real `tcp_sendmsg` (or its async equivalent) call.

- **`Documentation/networking/io_uring.rst`** — official guide. Brief but pointed.

- **liburing repo** (https://github.com/axboe/liburing) — the userspace wrappers. The `examples/` directory has runnable code for every common pattern.

## Bullet Points

- **epoll** = readiness model. "Tell me when ready, I'll syscall." Mature, simple, performs well for most servers.
- Three syscalls: `epoll_create1`, `epoll_ctl`, `epoll_wait`.
- **Level-triggered (default)** vs **edge-triggered (`EPOLLET`)** — ET requires draining to EAGAIN.
- **`EPOLLEXCLUSIVE`** — wake only one waiter per event. Solves thundering herd.
- **io_uring** = completion model. "Do this for me, tell me when done." Higher throughput at higher complexity.
- Net ops: `IORING_OP_RECV/SEND/RECVMSG/SENDMSG/ACCEPT/CONNECT`.
- **Multishot recv** (5.18+) — one submission, many completions.
- **Zero-copy send** (6.0+) — pin user pages, no copy. Two CQEs per send.
- For most servers, epoll. For very high-throughput batched workloads, io_uring.

## Check question

Why is `EPOLLEXCLUSIVE` important for accepting connections in a multi-worker server, and what's a more powerful alternative?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Without `EPOLLEXCLUSIVE`, when a SYN arrives at a listening socket shared by N workers, *all* of them get woken from `epoll_wait`. The first to call `accept()` succeeds; the rest immediately call `accept()`, get `EAGAIN`, and go back to sleep. That's "thundering herd" — wasted CPU, wasted scheduler decisions, lost cache locality. `EPOLLEXCLUSIVE` (added 4.5) tells the kernel "wake only one waiter per event," eliminating the wasted wake-ups.

**The more powerful alternative is `SO_REUSEPORT`** (Day 24). Instead of N workers sharing one listening socket, each worker creates its *own* listening socket bound to the same `(addr, port)`. The kernel hashes the incoming connection's 4-tuple and dispatches to one specific socket. Each worker's epoll only ever sees connections that *belong to it* — there's no shared FD, so no thundering herd is even possible. As a bonus, the kernel's hash gives client-side connection affinity (the same client always lands on the same worker — useful for stateful protocols, cache locality).

</details>

---

## End of Phase 3

You can now read the L4 layer: socket lifecycles, UDP, TCP states + congestion control + retransmission, sockopts, the modern wait APIs.

Phase 4 (Days 20–26) goes into the kernel's network subsystems: netfilter, conntrack, traffic control, kTLS, MPTCP.
