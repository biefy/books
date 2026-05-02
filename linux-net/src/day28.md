# Day 28 — io_uring networking: zero-copy send/recv

> **Today's mission:** see how io_uring fundamentally inverts the syscall model for sockets, why zero-copy send is a big deal for high-throughput servers, and how multishot recv lets you submit once and receive many. Total time: ~75 minutes.

## The two I/O paradigms

Day 19 introduced epoll (readiness model) and io_uring (completion model). Today we go deep into io_uring's networking-specific abilities.

![io_uring net](diagrams/day28_iouring_net.png)

Recall:

- **epoll**: "tell me when this FD is ready; I'll syscall myself." Each I/O = `epoll_wait` (1 syscall) + `recv`/`send` (1 syscall). Two syscalls per I/O.
- **io_uring**: "do this for me; tell me when done." Each batch of I/Os = 1 syscall (`io_uring_enter`) covering many ops. Or zero in steady state with `IORING_SETUP_SQPOLL` (kernel-thread polling).

For workloads doing > 100k ops/sec per thread, the syscall savings alone are significant. For zero-copy send, the gains scale with payload size.

## The basic API

```c
#include <liburing.h>

struct io_uring ring;
io_uring_queue_init(256, &ring, 0);

/* Submit a recv */
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sock_fd, buf, sizeof(buf), 0);
io_uring_sqe_set_data(sqe, /* user pointer */);
io_uring_submit(&ring);

/* Wait for completion */
struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);
/* cqe->res = number of bytes received (or -errno) */
io_uring_cqe_seen(&ring, cqe);
```

The ring is a pair of memory-mapped queues:
- **Submission Queue (SQ)**: userspace pushes Submission Queue Entries (SQEs).
- **Completion Queue (CQ)**: kernel pushes Completion Queue Entries (CQEs).

`io_uring_submit()` is a single syscall that hands control to the kernel; the kernel processes pending SQEs and (eventually) posts CQEs.

## Network-specific ops

In `io_uring/net.c`, where the actual `io_send`, `io_recv`, etc. functions live.

### Basic ops

| Op | Userspace prep | Equivalent syscall |
|----|----------------|---------------------|
| `IORING_OP_RECV` | `io_uring_prep_recv` | `recv()` |
| `IORING_OP_SEND` | `io_uring_prep_send` | `send()` |
| `IORING_OP_RECVMSG` | `io_uring_prep_recvmsg` | `recvmsg()` (msghdr — supports cmsg, scatter-gather) |
| `IORING_OP_SENDMSG` | `io_uring_prep_sendmsg` | `sendmsg()` |
| `IORING_OP_ACCEPT` | `io_uring_prep_accept` | `accept4()` |
| `IORING_OP_CONNECT` | `io_uring_prep_connect` | `connect()` |
| `IORING_OP_CLOSE` | `io_uring_prep_close` | `close()` |
| `IORING_OP_SHUTDOWN` | `io_uring_prep_shutdown` | `shutdown()` |

Each is async: submit → kernel does the work in the background → CQE posted when done.

### Multishot recv (5.18+)

`IORING_RECV_MULTISHOT` flag on `io_uring_prep_recv`: one submission, *many* CQEs. The kernel keeps the recv "armed" — every time data arrives, a CQE is posted. The recv stays in flight until the socket closes or you cancel it.

```c
io_uring_prep_recv(sqe, sock, buf, sizeof(buf), 0);
sqe->ioprio |= IORING_RECV_MULTISHOT;
io_uring_submit(&ring);

/* Now process CQEs as they come — no more submit per recv */
for (;;) {
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);
    /* cqe->res = bytes received this time */
    io_uring_cqe_seen(&ring, cqe);
}
```

For high-rate receivers, this eliminates the per-recv submission cost entirely.

### Provided buffers (5.19+)

Instead of providing a buffer with each recv, register a pool of buffers:

```c
io_uring_register_buffers(&ring, iovs, n);
```

When you submit recv with `IOSQE_BUFFER_SELECT`, the kernel picks a buffer from the pool when data is actually available — not at submit time. Saves buffer allocation churn.

### Zero-copy send (6.0+)

`IORING_OP_SEND_ZC` / `IORING_OP_SENDMSG_ZC`. Kernel pins user pages (locks them in memory), DMAs the data via the NIC without copying.

**Two CQEs per send:**

1. **Notification of submission**: kernel queued the send. Kernel may or may not have transmitted yet.
2. **Notification of completion**: user pages are no longer in use; the buffer is safe to free or reuse.

```c
sqe = io_uring_get_sqe(&ring);
io_uring_prep_send_zc(sqe, sock, buf, len, 0, 0);
io_uring_submit(&ring);

/* CQE 1: send started */
io_uring_wait_cqe(&ring, &cqe);

/* CQE 2: buffer no longer in use (e.g., NIC DMA done) */
io_uring_wait_cqe(&ring, &cqe);
```

Why two? Because at the first CQE the kernel has *queued* the send but the NIC hasn't necessarily DMAed the bytes. Reusing the buffer too early would corrupt the in-flight transmit. The second CQE tells you "now you can reuse."

For large transfers (> ~4 KB), zero-copy send approaches the limits of what the NIC and PCIe bus allow. Userspace processes (databases, HTTP servers serving large files) see significant throughput improvement.

### Zero-copy receive (experimental 6.x)

Day 29 mentions **io_iov** and **page pool memory provider** — the infrastructure to extend zero-copy semantics to RX. Not as mature as ZC send; check kernel notes.

## When to choose which

For most servers, **epoll is enough**. Battle-tested, simple API, performs well into the millions of QPS for typical web workloads.

**io_uring shines** when:

1. Sustained > 100k ops/sec per thread *and* you can pay the development complexity.
2. You're already doing batched I/O across multiple kinds (file I/O alongside network).
3. You want zero-copy send for large transfers (CDN edges, large file serving).
4. You want to use `IORING_SETUP_SQPOLL` to skip the syscall path entirely (reduces context switches under heavy load).

**io_uring's complexity tax**:
- Bigger API surface (~50 ops, lots of flags).
- Subtle ordering rules (when the SQE order matters; when CQE delivery is guaranteed).
- More failure modes (incorrect ring sizing → drops; misuse of ZC buffers → crashes).

Adoption is real but slower than the engineering benefits suggest. Notable users: **ScyllaDB**, parts of **QEMU** for storage I/O, experimental **nginx** branches, some **Kubernetes** runtimes for high-volume pod ingest.

## Today's experiment

```bash
# Verify io_uring support
ls /proc/kallsyms | grep io_uring_enter || cat /proc/version

# Install liburing if not present
sudo apt install liburing-dev liburing2

# Look at the examples
ls /usr/share/doc/liburing/examples/

# A trivial async-accept loop
cat << 'EOF' > /tmp/iour_accept.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <liburing.h>

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { AF_INET, htons(7777) };
    bind(s, (struct sockaddr*)&a, sizeof a);
    listen(s, 64);

    struct io_uring ring;
    io_uring_queue_init(8, &ring, 0);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, s, NULL, NULL, 0);
    io_uring_submit(&ring);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);
    int conn = cqe->res;
    if (conn >= 0) { send(conn, "hi via io_uring\n", 16, 0); close(conn); }
    io_uring_cqe_seen(&ring, cqe);

    io_uring_queue_exit(&ring);
    close(s);
    return 0;
}
EOF
cc /tmp/iour_accept.c -o /tmp/iour_accept -luring && /tmp/iour_accept &

# Connect:
nc localhost 7777
```

Watch the kernel side:

```bash
sudo bpftrace -e '
fentry:io_send_setup { @send = count(); }
fentry:io_recvmsg_setup { @recv = count(); }
interval:s:5 { print(@send); print(@recv) }'
```

## What to read in the kernel

- **`io_uring/net.c`** — networking ops. ~2500 lines. Key entries:
  - `io_send_setup` (line 349), `io_send` and friends — the send paths.
  - `io_sendmsg_setup` (line 395), `io_recvmsg`.
  - `io_send_zc`, `io_sendmsg_zc` — zero-copy paths.
  - The `io_kiocb` struct holds per-op state.

- **`io_uring/io_uring.c`** — main entry points: `io_uring_setup`, `io_uring_register`, `io_uring_enter`. Read `io_submit_sqes` for the submission walk and `io_iopoll_getevents` for the completion side.

- **`io_uring/poll.c`** — multishot infrastructure. Multishot recv keeps requests in a "ready" state and re-fires CQEs.

- **`include/uapi/linux/io_uring.h`** — UAPI. Operation IDs (`IORING_OP_*`), flags (`IOSQE_*`), all the structs userspace touches.

- **liburing repo** (https://github.com/axboe/liburing) — userspace API. The `examples/` directory has annotated code for every common pattern.

- **`Documentation/networking/io_uring.rst`** — kernel docs, brief.

- **External**: Jens Axboe's "io_uring: efficient io" papers/talks; the libuv issue tracker for nuanced behavior comparisons.

## Bullet Points

- **io_uring** = completion model. Submit ops as SQEs; kernel posts CQEs.
- **One syscall per batch** (`io_uring_enter`) instead of two per I/O (epoll + recv).
- **Zero syscalls in steady state** with `IORING_SETUP_SQPOLL` (kernel-thread polls).
- **Multishot recv** (5.18+): one submission, many CQEs as data arrives.
- **Zero-copy send** (6.0+): `IORING_OP_SEND_ZC`. Two CQEs per send (queued, then "buffer free to reuse").
- **Provided buffers** (5.19+): kernel picks from a registered pool when data arrives.
- For most servers, **epoll is fine**. io_uring is for sustained > 100k ops/sec or batched workloads.
- The complexity tax is real; adoption is slow but growing.

## Check question

If you submit `IORING_OP_RECV` and immediately `io_uring_wait_cqe`, what's the difference compared to a blocking `recv()`?

<details>
<summary>Click to reveal answer</summary>

**Answer:** Functionally similar — both block until data arrives. The mechanism is different.

For blocking `recv()`: the syscall enters kernel, blocks on the socket's `sk->sk_data_ready` wake queue, returns when woken with the data copied to user.

For `IORING_OP_RECV` + immediate wait: the SQE is processed, the kernel registers a wait on the socket, you exit to userspace once the SQE is queued. When the wait fires (data arrives), the kernel posts a CQE and you wake at `io_uring_wait_cqe`.

For a single recv this is *more overhead* than blocking recv — you pay the io_uring framework cost without getting the batching benefit. The win is when you have **hundreds of operations in flight**: one `io_uring_enter` syscall to submit them all, one to wait for any to complete. epoll would need one syscall per `recv()` plus one per `epoll_wait()`. At scale, io_uring's amortized syscall cost is much lower.

For a server doing 1 op/sec, blocking recv beats io_uring. For one doing 100k ops/sec, io_uring wins. The crossover depends on workload.

</details>

---

## Tomorrow

Day 29: recent additions — PSP encryption, drop_monitor improvements, devlink, NETLINK YAML.
