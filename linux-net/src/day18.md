# Day 18 — Socket options: per-socket tuning

> **Today's mission:** know which sockopts matter and what they do. Total time: ~60 minutes.

![sockopts](diagrams/day18_sockopts.png)

## SOL_SOCKET (generic)

- **`SO_RCVBUF`/`SO_SNDBUF`** — buffer sizes (kernel doubles when set; reads return doubled value).
- **`SO_REUSEADDR`** — bind on TIME_WAIT'd port.
- **`SO_REUSEPORT`** — multiple sockets share one port (load balancing). Day 24.
- **`SO_KEEPALIVE`** — periodic keepalives. Per-socket: `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`.
- **`SO_LINGER`** — block `close` until data flushed (or RST after timeout).
- **`SO_BINDTODEVICE`** — bind socket to specific iface. Useful for multi-homed hosts.
- **`SO_MARK`** — set fwmark on outgoing packets (for fib_rules).

## SOL_TCP

- **`TCP_NODELAY`** — disable Nagle. Tiny writes go on the wire immediately.
- **`TCP_CORK`** — opposite of NODELAY. Buffer until full or `TCP_CORK off`.
- **`TCP_QUICKACK`** — disable delayed ACKs (one-shot).
- **`TCP_CONGESTION`** — name string of CC algorithm.
- **`TCP_USER_TIMEOUT`** — give up after this much time without progress (instead of going by RTO).
- **`TCP_FASTOPEN`** — TFO server-side (queue up to N early-data connections).
- **`TCP_INFO`** — read kernel-side stats (rtt, cwnd, retrans, etc.).
- **`TCP_TX_DELAY`** — BBR pacing delay (4.9+).

## SOL_IP / SOL_IPV6

- **`IP_TOS`** — set DSCP / ECN bits.
- **`IP_TTL`** — outbound TTL.
- **`IP_PKTINFO`** — receive aux info (which iface a UDP packet arrived on).
- **`IP_TRANSPARENT`** — TPROXY, bind to non-local IP.
- **`IP_FREEBIND`** — bind before address is configured.

## Today's experiment

```bash
# See sockopts on a live socket:
ss -tipsm | head -20

# Check current TCP info via getsockopt:
cat << 'EOF' > /tmp/tcpinfo.c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(){
  int s = socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a = {AF_INET, htons(80), inet_addr("8.8.8.8")};
  connect(s, (void*)&a, sizeof a);
  struct tcp_info ti;
  socklen_t l = sizeof ti;
  getsockopt(s, IPPROTO_TCP, TCP_INFO, &ti, &l);
  printf("rtt %u, cwnd %u, retrans %u\n",
         ti.tcpi_rtt, ti.tcpi_snd_cwnd, ti.tcpi_total_retrans);
}
EOF
cc /tmp/tcpinfo.c -o /tmp/tcpinfo && /tmp/tcpinfo
```

## What to read in the kernel

- **`net/socket.c`** — `do_setsockopt`, `do_getsockopt`.
- **`net/ipv4/tcp.c`** — search `tcp_setsockopt`, `tcp_getsockopt`.
- **`net/core/sock.c`** — `sock_setsockopt`.
- **`include/uapi/linux/tcp.h`** — TCP sockopt constants.
- **`include/uapi/asm-generic/socket.h`** — SO_* constants.

## Bullet Points

- Sockopts split: `SOL_SOCKET` (generic), `SOL_IP`, `SOL_TCP`, `SOL_UDP`.
- `TCP_NODELAY` for latency-critical apps.
- `TCP_CORK` for batching small writes.
- `TCP_USER_TIMEOUT` is a shortcut to avoid waiting for RTO timeouts.
- `TCP_INFO` gives you everything `ss -ti` shows.
- BPF (via cgroup sockops) can override sockopts kernel-side.

## Check question

Why might `TCP_NODELAY` and `TCP_CORK` look like opposites but be set on the same socket at different times?

.  
.  
.

**Answer:** They serve different needs at different points. A request/response server might `CORK` while building a multi-piece response (header + body), then *uncork* — kernel sends one large segment. After response, `NODELAY` for any tail data so it doesn't wait. Real apps use both: cork for batching prepared output, nodelay for ad-hoc small writes between batches.

## Tomorrow

Day 19: epoll and io_uring for sockets.
