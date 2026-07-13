# Lab environment

The book targets Linux 7.1. Reading and rendering the mdBook works on other
platforms; compiling or running the eBPF labs requires Linux.

## Use an isolated Linux host

Use a disposable VM or dedicated development machine where you have root.
Tracing labs attach read-only programs, but later chapters exercise XDP, tc,
tcx, AF_XDP, cgroups, TCP struct_ops, and sched_ext. Never learn those hooks on
the interface carrying your only SSH session or on a production scheduler.

For runtime work the kernel needs BTF at `/sys/kernel/btf/vmlinux`, BPF syscall
and JIT support, and each chapter's hook/map/kfunc configuration. Linux 7.1
provides the required APIs when its corresponding BPF, networking, cgroup,
TCP-congestion-control, and sched_ext options are enabled. The preflight checks
what it can without changing the host; attachment failures still report the
specific unavailable hook or kfunc.

## Clone the pinned dependencies

```bash
git clone --recurse-submodules https://github.com/biefy/books.git
cd books
```

For an existing clone:

```bash
git submodule update --init --recursive
```

The repository pins:

- libbpf-bootstrap at `fac4e8ddf011aead8e14962bf8db74542331264b`,
  recursively including libbpf, bpftool, and architecture `vmlinux.h`;
- xdp-tools/libxdp v1.6.3 at `8fbad9f0af621a22aa87ff2520b3735915b1f0fd`;
- the official Linux 7.1 archive and commit in
  `ebpf/labs/linux-source.lock.json`.

Do not replace these with moving branches when validating book code.

## Install build prerequisites

You need Clang 17+ with the BPF target, a C compiler, GNU Make, Git, Python 3,
libelf/zlib development headers, and m4 for the pinned libxdp build. The
kernel-backed DCTCP and sched_ext builds add ordinary kernel build tools. On
Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y \
  clang llvm git make gcc libc6-dev libelf-dev zlib1g-dev pkg-config python3 \
  curl xz-utils m4 flex bison pahole libssl-dev libcap-dev libunwind-dev \
  libdw-dev libpcap-dev bc rsync binutils iproute2 iperf3
```

Package names differ on other distributions. Repository scripts do not install
packages, invoke `sudo`, mount filesystems, or silently fetch dependencies.

Run the check-only standalone preflight:

```bash
ebpf/labs/scripts/preflight.sh
```

Add `--kernel` after selecting/fetching the locked source and `--runtime` when
you also want checks against the running host:

```bash
ebpf/labs/scripts/linux-source.sh fetch
ebpf/labs/scripts/preflight.sh --kernel --runtime
```

## Build all lab sources

The quick path compiles every repository-owned standalone lab, including
AF_XDP and the reference capstone:

```bash
make -C ebpf/labs check-standalone
```

The exhaustive check also builds the canonical Linux v7.1 DCTCP object and the
sched_ext backends:

```bash
ebpf/labs/scripts/linux-source.sh fetch
make -C ebpf/labs check
```

Use an existing exact checkout with `LINUX_SRC=/path/to/linux`. The helper
rejects other commits/releases. Build one chapter with `make -C ebpf/labs dayNN`;
use `day28-30` for the combined capstone. All generated artifacts stay
under `ebpf/labs/.output/` and `make clean` removes them. Kernel-backed wrappers
build only the relevant v7.1 aggregate, convert its DWARF to BTF, and generate a
narrow `vmlinux.h`; compilation never depends on the build host's kernel BTF.

## Coverage by backend

| Days | Runnable source/build owner |
|---|---|
| **1–21, 24** | Repo-owned standalone libbpf/libxdp apps |
| **22** | Exact Linux v7.1 DCTCP BPF selftest wrapper |
| **23** | Repo-owned telemetry DCTCP derivative against v7.1 support |
| **25** | Exact v7.1 `tools/sched_ext/scx_simple` wrapper |
| **26** | Repo-owned priority-cgroup sched_ext derivative against v7.1 support |
| **27** | Exact v7.1 `tools/sched_ext/scx_central` wrapper |
| **28–30** | Repo-owned Option A reference capstone; the other project choices remain open-ended |

`make check-coverage` compares this curriculum mechanically with
`SUMMARY.md`, `manifest.json`, the source tree, and the chapter includes.

## Run without leaking state

Run ordinary loaders in the foreground and stop them with Ctrl-C. Their signal
paths destroy skeleton-owned links and maps; nothing is pinned unless a chapter
explicitly teaches pinning.

The privileged smoke dispatcher is opt-in and accepts an explicit day list:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
  ebpf/labs/scripts/smoke.sh day01 day14
```

It owns its triggers, child PIDs, temporary files, namespaces/veths, qdiscs,
and cgroups and cleans them in reverse order. TCP struct_ops registration additionally requires `EBPF_LABS_ALLOW_STRUCT_OPS=1`;
sched_ext replacement requires `EBPF_LABS_ALLOW_SCHED_EXT=1`. Run either only
on a disposable compatible VM. Hosted CI performs compile/link/BTF and
locked-source builds only; it never performs privileged attachment.
