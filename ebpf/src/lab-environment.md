# Lab environment

The book targets Linux 7.1, but reading the chapters and building the mdBook do
not require Linux. Compiling or running the eBPF labs does.

## Start with an isolated Linux host

Use a disposable VM or a dedicated development machine where you have root.
The first three labs attach read-only tracing programs, but later chapters
modify XDP, tc, cgroup, and scheduler hooks. Do not learn those mechanisms on a
production host or on the network interface carrying your only SSH session.

For the repo-owned Days 1–3 labs, the runtime kernel needs:

- BTF at `/sys/kernel/btf/vmlinux`;
- fentry support for `filename_unlinkat`;
- ring-buffer maps (Linux 5.8 or newer); and
- root, or an intentionally configured `CAP_BPF`/`CAP_PERFMON` capability set.

Linux 7.1 satisfies those feature requirements when the corresponding kernel
configuration is enabled.

## Clone the pinned toolchain

Clone the books repository with its recursive submodules:

```bash
git clone --recurse-submodules https://github.com/biefy/books.git
cd books
```

If you already cloned without them:

```bash
git submodule update --init --recursive
```

The repository pins libbpf-bootstrap at
`fac4e8ddf011aead8e14962bf8db74542331264b`. That gitlink recursively pins the
libbpf, bpftool, blazesym, and architecture `vmlinux.h` sources used by the
build. Do not separately clone a moving `master` branch for Days 1–3.

## Install host build prerequisites

You need Clang 17 or newer with the BPF target, a C compiler, GNU Make, Git,
and the libelf and zlib development headers. On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y clang llvm git make gcc libc6-dev libelf-dev zlib1g-dev pkg-config
```

Package names differ on Fedora and other distributions. The repository does
not install packages for you.

Run the non-mutating preflight from the repository root:

```bash
ebpf/labs/scripts/preflight.sh
```

Add `--runtime` to also require the running kernel's BTF:

```bash
ebpf/labs/scripts/preflight.sh --runtime
```

The script never invokes `sudo`, installs packages, or mounts filesystems.

## Build Days 1–3

From the repository root:

```bash
make -C ebpf/labs check
```

This builds pinned libbpf and bpftool, compiles each `.bpf.c`, verifies that
bpftool can read each object's BTF, generates each skeleton, and links each
userspace loader. Generated files stay under `ebpf/labs/.output/` and are
ignored by Git.

Build one day while experimenting:

```bash
make -C ebpf/labs hello   # Day 1
make -C ebpf/labs count   # Day 2
make -C ebpf/labs parent  # Day 3
```

Use `make -C ebpf/labs clean` to remove every generated artifact.

## Run without leaking attachments

Run loaders in the foreground and stop them with Ctrl-C:

```bash
sudo ebpf/labs/.output/day01/hello
```

The loader owns its BPF links and maps through the generated skeleton. Its
SIGINT/SIGTERM path frees the ring buffer if present, destroys the skeleton,
detaches every link, and closes every map. Nothing is pinned under
`/sys/fs/bpf`.

A privileged smoke helper exists for a disposable lab host. It is deliberately
opt-in and uses only an owned temporary directory and child PIDs:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED ebpf/labs/scripts/smoke.sh
```

CI performs compile and skeleton checks only; it never loads a BPF program.

## Which chapters own runnable files?

| Days | Source of the runnable lab |
|---|---|
| **1–3** | This repository: `ebpf/labs/day01` through `day03` |
| **4–21, 24** | Copyable chapter snippets; not yet compiled by repository CI |
| **22–23** | Linux source tree: `tools/testing/selftests/bpf` |
| **25–30** | Linux source tree: `tools/sched_ext` |

That boundary is intentional. A successful `make -C ebpf/labs check` proves
only the repo-owned Days 1–3 sources; it does not silently claim coverage for
the remaining curriculum.
