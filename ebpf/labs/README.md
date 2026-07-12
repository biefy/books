# Runnable labs for Practical eBPF

This directory owns or reproducibly builds the runnable source for every
published entry in the book. Complete chapter listings are included from the
files declared in `manifest.json`, so the source shown to readers is the source
compiled by the lab checks.

## Coverage contract

`manifest.json` has one entry for each chapter in `../src/SUMMARY.md`: Day 1
through Day 27 plus the combined Days 28–30 capstone. It records the build
backend, app or upstream target, source files, chapter includes, and the
compile/runtime proof available for that lab.

```bash
make check-coverage
```

The check fails for a missing/duplicate day, an absent source or upstream
wrapper, a standalone app without both BPF and userspace source, or a chapter
that does not include its declared book source. A green coverage check is not a
kernel runtime test; each manifest entry says what remains opt-in.

## Pinned dependencies

The repository pins two recursive submodules and one official source archive:

- `vendor/libbpf-bootstrap` at the commit in `bootstrap.commit`, recursively
  pinning libbpf, bpftool, and architecture `vmlinux.h` inputs;
- `vendor/xdp-tools` (libxdp) at the v1.6.3 commit in `xdp-tools.commit`, with
  its nested libbpf revision;
- Linux v7.1 in `linux-source.lock.json`, including the exact release git
  commit, kernel.org URL, and archive SHA-256.

Initialize the submodules after cloning:

```bash
git submodule update --init --recursive
```

`scripts/preflight.sh` rejects missing, dirty, or wrong-revision submodules.
The build copies xdp-tools beneath `.output/` before running its configure step,
so the pinned vendor checkout stays immutable.

The 7.1 kernel source is intentionally not a huge submodule and is never fetched
as a side effect of preflight:

```bash
./scripts/linux-source.sh fetch       # download and verify the official archive
./scripts/linux-source.sh verify      # verify the selected tree
./scripts/linux-source.sh path        # print the verified tree
```

Set `LINUX_SRC=/path/to/linux` to use an existing exact v7.1 git checkout (or a
tree previously produced by the fetch helper). Other revisions are rejected.

`scripts/kernel-btf.sh` builds only the locked kernel aggregate needed by the
selected backend, encodes its DWARF as BTF, and emits a deterministic
`vmlinux.h` under `.output/`. `scripts/linux-bpftool.sh` builds the bootstrap
bpftool from that same locked release, keeping its skeleton schema aligned with
the upstream kernel sources. Day 22 and the sched_ext wrappers therefore do not
read the build host's `/sys/kernel/btf/vmlinux` or require a complete kernel
image.

## Build backends

| Chapters | Backend | What is built |
|---|---|---|
| Days 1–21, 24 | Standalone libbpf/libxdp | Repo-owned BPF objects, skeletons, and loaders |
| Day 22 | Linux BPF selftest source | Canonical v7.1 DCTCP struct_ops object + owned registration check |
| Day 23 | Kernel derivative | Repo-owned telemetry DCTCP derivative against v7.1 support |
| Day 25 | sched_ext upstream | Locked v7.1 `scx_simple` |
| Day 26 | sched_ext derivative | Repo-owned priority-cgroup scheduler against v7.1 support |
| Day 27 | sched_ext upstream | Locked v7.1 `scx_central` |
| Days 28–30 | Standalone reference capstone | Repo-owned latency histogram/outlier/stack tracer |

Run the non-mutating standalone preflight and fast compile check:

```bash
./scripts/preflight.sh
make check-standalone
```

After explicitly fetching or selecting v7.1, build every manifest backend:

```bash
./scripts/linux-source.sh fetch
make check
```

Useful targets:

```bash
make day14             # build one declared chapter lab
make day28-30          # build the reference capstone
make hello             # compatibility alias for Day 1
make objects           # all standalone BPF ELF objects
make skeletons         # all standalone skeleton headers
make loaders           # all standalone userspace binaries
make check-kernel      # only selftest/sched_ext-backed entries
make clean             # remove every generated file under .output
make V=1 check         # show complete compiler commands
```

Generated files never leave `ebpf/labs/.output/`.

## Runtime boundary

Compilation needs Linux, Clang 17+, GNU Make, a C compiler, Git, Python 3,
libelf/zlib/libpcap headers, and the tools required by the selected backend.
Kernel-backed builds additionally use `bc`, Flex, Bison, `pahole`, `readelf`,
`rsync`, and the explicitly fetched or selected Linux v7.1 tree. Loading
programs generally requires root (or deliberately configured BPF
capabilities), runtime BTF, and the relevant kernel configuration/hooks.

Run loaders in the foreground and stop them with Ctrl-C. Skeleton-owned links
and maps are destroyed by each signal path. Networking smoke cases use owned
namespaces/veth pairs; cgroup cases move only controlled children; DCTCP cases
restore captured congestion-control state; sched_ext cases require a disposable
compatible VM and a bounded timeout.

The dispatcher is deliberately opt-in:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
  ./scripts/smoke.sh day01 day14
```

Set `EBPF_LABS_ALLOW_STRUCT_OPS=1` in addition for TCP struct_ops registration,
or `EBPF_LABS_ALLOW_SCHED_EXT=1` for scheduler replacement. Read the selected case before running it. Hosted CI
performs compile, BTF, skeleton, link, source-sync, and locked-upstream build
checks only; it never attaches programs or replaces the scheduler.
