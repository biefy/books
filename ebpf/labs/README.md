# Runnable labs for Practical eBPF

This directory owns the buildable source for Days 1–3 of the book. The chapter
code blocks include anchored regions from these files, so the displayed source
and the source compiled in CI are the same bytes.

## Dependency contract

`vendor/libbpf-bootstrap` is a git submodule pinned by the parent repository.
`bootstrap.commit` records the same commit so `scripts/preflight.sh` can detect
a checkout whose working tree does not match the gitlink.

Current pin:

- libbpf-bootstrap: `fac4e8ddf011aead8e14962bf8db74542331264b`
- nested libbpf, bpftool, blazesym, and architecture `vmlinux.h` repositories:
  the commits recorded by that bootstrap revision

Initialize the complete dependency tree after cloning:

```bash
git submodule update --init --recursive
```

Do not replace the submodule with a system libbpf or bpftool when validating
book changes. The pin is what makes local builds and CI exercise the same API.

## Build

The build is Linux-only. From this directory:

```bash
./scripts/preflight.sh
make check
```

`preflight.sh` only inspects the host and checkout. It does not install
packages, invoke `sudo`, mount filesystems, or modify kernel state.

The Makefile maps the host machine to the BPF target name (`x86_64` → `x86`,
`aarch64` → `arm64`, and so on), uses the pinned architecture header under
`vendor/libbpf-bootstrap/vmlinux.h`, builds a static libbpf and bootstrap
bpftool, then produces:

```text
.output/day01/hello.bpf.o   .output/day01/hello.skel.h   .output/day01/hello
.output/day02/count.bpf.o   .output/day02/count.skel.h   .output/day02/count
.output/day03/parent.bpf.o  .output/day03/parent.skel.h  .output/day03/parent
```

Useful targets:

```bash
make hello       # Day 1 only
make count       # Day 2 only
make parent      # Day 3 only
make objects     # BPF ELF objects only
make skeletons   # objects plus generated skeletons
make loaders     # all three userspace binaries
make clean       # remove .output
make V=1 check   # show complete compiler commands
```

## Runtime

Loading and attaching these programs changes live kernel state and normally
requires root (or a carefully configured capability set). Each loader owns its
BPF links and maps through its generated skeleton; Ctrl-C or SIGTERM destroys
the skeleton, which detaches links and closes maps. The labs do not pin objects
in bpffs.

Run one loader at a time from this directory, for example:

```bash
sudo ./.output/day01/hello
```

For an automated runtime check, first read `scripts/smoke.sh`. It requires an
explicit acknowledgement, runs only already-built binaries, creates triggers
inside one owned temporary directory, tracks one child PID at a time, and has a
trap that terminates that PID and removes the directory:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED ./scripts/smoke.sh
```

The compile-only CI workflow never runs this privileged smoke test.

## Scope

Only Days 1–3 are repo-owned labs today. Days 4–21 and Day 24 still publish
copyable chapter snippets rather than files compiled from this directory. Days
22–23 intentionally use the Linux kernel's BPF selftests, and Days 25–30 use
the kernel's `tools/sched_ext` tree. See the book's
[Lab environment](../src/lab-environment.md) page for the reader-facing matrix.
