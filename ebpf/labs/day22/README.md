# Day 22 — BPF DCTCP struct_ops (kernel selftest wrapper)

Day 22 loads the kernel's canonical BPF struct_ops example, the DCTCP
congestion-control reimplementation at
`tools/testing/selftests/bpf/progs/bpf_dctcp.c`. That program is part of the
Linux source tree and is **not copied into this repository**; copying it would
fork a file the kernel keeps evolving. Instead this directory ships thin,
auditable wrappers that compile and drive the canonical in-tree object from a
verified kernel checkout.

## What's here

- `config.env` — locked identifiers for the target: the selftest path, the
  built object name (`bpf_dctcp.bpf.o`), the two vtable variables (`dctcp` →
  `bpf_dctcp`, `dctcp_nouse` → rejected), and the persistent bpffs directory
  (`/sys/fs/bpf/dctcp`).
- `build.sh` — the `kernel-selftest` build wrapper the lab dispatcher runs
  (`scripts/build-day.sh day22`). Builds the canonical `bpf_dctcp.bpf.o` with
  a type header generated from the locked v7.1 kernel source.
- `run.sh` — the operator: `selftest` (default), `available`, `register`,
  `inspect`, `unregister`.

## Dependency contract

The wrappers resolve the kernel source through the shared
`scripts/linux-source.sh` helper, which honors `$LINUX_SRC` when set and
otherwise uses the pinned/fetched `v7.1` tree under `.output/`. Nothing needs
`LINUX_SRC` exported by hand. The build uses the repository's pinned bpftool;
only runtime struct_ops support comes from the host kernel.

## Use

Building is what the dispatcher does and it never needs root:

```bash
make -C ebpf/labs day22        # → scripts/build-day.sh day22 → day22/build.sh
```

Loading a BPF program does. As with `scripts/smoke.sh`, the privileged
subcommands of the operator are opt-in:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 EBPF_LABS_ALLOW_STRUCT_OPS=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED,EBPF_LABS_ALLOW_STRUCT_OPS \
  ./run.sh selftest
```

`selftest` temporarily registers the canonical object, verifies `bpf_dctcp`
appears, and then **unregisters it and removes its PID-scoped directory**. To
make the BPF algorithm persist for the "use it on a connection" and `inspect`
steps, `register` it, then `unregister` when finished:

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 EBPF_LABS_ALLOW_STRUCT_OPS=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED,EBPF_LABS_ALLOW_STRUCT_OPS \
  ./run.sh register
# ... inspect / run iperf3 -C bpf_dctcp ...
EBPF_LABS_ALLOW_PRIVILEGED=1 sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
  ./run.sh unregister
```

`register` tolerates the non-fatal error `bpftool` prints for the intentionally
incomplete `dctcp_nouse` vtable — that rejection is the required-ops gate firing,
exactly as the chapter describes, and the valid `dctcp` vtable still registers.
