# books

Two hands-on books on Linux kernel internals, written in Head First style with rendered diagrams.

## Read online

- **[Linux Network Subsystem in 30 Days](https://biefy.github.io/books/linux-net/)** — kernel network stack from `sk_buff` to MPTCP.
- **[Practical eBPF in 30 Days](https://biefy.github.io/books/ebpf/)** — modern eBPF on Linux 7.1.

Read the network book first; the BPF book builds on it.

## Build locally

Both books use [mdbook](https://rust-lang.github.io/mdBook/).

```bash
brew install mdbook        # or cargo install mdbook
cd linux-net && mdbook serve --port 4001
cd ebpf      && mdbook serve --port 4002
```

Open `http://127.0.0.1:4001` and `http://127.0.0.1:4002`.

Every eBPF chapter has a manifest-backed lab entry. Build all repo-owned standalone programs on Linux with recursive submodules:

```bash
git submodule update --init --recursive
ebpf/labs/scripts/preflight.sh
make -C ebpf/labs check-standalone
```

The exhaustive `make -C ebpf/labs check` additionally builds the canonical locked Linux v7.1 DCTCP object and sched_ext entries after `ebpf/labs/scripts/linux-source.sh fetch`. See the eBPF book's [Lab environment](ebpf/src/lab-environment.md) for packages, runtime privileges, dependency locks, and backend details.

## Layout

```
books/
├── index.html               ← landing page (deployed at /books/)
├── linux-net/
│   ├── book.toml
│   └── src/
│       ├── SUMMARY.md
│       ├── README.md
│       ├── day01.md … day30.md
│       └── diagrams/*.png
├── ebpf/
│   ├── book.toml
│   ├── labs/                    ← manifest-backed labs for every chapter
│   │   ├── day01/ … day28-30/
│   │   ├── manifest.json        ← coverage/build/runtime contract
│   │   └── vendor/              ← pinned bootstrap + xdp-tools submodules
│   └── src/
│       ├── SUMMARY.md
│       ├── README.md
│       ├── day01.md … day28-30.md
│       └── diagrams/*.png
└── .github/workflows/
    ├── deploy.yml
    └── ebpf-labs.yml
```

## Diagram sources

Diagrams are rendered from Mermaid (`.mmd`), D2 (`.d2`), and Graphviz (`.dot`) sources. To re-render:

```bash
# in either book's diagrams/ dir, given source files in src/
brew install graphviz d2 imagemagick
npm install -g @mermaid-js/mermaid-cli

for f in src/*.mmd; do mmdc -i "$f" -o "$(basename "${f%.mmd}").png" -b white --scale 2 -q; done
for f in src/*.d2;  do d2 --pad 20 "$f" "$(basename "${f%.d2}").png"; done
for f in src/*.dot; do dot -Tpng "$f" -o "$(basename "${f%.dot}").png"; done
```

## License

Content: CC BY-SA 4.0. Use, share, adapt — credit and share-alike.
