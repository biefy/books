# books

[English](README.md)

两本通过动手实验学习 Linux 内核原理的图文教程，采用 Head First 风格编写。

## 在线阅读

- **[Linux 网络子系统 30 天](https://biefy.github.io/books/linux-net/zh-CN/)** — 从 `sk_buff` 到 MPTCP，系统学习内核网络协议栈。
- **[30 天 eBPF 实战](https://biefy.github.io/books/ebpf/zh-CN/)** — 在 Linux 7.1 上学习现代 eBPF。

建议先读网络子系统，再读 eBPF；后者建立在前者的知识之上。

## 本地构建

两本书均使用 [mdBook](https://rust-lang.github.io/mdBook/) 构建。完整双语站点还使用锁定版本的 Pagefind：

```bash
brew install mdbook        # 也可以使用 cargo install mdbook
npm ci
./scripts/build-site.sh
python3 -m http.server --directory _site 8000
```

打开 `http://127.0.0.1:8000/`。单独预览英文版时仍可运行：

```bash
cd linux-net && mdbook serve --port 4001
cd ebpf      && mdbook serve --port 4002
```

每个 eBPF 章节都有清单记录的实验入口。在 Linux 上构建仓库自有的独立程序时，需要递归初始化子模块：

```bash
git submodule update --init --recursive
ebpf/labs/scripts/preflight.sh
make -C ebpf/labs check-standalone
```

完整的 `make -C ebpf/labs check` 还会构建锁定的 Linux v7.1 DCTCP 对象和 sched_ext 项目。请先运行 `ebpf/labs/scripts/linux-source.sh fetch`，并参阅 eBPF 一书的[实验环境](ebpf/src.zh-CN/lab-environment.md)页面了解软件包、运行权限、依赖锁和后端细节。

## 目录结构

```text
books/
├── index.html                    ← 英文入口（部署到 /books/）
├── zh-CN/index.html              ← 简体中文入口
├── linux-net/
│   ├── book.toml
│   ├── src/                      ← 英文原文
│   └── src.zh-CN/                ← 简体中文译文
├── ebpf/
│   ├── book.toml
│   ├── labs/                     ← 每章对应的实验
│   ├── src/                      ← 英文原文
│   └── src.zh-CN/                ← 简体中文译文
├── i18n/zh-CN-style.md           ← 翻译规范与术语表
└── scripts/
    ├── build-site.sh
    └── check-i18n.py
```

## 图表源文件

图表从 Mermaid（`.mmd`）、D2（`.d2`）与 Graphviz（`.dot`）源文件渲染。默认渲染英文图表，使用 `--locale` 渲染本地化图表：

```bash
./render-diagrams.sh
./render-diagrams.sh --locale zh-CN
./render-diagrams.sh --locale zh-CN linux-net
```

## 许可

内容采用 CC BY-SA 4.0 许可。使用、分享和改编时须署名，并以相同方式共享。
