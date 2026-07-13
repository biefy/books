# 实验环境

本书面向 Linux 7.1。其他平台也可以阅读和渲染 mdBook；编译或运行 eBPF 实验则需要 Linux。

## 使用隔离的 Linux 主机

请使用你拥有 root 权限的一次性虚拟机或专用开发机器。跟踪实验挂载的是只读程序，但后续章节会使用 XDP、tc、tcx、AF_XDP、cgroup、TCP struct_ops 和 sched_ext。切勿在承载你唯一 SSH 会话的接口上或生产调度器上学习这些钩子。

要进行运行时实验，内核需要在 `/sys/kernel/btf/vmlinux` 提供 BTF，支持 BPF 系统调用和 JIT，并启用各章所需的钩子、映射及 kfunc 配置。启用相应的 BPF、网络、cgroup、TCP 拥塞控制和 sched_ext 选项后，Linux 7.1 会提供所需 API。预检脚本会在不更改主机的前提下检查它能检查的内容；挂载失败时仍会报告具体不可用的钩子或 kfunc。

## 克隆锁定的依赖项

```bash
git clone --recurse-submodules https://github.com/biefy/books.git
cd books
```

对于已有的克隆：

```bash
git submodule update --init --recursive
```

仓库锁定了：

- libbpf-bootstrap 提交 `fac4e8ddf011aead8e14962bf8db74542331264b`，递归包含 libbpf、bpftool 和各架构的 `vmlinux.h`；
- xdp-tools/libxdp v1.6.3，提交为 `8fbad9f0af621a22aa87ff2520b3735915b1f0fd`；
- `ebpf/labs/linux-source.lock.json` 中记录的官方 Linux 7.1 归档与提交。

验证书中代码时，不要用不断变化的分支替换这些锁定版本。

## 安装构建依赖

你需要支持 BPF 目标的 Clang 17+、C 编译器、GNU Make、Git、Python 3、libelf/zlib 开发头文件，以及构建锁定版 libxdp 所需的 m4。基于内核的 DCTCP 和 sched_ext 构建还需要常规内核构建工具。在 Ubuntu 或 Debian 上：

```bash
sudo apt update
sudo apt install -y \
  clang llvm git make gcc libc6-dev libelf-dev zlib1g-dev pkg-config python3 \
  curl xz-utils m4 flex bison pahole libssl-dev libcap-dev libunwind-dev \
  libdw-dev libpcap-dev bc rsync binutils iproute2 iperf3
```

其他发行版的软件包名称有所不同。仓库脚本不会安装软件包、调用 `sudo`、挂载文件系统，也不会静默获取依赖项。

运行仅执行检查的独立预检脚本：

```bash
ebpf/labs/scripts/preflight.sh
```

选择或获取锁定的源代码后加入 `--kernel`；若还要检查当前运行的主机，则加入 `--runtime`：

```bash
ebpf/labs/scripts/linux-source.sh fetch
ebpf/labs/scripts/preflight.sh --kernel --runtime
```

## 构建所有实验源代码

快速路径会编译仓库自有的全部独立实验，包括 AF_XDP 和参考综合项目：

```bash
make -C ebpf/labs check-standalone
```

完整检查还会构建规范的 Linux v7.1 DCTCP 对象和 sched_ext 后端：

```bash
ebpf/labs/scripts/linux-source.sh fetch
make -C ebpf/labs check
```

可通过 `LINUX_SRC=/path/to/linux` 使用已有且版本完全一致的检出目录。辅助脚本会拒绝其他提交或发行版。使用 `make -C ebpf/labs dayNN` 构建单章；合并的综合项目使用 `day28-30`。所有生成的产物都位于
`ebpf/labs/.output/` 下，`make clean` 会将其删除。基于内核的包装器只构建相关的 v7.1 聚合目标，将其 DWARF 转换为 BTF，并生成精简的 `vmlinux.h`；编译从不依赖构建主机的内核 BTF。

## 各后端的覆盖范围

| 天数 | 可运行源码与构建归属 |
|---|---|
| **1–21, 24** | 仓库自有的独立 libbpf/libxdp 应用 |
| **22** | 精确的 Linux v7.1 DCTCP BPF 自测试包装器 |
| **23** | 基于 v7.1 支持的仓库自有遥测 DCTCP 派生实现 |
| **25** | 精确的 v7.1 `tools/sched_ext/scx_simple` 包装器 |
| **26** | 基于 v7.1 支持的仓库自有优先级 cgroup sched_ext 派生实现 |
| **27** | 精确的 v7.1 `tools/sched_ext/scx_central` 包装器 |
| **28–30** | 仓库自有的选项 A 参考综合项目；其他项目选项保持开放 |

`make check-coverage` 会将这套课程与 `SUMMARY.md`、`manifest.json`、源代码树以及各章 include 进行机械比对。

## 运行时不遗留状态

在前台运行普通加载器，并用 Ctrl-C 停止。其信号处理路径会销毁由骨架管理的链接和映射；除非某章明确讲解对象固定（pinning），否则不会固定任何对象。

特权冒烟测试调度器需显式选择启用，并接受明确的天数列表：

```bash
EBPF_LABS_ALLOW_PRIVILEGED=1 \
  sudo --preserve-env=EBPF_LABS_ALLOW_PRIVILEGED \
  ebpf/labs/scripts/smoke.sh day01 day14
```

脚本会管理自己创建的触发器、子进程 PID、临时文件、命名空间/veth、qdisc 和 cgroup，并按创建顺序的逆序清理它们。注册 TCP struct_ops 还需要 `EBPF_LABS_ALLOW_STRUCT_OPS=1`；替换 sched_ext 则需要 `EBPF_LABS_ALLOW_SCHED_EXT=1`。这两者都只能在一次性的兼容虚拟机上运行。托管 CI 只执行编译、链接、BTF 和锁定源代码构建；绝不进行特权挂载。
