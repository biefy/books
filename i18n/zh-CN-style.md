# 简体中文翻译规范

本规范适用于 `linux-net/src.zh-CN/` 与 `ebpf/src.zh-CN/`。目标是准确、自然地翻译技术叙述，同时让命令、源码和可验证的技术标识与英文原文严格同步。

## 基本规则

- 使用简体中文与中国大陆通行标点。正文采用自然、直接的技术中文，不逐词硬译，也不擅自增删结论。
- 标题、段落、列表、表格说明、图片替代文本和面向读者的提示语必须翻译。
- 保持原文的 Markdown 层级、页面顺序、链接目标和图片文件名。可以翻译链接文字与图片替代文本。
- 以下内容必须逐字保留：围栏代码块（包括围栏、语言标记与块内空白）、`{{#include ...}}` 指令、URL、内核符号、API 名称、命令、文件路径，以及反引号内的文本。
- 不翻译或改写程序输出、日志、报错、协议字段、配置键、命令行选项、环境变量和单位缩写。
- 英文与中文之间通常留一个半角空格，例如“通过 `bpf()` 加载程序”；中文标点前后不加空格。
- 首次出现容易歧义的术语时可写作“中文（English）”，后文使用本表约定。业内通常直接使用英文缩写的术语不强行展开。
- `Linux`、`eBPF`、`BPF`、`TCP`、`XDP`、`NAPI`、`BTF`、`CO-RE` 等专名保持原有大小写。
- 不使用机器翻译占位文本，不把英文页面复制到中文目录，也不以少量中文标题掩盖未翻译的正文。

## 必须保持字面不变的示例

```text
`struct sk_buff`
`net/ipv4/tcp_input.c:123`
`bpf_map_lookup_elem()`
`sudo bpftool prog list`
https://docs.kernel.org/
{{#include ../labs/day01/trace.bpf.c:book}}
```

围栏代码必须与英文页完全一致；即使代码中的注释是英文，也不能在翻译页中直接修改。需要解释时，在代码块外增加与原文等价的中文叙述。

## 术语表

| English | 简体中文 | 说明 |
|---|---|---|
| packet | 数据包 | 不使用“封包” |
| frame | 帧 | 特指二层帧 |
| segment | 报文段 | TCP 语境；分段动作译为“分段” |
| datagram | 数据报 | UDP/IP 语境 |
| socket | 套接字 | 标识符中的 `socket` 保持不变 |
| network stack | 网络协议栈 | 可按语境简称“协议栈” |
| receive path / RX path | 接收路径 / RX 路径 | RX 保持大写 |
| transmit path / TX path | 发送路径 / TX 路径 | TX 保持大写 |
| ingress / egress | 入站 / 出站 | 作为钩子名时保留原符号 |
| wire | 线路 | 表示物理网络一侧时使用 |
| network namespace | 网络命名空间 | `netns` 保持不变 |
| routing | 路由 |  |
| forwarding | 转发 |  |
| neighbour subsystem | 邻居子系统 | 采用内核英式拼写时原符号不变 |
| congestion control | 拥塞控制 |  |
| retransmission | 重传 |  |
| checksum | 校验和 |  |
| offload | 卸载 | 例如“分段卸载” |
| segmentation | 分段 |  |
| coalescing | 合并 | GRO 语境 |
| queue | 队列 |  |
| queueing discipline | 队列规则 | 首次可写“队列规则（qdisc）” |
| traffic control | 流量控制 | `tc` 保持不变 |
| rate limiting | 速率限制 |  |
| flow | 流 |  |
| flow steering | 流量引导 |  |
| hash table | 哈希表 | 统一使用“哈希” |
| lookup | 查找 | 作为函数名的一部分不翻译 |
| hook | 钩子 |  |
| callback | 回调函数 |  |
| fast path / slow path | 快速路径 / 慢速路径 |  |
| zero-copy | 零拷贝 |  |
| copy-on-write | 写时复制 | 首次可附 `COW` |
| reference count | 引用计数 |  |
| lifetime | 生命周期 |  |
| ownership | 所有权 |  |
| race condition | 竞态条件 |  |
| lockless | 无锁 |  |
| memory barrier | 内存屏障 |  |
| cache line | 缓存行 |  |
| userspace | 用户空间 | 统一使用“空间” |
| kernel space | 内核空间 |  |
| system call | 系统调用 |  |
| tracepoint | 跟踪点 | 标识符保持不变 |
| probe | 探针 |  |
| verifier | 验证器 | eBPF Verifier 统一译为“验证器” |
| program type | 程序类型 |  |
| attach type | 挂载类型 | attach 作动词时译“挂载” |
| helper | 辅助函数 | BPF helper |
| kfunc | kfunc | 不翻译；可解释为内核函数接口 |
| map | 映射 | BPF map；标识符保持不变 |
| ring buffer | 环形缓冲区 | `ringbuf` 保持不变 |
| per-CPU | 每 CPU | 保留连字符形式仅用于英文标识 |
| tail call | 尾调用 |  |
| trampoline | 跳板 | BPF tracing 语境 |
| relocation | 重定位 |  |
| type information | 类型信息 |  |
| bytecode | 字节码 |  |
| JIT compilation | JIT 编译 |  |
| bounded loop | 有界循环 |  |
| pointer arithmetic | 指针运算 |  |
| out of bounds | 越界 |  |
| state machine | 状态机 |  |
| scheduler | 调度器 |  |
| scheduling class | 调度类 |  |
| run queue | 运行队列 |  |
| task | 任务 | 指 `task_struct` 时符号保持不变 |
| wakeup | 唤醒 |  |
| latency | 延迟 |  |
| throughput | 吞吐量 |  |
| benchmark | 基准测试 |  |
| observability | 可观测性 |  |
| troubleshooting | 故障排查 |  |
| capstone | 综合项目 | 章节标题中使用 |

## 校验流程

翻译或同步页面后运行：

```bash
python3 scripts/check-i18n.py check
python3 scripts/check-i18n.py update-lock
```

先用 `check` 修复结构与字面内容差异。确认译文已经吸收对应英文改动后，才运行 `update-lock` 更新源文件哈希；更新锁文件不能代替人工同步译文。
