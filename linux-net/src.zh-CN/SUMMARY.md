# 目录

[简介](README.md)

---

# 阶段 1：基础

- [第1天 — sk_buff：通用数据包容器](day01.md)
- [第2天 — RX 路径：从 NAPI 到 ip_rcv](day02.md)
- [第3天 — TX 路径：从 sendmsg 到线路](day03.md)
- [第4天 — GRO、GSO、TSO：分段卸载](day04.md)
- [第5天 — 网络命名空间与 struct net](day05.md)

# 阶段 2：L2 和 L3

- [第6天 — 以太网、VLAN 与 L2 层](day06.md)
- [第7天 — ARP 与邻居子系统](day07.md)
- [第8天 — IP 路由：FIB](day08.md)
- [第9天 — 多路径、策略路由与基于源地址的路由](day09.md)
- [第10天 — IPv6 特有机制：NDP、自动配置与扩展头](day10.md)
- [第11天 — 网桥子系统](day11.md)
- [第12天 — 隧道：VXLAN、GRE、IPIP、WireGuard](day12.md)

# 阶段 3：L4

- [第13天 — 套接字层：struct sock](day13.md)
- [第14天 — UDP：简单的协议](day14.md)
- [第15天 — TCP 状态机](day15.md)
- [第16天 — TCP 拥塞控制：CUBIC、BBR 与框架](day16.md)
- [第17天 — TCP 重传、RACK、FACK 与恢复](day17.md)
- [第18天 — 套接字选项：逐套接字调优](day18.md)
- [第19天 — 用于套接字的 epoll 与 io_uring](day19.md)

# 阶段 4：子系统

- [第20天 — Netfilter 钩子](day20.md)
- [第21天 — nftables 与 iptables 对比](day21.md)
- [第22天 — Conntrack：有状态防火墙](day22.md)
- [第23天 — 流量控制：qdisc、类与 fq_codel](day23.md)
- [第24天 — SO_REUSEPORT 与套接字流量引导](day24.md)
- [第25天 — kTLS：内核内传输加密](day25.md)
- [第26天 — MPTCP：2026 年的多路径 TCP](day26.md)

# 阶段 5：现代特性与综合项目

- [第27天 — XDP 与协议栈的其余部分](day27.md)
- [第28天 — io_uring 网络：零拷贝发送/接收](day28.md)
- [第29天 — 近期新增特性：PSP、drop_monitor、devlink、NETLINK](day29.md)
- [第30天 — 综合项目：端到端跟踪一个数据包](day30.md)
