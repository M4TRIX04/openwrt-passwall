# B3.3-2：冻结端点、核心身份与监听地址族

本阶段是未接入生产入口的 B2/B3.1 适配层。`app.sh::start()`、
`acl_app()`、init、LuCI、DNS、正式 nftables/iptables hook 和服务端均未切换。
仅支持 SS-libev 与 Hysteria v1.3.5；FakeTCP 仍是 Hysteria 内部传输，
继续由同一个 `hysteria_runtime.lua` 管理。

## 接口与调用前提

调用方必须持有既有服务生命周期锁，加载 utils、B1、快照、B2、B3.1、
`bound_nodes.sh`，并设置 `PW_BOUND_HELPER` 为 `runtime_binding.lua`。
本阶段不增加生命周期锁、后台监控器或新成功缓存框架。

```sh
passwall_start_bound_global_nodes SNAPSHOT PREFERENCE FAMILY
passwall_start_bound_acl_nodes SNAPSHOT SID PREFERENCE FAMILY LOG LEVEL
```

`PREFERENCE` 为端点契约已有的 ipv4/ipv6/ipv4-only/ipv6-only；
`FAMILY` 为透明监听能力 4/6/dual，独立于端点地址族及 TCP/UDP 业务角色。
IPv6 TCP 必须使用 TPROXY。旧调用方不设置绑定上下文，继续原有行为。
停止与查询继续使用 B2/B3.1 原接口；绑定实例查询会额外执行实时核验。
关闭、ready、failed 和 0/2/1 分类继续沿用既有契约。
继承按冻结的请求判断：全局只成功一个协议时，ACL 可以继承这个成功能力，
但缺失的请求协议返回 failed/2，不能把它悄悄改成 Close。

`runtime_binding.lua` 提供 prepare、spawn、start_hysteria、verify、compatible、
owner、remote。CLI 为 prepare/spawn/hysteria/verify/seal/compatible/owner。
`verify DIR FAMILY PROTOCOL [PORT]` 可检查精确能力及端口；不接受仅 PID 存活的证明。
`firewall_endpoint.lua` 对绑定实例调用 remote；`split_firewall.sh` 的未挂接规则
在消费能力时使用相同实时校验，不再用 `/proc/net/tcp` 单表否定已证实的双栈 socket。
这不解除 B3.2 的 OUTPUT 冲突保护，也不安装新的 hook 或核心豁免规则。

## 冻结配置与端点

1. 入口在任何替换动作前执行 `passwall_snapshot_check`，拒绝旧配置快照。
2. 原生 UCI cursor 读取快照私有 package 的完整节点；原始 UCI 不写入。
3. 每个 snapshot/node/preference 只记录一次完整解析结果与确定性选择。
   多 A/AAAA 去重、选择、IPv4-mapped IPv6 拒绝沿用 B3.3-1。
4. 使用完整 `frozen_node` 调用现有 SS/Hysteria 客户端生成器；不只覆盖地址后
   再从 live UCI 读认证或 TLS 字段。未传此参数的旧生成调用不变。
5. 实际 JSON 使用固定 IP；Hysteria 保留原域名 SNI、Custom CA、严格证书验证、
   认证和 obfs。FakeTCP 不再独立解析或重写已冻结的 JSON。
6. 实例 binding.json 记录快照、端点、地址族、配置与端点清单摘要；
   bound.identity 关联 generation、PID/birth、路径及配置摘要。
   防火墙端点来自同一个 binding 与实际配置，不重新查询 DNS。
7. 同代重试继续使用原 IP；重新选择地址需要新快照代次。不同代次、端点或
   配置不能共享旧实例。同代兼容条件还包括既有日志、监听及协议能力约束。

bind/identity 是来源与所有权记录，不是永久 ready 证明。
`bound.capabilities` 只记录 seal 时通过的能力；后续查询仍核验活进程与 socket。
源文件、生成 JSON 或端点清单变化会使实例能力校验失败。

最终审查确认并修复两处本阶段缺陷：

- 绑定入口先验证 PREFERENCE/FAMILY，再进入已有停止/替换函数。
  修复前，非法参数可在生成器拒绝前撤下有效实例；回归验证返回 1 且原缓存、
  全局与 ACL 监听保持不变。
- owner 不再把 `pcall(alive)` 的任意异常解释为进程已死。
  只有 Hysteria 管理记录确实 ENOENT，且 /proc 证明原进程已退出/换代时，
  才允许完成上次停止后的目录回收。记录损坏、权限/读取错误均保留身份并返回错误。
  原生 nixio 的 stat 错误顺序是 nil/errno/message，回归同时检查拒绝错误清理
  和目录删除失败后的正常重试，不以“一律拒绝”冒充成功。

最终审查还在隔离容器中直接执行 HEAD 与工作区生成器的差分实验：108 个
Client 参数组合输出一致，冻结参数绕过 live UCI，Server JSON 比较一致。
这是一次审查实验；持久回归仍由原有生成器/Client-Server 测试与本阶段原生测试提供。

## 身份、监听与成功发布

核心通过生产 `api.exec_call_as_gid(..., 9911)`，在 exec 和 socket 创建前设置 GID。
Hysteria 继续经过统一运行管理器；SS ACL 的 ipt2socks 不承担外层核心身份，
其实际透明监听另行验证。SS UDP-only 的 SOCKS TCP 控制连接是辅助能力，
不会发布为 TCP 透明代理能力。

实时核验包含 PID/birth、非僵尸、实际 executable、核心全部线程 GID、
PID FD socket inode、FD GID、监听状态/端口、通配绑定地址与 socket options。
`ss --inet-sockopt` 提供 inet-diag 的 transparent 与 V6ONLY 证据：

- TCP REDIRECT 核验实际 TCP listener；TCP TPROXY 还必须有 transparent 属性。
- UDP TPROXY 必须有真实 UDP socket 和 transparent 属性。
- IPv6 必须获得 V6ONLY 属性；只有实际 V6ONLY=0 通配 socket 可证明双栈。
- 即使内核 socket 双栈，显式请求 IPv6-only 也只发布 IPv6 能力。
- 不可用、未知或诊断工具报错即拒绝发布，不退回进程或端口字符串判断。

需要目标系统具有支持 `--inet-sockopt` 的 `ss` 及内核 inet-diag。
OpenWrt 的 `ss` 是独立软件包，不能假设安装 ip-full 就存在它；
本轮没有修改 Makefile，B4 必须核实包和内核诊断依赖后才可启用。

seal 在既有原子缓存发布前保存身份；发布后再次检查活监听和快照。
发布失败按原有实例引用/回滚分类处理，回滚失败返回 1 并保留精确重试记录。
owner 检查不依赖仍然新鲜的 UCI，因此可清理已过期代次，但不得据旧 PID
杀死新实例。快照/端点清单在仍有实例引用时不得先删除；其回收时序留给集成。

## 真实测试证据与地址族矩阵

入口：`PASSWALL_BOUND_DOCKER=doocs/md:latest node tests/passwall-bound-nodes.cjs`。
测试只写一次性容器，仓库只读挂载，独立 PID/网络命名空间，不使用宿主网络。
也支持 `PASSWALL_BOUND_CONTAINER` 复用本任务预先准备的隔离实验容器。

工具链：原生 Lua 5.1/UCI/nixio；SS-libev 3.3.5-11 官方 OpenWrt 二进制，
Hysteria 官方 v1.3.5 二进制，ipt2socks 1.1.4-r2 官方 ImmortalWrt 二进制。
准备脚本验证 IPK 索引摘要和固定 Hysteria/ipt2socks SHA256，只解包到 /tmp，
不执行软件包安装脚本，不编译代理核心。测试 nixio 固定源码提交。
底层内核为 WSL2 6.18.54.1；nftables 1.1.6，iptables/ip6tables 1.8.13 nf_tables。

| 实际全局核心 | IPv4 TCP/UDP/合并 | IPv6 TCP/UDP/合并 | 单实例双栈 TCP | 单实例双栈 UDP/合并 |
|---|---|---|---|---|
| SS-libev ss-redir 3.3.5-11 | 通过 | 通过 | 通过 | 拒绝，未发布缓存 |
| Hysteria udp | 通过 | 通过 | 通过 | 通过 |
| Hysteria wechat-video | 通过 | 通过 | 通过 | 通过 |
| Hysteria faketcp | 通过 | 通过 | 通过 | 通过 |

这里“通过”表示实际进程、协议 socket 与必要 options 通过能力核验，
不能把全部矩阵都称为透明代理数据面验收。SS 该构建的 IPv6 UDP socket
V6ONLY=1，故不能从单个 ss-redir 宣称双栈 UDP。拒绝是安全降级，
不是把 SS 限制为 TCP 核心；IPv4/IPv6 单族均可承担 TCP/UDP。
ACL 的 ss-local + 真实 ipt2socks 路径也实际启动、核验和释放。
最终审查补充真实 SS ACL dual 检查：relay 分别持有 IPv4/IPv6 的 TCP/UDP
socket，按协议及地址族检查成功。这与单个 V6ONLY=0 socket 的双栈证明不同，
不意味着一个 ss-redir 的 IPv6-only UDP socket 可以宣称双栈。

真实传输另外验证：

- 两种防火墙前端、IPv4/IPv6、SS-local 与 Hysteria 三种模式：SOCKS TCP HTTP
  与 SOCKS UDP echo 成功；9911 规则计数增加，同一端点的普通 GID 流量命中 DROP。
- SS-redir 与 Hysteria 的 IPv4 TCP REDIRECT 实际 HTTP 转发成功。
  测试目标使用命名空间内基准地址：官方 Hysteria TCPRedirect 明确拒绝 loopback
  原始目的地址，不能用这种夹具失败推断实现不兼容。
- 实际 Hysteria FakeTCP PID 持有 raw socket，FD GID=9911；双地址族 TTL/HL
  filter DROP 规则和非零计数仍存在，早期 GID RETURN 未绕过它们。
- 错误 GID 的真实核心、诊断失败、实际进程死亡、缓存发布/撤销失败、
  FakeTCP 删除/查询失败、共享引用释放、新代端点切换及跨代清理均有故障注入。
  验证下游不能消费失败能力，并且其他 ACL 存活、记录可重试。
- 原生产调用函数与生成器直接执行；原生测试 API 禁止 live UCI 生成器读取。
  netfilter 实验规则用于核实实际核心身份，不等于 B3.2/B3.3 完整生产 hook。
- 最终审查新增：活核心 + 管理记录缺失 + /proc 读失败、stat 权限错误、损坏记录
  + 进程退出、目录删除失败重试、非法入口参数不改变有效实例，以及把旧代身份
  放到新实例路径时清理必须拒绝。两处缺陷均先复现失败，再修复复测。

## 未完成的集成与设备验证

1. B3.3-3/4：OUTPUT 核心身份与正式链拓扑、策略路由、DNS/SOCKS 归属、
   规则代次挂接/撤销、端点及快照最终回收仍未接入。
2. B4：服务锁并不锁 LuCI/外部 UCI 写入；前后 freshness 检查不能消除 ABA
   并发编辑。必须完成写入隔离后才能部署，不新增通用事务框架。
   当前快照不冻结 CA 文件字节或其他包的 network/dhcp 配置；其变更归属需在集成时明确。
3. B5：目标 ImmortalWrt、实体硬件、公网 FakeTCP、真实多网卡/路由、legacy
   iptables、完整 IPv4/IPv6 TCP/UDP TPROXY 数据面、LAN DNS/KMS 专项仍待验证。
   本轮本机私有命名空间的真实核心证据不能替代这些验收。
4. SS 单 ss-redir 双栈 UDP 的不足需要在集成前确定成熟的监听方案，不能伪造能力，
   也不在本轮建立额外管理框架。缺 ss/内核诊断时新路径明确拒绝启动。
5. B3.2 历史并行测试偶发 `cannot stop owned process`：本轮两个并行隔离测试任务及
   完整相关回归未复现，根因仍未定位，保持未解决。仅增加原有清理异常的
   PID/birth/TERM/KILL 诊断；没有增加等待时间或放宽断言。
   最终审查又执行一次双容器并行复跑，两者均通过 68 项断言。
   夹具 PID/网络命名空间分离，端口不映射，目录/缓存/注册表在各自容器内；
   未发现跨任务共享这些资源的证据。宿主调度负载对等待窗口的影响尚未证实，
   不能因此将历史失败归因于资源竞争或宣称已解决。
6. B4 正式切换前继续审查 SS-Rust、SSR、Naive 等历史生产入口可达性；
   本轮未清理这些核心，没有用新模块的双核心白名单代替旧入口审查。

源码依据：[Hysteria v1.3.5 TCPRedirect](https://github.com/apernet/hysteria/blob/v1.3.5/app/redirect/tcp_linux.go)、
[客户端配置及传输](https://github.com/apernet/hysteria/blob/v1.3.5/app/cmd/client.go)、
[SS-libev v3.3.5 redir](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/redir.c)、
[Linux inet_diag 属性](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/inet_diag.h)、
[OpenWrt 24.10 ss 包](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/network/utils/iproute2/Makefile)。
