# 冻结运行适配层：B3.3-2、B1 与 Global SOCKS F1

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
owner、remote。CLI 为 prepare/spawn/hysteria/verify/seal/compatible/reference/owner。
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

seal 在新实例创建路径、既有原子缓存发布前保存身份。
Global 与 ACL 的 publish 本身不 seal；发布前后均执行完整只读 reference，
重复 publish、共享及继承不会补写缺失的封存记录。
发布失败按原有实例引用/回滚分类处理，回滚失败返回 1 并保留精确重试记录。
owner 检查不依赖仍然新鲜的 UCI，因此可清理已过期代次，但不得据旧 PID
杀死新实例。快照/端点清单在仍有实例引用时不得先删除；其回收时序留给集成。

## B3.3-3C-1B-A：可选 SOCKS TCP socket 声明

本节记录 A 阶段建立的共同 socket 核验基础。当前工作区的 F1 已使用该基础
在冻结 Global 路径中实现 SOCKS：Hysteria 使用主进程，SS 使用附属 ss-local，
具体身份与回收边界见下文 F1。正式生产入口（`app.sh`、`init.d/passwall`、LuCI）
仍未接入冻结运行路径；不能将工作区实现等同于生产已启用或运行验收通过。

`prepare` 的参数 JSON 可显式带 `socks_tcp_socket`。它在生成前被移出生成器输入，
只作为冻结绑定元数据；**不会自动配置或启动 listener**。格式固定为：

```json
{"address":"127.0.0.1","protocol":"tcp","family":"4","port":11100}
```

- `port` 必须为 1–65535 的 JSON 整数；四个字段均必需，不接受额外字段、PID 或附属角色。
- 声明写入 `binding.json.socks_tcp_socket`。它必须与现有 SS 本地 TCP 配置或
  Hysteria v1.3.5 的 `socks5.listen` 一致；`socks_port` 文件也必须逐值匹配。
- 仅绑定当前主进程，复用其 PID/birth、实际 executable、全线程 GID 及 FD GID 核验。
  通过现有 socket inode/inet-diag 路径检查该 PID 持有的 **IPv4 TCP LISTEN**，
  地址精确等于 `127.0.0.1`、端口等于声明值。通配地址、IPv6、UDP、其他 PID 的 socket 均不能满足。
- 成功时首次 seal 增加 `bound.capabilities.socks_tcp_socket = {"4":true}`；
  透明能力仍位于既有 `tcp`/`udp`，仍按既有通配地址、transparent、V6ONLY 和 family 规则验证。
  `verify` 的透明协议参数仍只接受 `tcp`/`udp`，不能用 SOCKS socket 冒充透明 TCP。
- 首次 seal 前必须取得全部声明 socket 及透明能力证据；任何一项失败均不发布。
  `reference DIR SNAPSHOT PREFERENCE FAMILY` 重验来源、代次、配置、身份、实时能力，
  并比较完整封存能力记录；缺失、不兼容、格式错误或不一致均拒绝，不重新 seal、不修复记录。
- 未声明的旧实例保持原来的 binding/capabilities 格式及核验路径。
  即使配置已有 SOCKS（如既有 ACL），也不自动新增能力字段；只读 reference 不升级记录。
  声明存在而封存项缺失，或无声明却额外出现该封存项，均拒绝。

此记录只证明 TCP socket，**不证明 SOCKS5 方法协商、外层连接或真实 DNS 转发**；
3B 的真实协商与精确连接归属探针保持不变，不产生 `dep_ready`。
F1 仅在新建冻结实例时加入声明，不能给已发布实例追加声明或升级其格式。

隔离测试仍使用 `tests/passwall-bound-immutability.cjs`，其新增
`tests/shell-bound-socket.sh` 保留显式声明的 ACL 夹具，并补充 F1 冻结 Global
路径的覆盖。夹具 socket 成功不能替代 Global 路径的证据；静态检查、原生隔离
测试和目标设备验收须分别报告。本轮仅更新测试代码，未执行这些检查或测试。

## B3.3-3C-1B-B1：严格引用与有限回滚修复

B1 提供严格引用与有限回滚基础；当前工作区同时包含下文 F1 的 Global SOCKS
实现。两者均未接入正式生产入口，不涉及 DNS helper 的创建或 `dep_ready` 发布。

- 3B 在 SOCKS5 协商前后均调用 `compatible(..., true)`，与 CLI `reference`
  使用同一完整封存核验；仍保留按 TCP 端口/family 的实时核验和真实方法协商。
  缺失、损坏或不匹配的 `bound.capabilities` 返回 `1 / dns_dep_identity`，
  失败时不保留候选 state、不补 seal。旧格式不要求新增 SOCKS 声明。
  严格引用提前发现的既有 `socks_port` 缺失/不一致仍映射为
  `2 / dns_dep_socks`；身份或能力封存错误不因此降级。
- Global 创建函数用局部标志区分私有创建与已经进入 publish 的尝试。
  私有失败沿用精确实例回收；进入 publish 后，必须得到既有引用扫描的
  “确认无引用”结果才可终止。共享引用、引用读取失败、缓存类型/语法异常
  或悬空链接均保留实例并返回 `1`；撤销失败的私有 `3` 仍转公开 `1`。
  不改原子协议元组、不撤销 ACL 或另一独立协议、不增加持久状态机。
- SS stop 不再用布尔 alive 的失败证明退出。专用只读 Lua 5.1 观察使用
  `io.open` 的独立 errno，区分同一活 PID/birth、确认 ENOENT、PID 重用、
  僵尸和未知；检查前先确认当前 `/proc` 视图可读。未知或读/解析失败时
  返回停止失败，保留责任。每次 TERM/KILL 前及轮询中使用相同观察，
  PID 重用不发送信号，等待次数和 sleep 时长不增加。
  ACL 继续共用该 stop/kill 路径；不修改启动命令、process 或封存格式。

创建期 process 记录部分写失败，仍只可使用本次启动的内存 PID/birth 回滚。
PID 回执完全丢失时，现有启动路径不能证明精确 PID 已归属或已清理；返回 `1`
并保留责任目录，不按进程名猜测或误报成功。隔离测试可由测试观察者清理，
不代表产品已具备该故障的自动恢复。PID 检查与发信号仍有既有非原子窗口。

测试复用 DNS、bound、immutability 入口；`PASSWALL_BOUND_B1=rollback|stop`
选择 `tests/shell-bound-b1.sh` 的专用故障组。读取失败在实际 I/O 边界注入并
检查命中，不以 root 下无效的 chmod 作为证据。隔离结果不替代 OpenWrt 目标
设备验收、完整 DNS/helper 验收或生产入口接入。

B1 历史隔离记录（2026-10-23，不代表当前 B1+F1 候选通过）：专项 rollback/stop、完整 DNS dependency、
immutability/socket、完整 bound 运行回归及非 bound Global/ACL 回归最终均
退出 `0`。当时使用从官方 Alpine 3.24 准备的依赖，测试容器网络为 `none`、
仓库只读挂载、PID/网络命名空间独立，无生产配置挂载。非 bound 回归新增
`PASSWALL_B2_CONTAINER` / `PASSWALL_B3_CONTAINER` 入口复用已准备容器，
避免测试期联网安装，原测试逻辑不变。完整 bound 回归包含私有命名空间内
真实 SOCKS TCP/UDP 与 IPv4 REDIRECT 数据转发；DNS 组仅验证候选/方法协商，
未运行 DNS helper、dnsmasq L1/L2/L3 或目标设备验收。

## Global SOCKS F1 与 B1+F1-C1 配套修正

**已验证事实（源码）**：当前工作区在 `PW_BOUND_SNAPSHOT` 非空且实例具有透明
TCP 角色时分配独立的内部 IPv4 loopback TCP SOCKS 端口。UDP-only 不声明该
能力；不写生产 `GLOBAL_SOCKS_server`，不调用 live-UCI `run_socks`。

- Hysteria 的 `socks_tcp_socket` 对应同一冻结配置中的 `socks5.listen`，复用主
  进程身份。SS 保持 ss-redir 主进程，在同一实例的 `socks/` 下生成冻结的
  `tcp_only` ss-local 配置，使用相同冻结节点、端点、认证和 GID 9911。
- SS 的 `binding.json.ss_socks` 记录 socket 声明及附属配置摘要，
  `socks/process` 与 `socks/bound.identity` 绑定该附属 PID/birth、配置路径和
  同一代次。它不形成独立引用或资源生命周期。
- 首次 seal 和只读 reference 均核验主/附属身份、配置摘要、实际 executable、
  全线程与 FD GID，以及精确属于该进程的 `127.0.0.1` TCP LISTEN。
  封存能力仍为 `socks_tcp_socket={"4":true}`，不替代透明 TCP/UDP 能力。
- Global/继承 ACL 继续共享同一封存实例。停止先检查既有所有权和引用边界，
  SS 先停止附属进程再停止主进程；不确定时保留责任，最后一个引用释放才回收。
- DNS dependency 只读查询可产生 Global 或继承 Global 的 `dep_resolved` /
  `dep_validated` 候选；SS 候选额外绑定附属配置/身份摘要，真实 SOCKS5 无认证
  协商使用附属 PID，Hysteria 使用主 PID。仍未实现 DNS helper、dnsmasq 衔接
  或 `dep_ready`，也不以方法协商证明外层连接、真实 DNS 查询或数据转发。

**失败回收分析（源码，尚待故障实测）**：`_pw_global_ss_socks_start` 在调用
spawn 前设置 `PW_GLOBAL_NEW_SOCKS_STARTED=1`，含义是“已尝试启动”。取得有效
PID/birth 后的 process 写失败可使用本次内存回执停止附属进程，再由既有私有
owner 门禁核验并回收主进程和目录，不改变正常成功路径。

spawn 可能在子进程已经启动后丢失回执；此时附属 PID/birth 未取得，现有
`private-owner` 拒绝回滚，返回 `1` 并保留责任目录，主/附属进程可能留存。
仅把 STARTED 移到 spawn 成功之后会错误允许“未启动”清理，不能安全解决该
路径。要区分确定未启动与已启动但回执丢失，需扩展启动器回执契约，涉及
`runtime_binding.lua` / 启动器边界，超出本轮生产代码授权，因此 C1 未修改
`global_nodes.sh`。此限制不得记为已自动回收；测试观察者的精确 PID 清理也
不得作为产品恢复能力。

C1 复用 `tests/passwall-bound-immutability.cjs`（包含 socket 组）和
`tests/passwall-dns-dependency.cjs`：更新过时断言，扩展原 JSON 夹具以支持 F1
嵌套声明，保留不可变性、严格引用和未接生产入口检查。新增 SS 附属身份、
Global TCP-only/UDP-only 边界、共享与停止保护、首次 seal 失败时双进程回收、
附属 process 部分写失败以及 spawn 回执丢失时的责任保留断言。

**本轮未执行测试、语法检查、构建、容器启动或部署**。后续需另行授权，在
仓库只读挂载、独立 PID/网络命名空间的一次性已准备容器内运行上述两入口；
不可仅凭没有设置容器变量时的 SKIP 判断通过。历史 B1 结果不能替代本候选
验证。当前具备进入定向测试的代码准备条件，尚非通过验证的提交结论。

**范围外的夹具限制（源码已确认）**：完整 bound / B1 专项入口
`tests/passwall-bound-nodes.cjs` 直接使用 `tests/shell-bound-nodes.sh` 的平铺 JSON
夹具，未提供 F1 所需的 `json_add_object` / `json_add_int` / `json_close_object`。
C1 只在获准修改的 immutability 与 DNS 测试中扩展该夹具；未修改上述共用
文件或 B1 专项。完整入口仍需先补齐夹具再回归，不能据两项定向入口的准备
情况宣布整个提交候选已自洽。

## 真实测试证据与地址族矩阵

本节为既有阶段的历史运行记录，不是本轮 B1+F1-C1 的验证结果。

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
