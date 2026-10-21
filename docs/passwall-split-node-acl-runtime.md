# Passwall Lite B3.1：未接入的 ACL TCP/UDP 运行能力

基线：`7a439dda976681d72a4da81ee85d819cffef8ce5`。

## 边界与参考

新增 `acl_nodes.sh`，只定义函数；没有接入现有 `acl_app()`、init、LuCI、DNS、nftables 或 iptables。
不执行 UCI 迁移，不修改节点配置，两种核心的 Client/Server 生成器与服务端保持不变。
因此这些接口是供 B3.2/B3.3 后续接入的能力，不是当前固件已启用独立 ACL 的声明。

参考本地 main `1294c9aa` 的 `acl_app()`、`start_redir()`、`run_ipt2socks()`：
保留按协议分配端口、同节点合并和 `-T`/`-U` 分发；不复用其提前发布缓存、只凭节点 ID
继承端口或将 UDP 直接等同于 TCP 端口的做法。保留 Lite 的成功发布与失败隔离约束。

## 接口

调用方加载现有 app.sh/utils.sh 函数、B1 node_config.sh、B2 global_nodes.sh 和 acl_nodes.sh，
并持有现有生命周期锁。脚本不会自行加载 app.sh，也没有新增后台监控或另一套并发锁。

```sh
passwall_start_acl_nodes SID MODE USE_GLOBAL_CONFIG TCP_SELECTOR UDP_SELECTOR LOG_FLAG LOG_LEVEL
passwall_acl_node_ready SID tcp   # 或 udp；重新验证当前实例和监听
passwall_acl_protocol_state SID tcp EFFECTIVE_REQUESTED_NODE
passwall_stop_acl_nodes SID
```

启动返回 0=所请求能力成功或全部关闭；2=失败协议已安全隔离，其他成功绑定保留；
1=缓存、归属或清理状态不可信，调用方不得继续依据不可信状态生成规则。
停止返回 0/1；停止失败不伪装成成功，保留记录供重试。原有独立 SOCKS section 的 node 字段不变。

TCP/UDP 选择沿用 B1 五态；缺失表示关闭，不补默认。跟随 tcp 与显式同 ID 不写回 UCI，
解析结果中的 UDP_SELECTOR 保持两种选择语义。两种核心均支持任意业务协议角色。
MODE=0 在节点解析/校验和日志字段校验之前清理本 ACL 的新绑定并返回，不读取无用节点。
调用方必须预先按现有端口豁免策略计算有效 MODE，并负责 enabled 开关。

USE_GLOBAL_CONFIG=1 只继承通过 B2 ready 查询的协议，不读取 UCI 全局节点选择，也不补回失败协议。
原全局绑定释放后，只要 ACL 仍引用，实例继续存在；ACL 最后解绑后可回收已无引用的实例。
独立 ACL 不因节点 ID 与全局相同而自动继承 DNS 或 default。

### B3.2 协议状态消费契约

`passwall_acl_protocol_state SID tcp/udp EFFECTIVE_REQUESTED_NODE` 是只读查询，
不新增独立 ready 缓存标志。参数必须来自**本次 ACL 初始化的有效请求快照**，不能根据缺失端口构造：

| 请求及运行记录 | 输出 | B3.2 消费要求 |
| --- | --- | --- |
| 有效请求为空，且无协议绑定 | closed | 配置明确关闭；源匹配的直连豁免由 B3.2 实现 |
| 请求非空，无成功绑定或当前监听失效 | failed | 启动/运行失败；不得当成关闭、直连或自动继承全局 |
| 请求与节点/端口/instance 三字段一致，当前监听验证通过 | ready | 才能使用对应实例和端口生成转发规则 |
| 参数非法、三字段部分存在、请求与记录矛盾或缓存读取失败 | 返回 1，无状态输出 | 不能安全分类，必须阻断消费并诊断 |

成功分类返回 0；failed 是协议状态，不代表可以忽略初始化/清理的返回 1。
调用层必须先处理启动返回值：0 表示本次请求处理完成；2 表示某协议失败但隔离成功，可以继续处理其他 ready 协议；
1 表示状态不可信，不能让状态查询覆盖此错误。不要用缺少端口或 split_failed 反推 closed。
failed 的最终丢弃/隔离规则由 B3.2 决定，本轮不实现防火墙策略。

独立 ACL 用 B1 解析后的节点 ID；MODE=0 或端口策略明确关闭时传空；UDP 跟随先解析成真实节点 ID。
全局继承时，调用方须保留本轮全局启用状态和 B1 的完整请求快照，并结合 B2 启动结果，
不能只把成功缓存里的节点列表当作完整配置意图。全局某协议失败时，该协议仍为非空请求，查询结果为 failed。
继承启动返回 0 仅表示对**已验证成功的全局子集**完成绑定，不覆盖 B2 已报告的失败，不能据此把失败协议视为关闭。
这些参数与错误聚合是 B3.2 接入责任；B3.1 不读取全局 UCI 或新增全局启动入口。
全局后来换节点时，已存在 ACL 的查询使用其原初始化快照；新配置需要重新初始化，不能偷偷替换旧引用。

## 缓存、共享与生命周期

每个成功协议一次性发布：

- `ACL_${sid}_tcp_node` / `tcp_redir_port` / `tcp_instance` / `tcp_default`
- `ACL_${sid}_udp_node` / `udp_redir_port` / `udp_instance` / `udp_default`

instance 为实际 config.json 绝对路径。default=1 仅表示已继承的透明协议能力，独立实例不发布 default。
这里不发布 DNS 端口、源匹配、整体 enabled；B3.2 不得把上述 default 当成 DNS 已就绪证明。
`ACL_${sid}_split_failed=1` 为安全失败诊断，不代表所有协议均不可用；消费者须逐协议检查完整记录和 ready。
返回 1 必须阻断，不能仅看诊断字段或目录是否存在判断隔离成功。

独立实例位于 `${TMP_ACL_PATH}/split-acl/instance.XXXXXX`。meta 记录核心、节点、TCP/UDP 端口及创建者 SID；
context 记录 TCP 方式、IPv6、日志开关和级别，node.snapshot 记录节点的 UCI show 快照。
复用从现有完整成功绑定查找，核对绑定的节点/端口/instance，要求快照、context、所需监听能力均匹配；
只有 instance 字段而缺少节点或端口不能作为复用依据。没有独立 ready 标志或引用计数。
独立 ACL 仅自动复用 ACL 私有实例，全局复用通过显式继承接口进行。

同节点没有可复用能力时合并双协议；已存在两个独立单协议实例时可分别复用。
TCP-only 不能被当作 UDP-ready，新增协议不会重写或终止其他使用者的配置。
日志、地址族、监听方式、节点配置不兼容时另建实例；不为减少进程而强行共享。

发布前后均确认监听及 PID/启动时间；TCP 检查 LISTEN，UDP 检查对应 PID 持有的绑定 socket inode。
共享的合并实例任一必需监听失效时，ready 保守返回失败；发布后崩溃不自动重启，缓存不等于当前就绪。
缓存写入通过既有 set_cache_vars 分组 rename。发布期间退出则撤销本次协议；撤销失败返回硬错误并保留所有权记录。
回滚只使用本次明确创建的路径，不从节点共享缓存反查。共享实例发布失败只撤销本 ACL 绑定，不停止原使用者。

解绑先将本次精确实例路径原子保存为 `split-acl/release.SID`，再原子撤销本 ACL 的新字段，
最后检查已有 *_instance 引用；最后一个引用释放才停止。清单每个实例只记录一次，写入失败不撤销绑定。
原创建者退出后，最后共享者也可能负责清理；只有创建者 meta 和局部 released 变量不能保证失败重试。
停止失败保留清单，下一次调用从清单恢复路径（包括 B2 全局实例），不依赖原创建者或上次 Shell 的局部变量。
全部处理成功才删除清单；删除失败也返回 1，后续可对已消失的实例路径幂等重试。
仅收集本 ACL 创建的待重试实例和本次解绑的精确实例，不处理其他 ACL 的无绑定失败尝试。
Hysteria 按 client + config 路径停止，保留既有 FakeTCP 管理；SS 按 PID + 启动时间处理后端及 relay。
停止或规则回收失败保留实例记录并传播错误；旧单节点、DNS、SOCKS 和旧 acl_node_* 缓存不清理。

## SS 与 Hysteria 启动

Hysteria 继续调用原生成器和 start_hysteria，分别传 TCP/UDP 透明端口，并保留供后续 DNS 使用的原生 SOCKS。
udp/faketcp/wechat-video 外层传输与业务协议角色独立。既有 IPv6 + TCP REDIRECT 拒绝校验不放宽，IPv6 使用 TCP TPROXY。

SS 使用 `ss-local -c ... -v` 和 ipt2socks：

| 透明业务能力 | SS-local mode | ipt2socks |
| --- | --- | --- |
| TCP-only | tcp_only | -T |
| UDP-only | tcp_and_udp | -U |
| TCP/UDP | tcp_and_udp | 不加 -T/-U |

UDP-only 的 SS-local 不能用 udp_only：ipt2socks 的 UDP 路径先建立 SOCKS TCP 控制连接；
SS-local udp_only 不建立 TCP listener。该内部控制入口不发布为 TCP 透明代理能力。
依据：[SS-libev v3.3.5 local.c](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/local.c)
的 mode != UDP_ONLY 监听分支，以及
[ipt2socks udp_tproxy_recvmsg_cb](https://github.com/zfl9/ipt2socks/blob/master/src/ipt2socks.c) 的 TCP 协商路径。

relay 保留 `-b 0.0.0.0 -B ::`，TCP REDIRECT 使用 -R，TPROXY 不加 -R；IPv6 开启时额外检查 relay 的 TCP6/UDP6 归属。
为捕获本次进程身份和精确回滚，使用与现有 ln_run 相同的前台命令和 PID/birth/命令记录格式，
没有修改现有 run_socks/run_ipt2socks 的生产调用。每个私有实例的 socks_port 文件供后续依赖接入核对，
不据此宣称 DNS 或真实 SOCKS 数据面成功。B2 socket 辅助函数仅增加可选地址族过滤，旧调用默认行为不变。

## 测试与部署前提

`PASSWALL_B3_DOCKER=doocs/md:latest node tests/passwall-acl-nodes.cjs` 在一次性 Alpine 容器直接执行生产函数、
缓存 API、两个生成器和 Hysteria 管理器。LuaSocket 只提供前台监听夹具，真实 /proc、进程、socket、信号和配置目录参与验证。
SS、Hysteria、ipt2socks 的网络协议、iptables/ip6tables 操作和 nixio 锁仍为边界夹具，不能据此宣称真实数据面、内核规则或并发通过。
测试工具 lua5.1-socket 只安装在测试容器，不增加 OpenWrt 运行依赖。

覆盖：五态/两核心/混用/同核不同节点、跟随与显式 ID、IPv4/IPv6、协议能力不足、双实例复用、
日志/节点快照不兼容、共享解绑、全局部分成功继承及全局停止、配置/立即退出/监听/端口故障、
各缓存字段和继承 default 的原子发布、部分写入、发布期间退出、撤销/SS 清理/FakeTCP 规则清理失败及重试，
另一个 ACL、独立 SOCKS、旧缓存与连续启停隔离。既有 B2/B1/阶段 A/ACL/缓存回归独立执行。

B3.2 必须共同完成：源匹配及端口豁免与有效 MODE、两防火墙逐协议消费成功能力和错误分类、
TCP/UDP 两个远端绕行、DNS 与 SOCKS 依赖及继承发布。B3.3/后续再接入入口、LuCI 和配置迁移。
未完成这些依赖前不能部署或启用新链路。
两协议关闭和单协议关闭时仍须为匹配 ACL 的源生成相应豁免，不能因没有端口就意外落入全局代理规则。

剩余边界：PID 检查与信号不是内核原子操作，最后一次 ready 后仍可崩溃；不新增自动恢复。
节点 UCI 快照只是复用校验，不是配置写入锁；并发配置修改和生命周期调用须在后续接入边界协调。
现有 init 的 start/stop/restart 持有 passwall.lock，可作为受控调用的串行边界，但新接口本身不取该锁。
直接调用或另一个调用方绕过锁不受保护；Hysteria 的 registry 锁只保护其管理器，不能串行化整个缓存和 ACL 流程。
极端文件系统/进程身份不可读、同时无法持久记录与终止进程等故障需人工处理，不声称已安全回滚。
目标 ImmortalWrt 的真实两核心/ipt2socks、三外层传输、IPv6 数据面及 LAN/KMS DNS 仍需专项验收。

## 本轮验证记录

- B3.1 原生测试：Alpine 3.24.2 / BusyBox 1.37.0 / Lua 5.1.5 / LuaSocket 监听夹具；上述组合和故障注入通过。
  包括两个 SS 进程的 PID 记录部分写入、失败诊断写入失败、共享引用读取失败和清理重试。
- B2 原生进程/socket 回归通过；既有五组及 Hysteria2 清理、init 状态、临时探测清理通过。
- B1、阶段 A 真实 UCI、缓存生命周期、七项 ACL 及 nftables/iptables 错误传播回归在
  OpenWrt SNAPSHOT r37478-8975977f7a 的 BusyBox ash 中通过；不是目标 ImmortalWrt 数据面验证。
- Lua 5.1 语法检查 39 个文件（37 个生产文件及两个测试夹具）；15 个 Node 和 24 个 Shell 文件语法通过。
- app.sh、原 ACL 入口、两防火墙、DNS、LuCI、生成器、Hysteria 管理器、服务端、迁移和 Actions 与 HEAD 保持一致。
  新增文件 UTF-8、尾随空白及 git diff --check 通过；没有暂存、提交、推送。

### 最终审查补充

已用故障注入复现并修复“创建者 A 退出、最后引用者 B 停止失败后重试漏收”的缺陷；
原实现第二次返回 0，但实例目录和 SS 进程仍存在。增加外部精确释放清单后，非创建者及全局实例最后引用者均可重试。
补测清单写入/临时文件/rename/删除失败，SS 停止和 FakeTCP 规则删除失败、子 Shell 重试、
全局换节点但旧 ACL 保留、两个 ACL 逐个解绑、继承实例崩溃、TCP/UDP 各半失败及三状态查询。
本轮未接入 B3.2 规则或 DNS 流程。
