# Passwall Lite B3.2：未挂接的 TCP/UDP 防火墙规则

基线为 `07c685ec3b0cf7dad9c918d21d1287769a48dc54`。

## 实施边界

新增 `split_firewall.sh` 只定义函数。app.sh、acl_app、原 nftables.sh/iptables.sh、
init、LuCI、DNS、UCI 迁移以及两种核心的 Client/Server 均未修改。
新链没有 hook，也不向已有链插入 jump/goto；安装新链不会改变当前固件的数据面。
没有修改 Hysteria 管理器或 FakeTCP 规则。回收只删除本候选明确拥有的新链，不停止代理实例。

本地 main `1294c9aa` 的参考位置：nftables.sh/iptables.sh 的 `load_acl`、
`add_firewall_rule`、`filter_node`、`filter_server_port`。复用按协议端口、
ACL 顺序及结束 RETURN、本机标记/回环 TPROXY、IPv4 TCP REDIRECT、IPv6 TPROXY、
白名单/黑名单/GFW/国内 IP 和端口策略的结构，不复制整份脚本或退休核心分支。
原实现的节点 ID/端口缓存不能替代 B2/B3.1 的当前能力校验。

## B3.3 可调用接口

调用方应在同一 Shell 中持有现有 Passwall 生命周期锁，提供 B1/B2/B3.1、缓存 API、
`lua`、`echolog` 及 api/Hysteria 注册表已经依赖的 md5sum，并设置：

```sh
PW_FW_ENDPOINT_HELPER=/usr/lib/lua/luci/passwall/firewall_endpoint.lua
passwall_fw_begin nft tproxy 1   # backend=nft/iptables, TCP way, inner IPv6=0/1
dir=$PW_FW_DIR
passwall_fw_policy "$dir" SID TCP_NO UDP_NO TCP_DROP UDP_DROP TCP_REDIR UDP_REDIR \
    DIRECT PROXY BLOCK GFW CHN TCP_MODE UDP_MODE BLACK4 BLACK6 GFW_BASE
passwall_fw_acl "$dir" SID ENABLED MODE INIT_STATUS RESOLVED_TCP RESOLVED_UDP SOURCE [DEVICE]
# 所有 ACL 按 UCI 顺序处理完，最后添加一次全局/默认客户端及 OUTPUT：
passwall_fw_global "$dir" INIT_STATUS RESOLVED_TCP RESOLVED_UDP CLIENT_ENABLED OUTPUT_ENABLED
passwall_fw_seal "$dir"
passwall_fw_apply "$dir"
passwall_fw_discard "$dir"      # 仅在尚未挂接，或由未来调用方先解除挂接之后调用
```

`passwall_fw_policy` 的端口取值沿用 disable、单端口、冒号范围、逗号列表；
四个名单开关取 0/1，CHN 取 0/direct/proxy，代理模式取 proxy/disable。
BLACK4/BLACK6 是作用域的动态代理集合名称，GFW_BASE 的 IPv6 名称追加 6。
例如全局为 psw_black、psw_black6、psw_gfw；独立 ACL 可使用现有 psw_SID_black 等名称。
接口不读取节点选择，也不设置缺失协议默认值；跟随 TCP 必须先由 B1 解析成实际 ID，
原始选择语义仍由配置层保存。独立 SOCKS section 不受影响。

SOURCE 支持 any、ip:IPv4/IPv6/CIDR、mac:MAC、ipset 对应的 set:NAME、iprange:IPv4-IPv4；
可选 DEVICE 是已经解析出的内核设备名，不在规则层重新解析 UCI interface。
同一 ACL 多个源调用多次，属于相同的协议请求快照。禁用 ACL 直接跳过，不能变成关闭 ACL。
调用方对任何返回 1 都必须放弃候选，不能忽略错误继续挂接。

DNS 的直接前置条件可通过以下只读接口检查：

```sh
passwall_fw_check_dns "$dir" global GLOBAL tcp NODE 4  # 或 udp、目标地址族 6
passwall_fw_check_dns "$dir" acl SID socks NODE
passwall_fw_check_dns "$dir" global GLOBAL local ''
```

这里只证明实际透明协议或 B3.1 原生 SOCKS 的前置能力，不证明 DNS helper 已启动。
缺少必要协议或原生 SOCKS 时明确诊断并使候选不可用；不会以另一种协议的透明端口顶替 DNS/SOCKS 端口。
本地 DNS 模式不要求代理能力。实际 DNS 模式、目标地址族和 helper 就绪由 B4 的调用方提供，
不能因为未调用这个可选检查就宣称 DNS 已适配。

## 状态和匹配顺序

| 输入/查询结果 | 新规则语义 |
| --- | --- |
| ENABLED=0 | 完全跳过，该源继续匹配后续 ACL 或默认客户端 |
| MODE=0 | 不读取或校验无用节点，两个协议显式关闭 |
| closed | 源和协议匹配后 RETURN，不能落入本分发链后面的全局代理 |
| failed | mangle DROP；不尝试直连、不从旧端口或另一协议补齐 |
| ready | 完整节点/端口/config 记录 + 当前身份/监听成功才转发 |
| 查询返回 1、初始化返回 1、部分记录、必需写入失败 | 候选不可安装，不生成可挂接的成功标志 |
| 初始化返回 2 | 只消费实际 ready 的协议，失败协议 DROP；其他 ACL 和全局继续生成 |

每条链先保留本地/LAN/WAN、回复方向、核心自带 mark 豁免等基础返回，
仅 OUTPUT 保留实际节点远端绕行，PREROUTING 不再先行豁免这些公网端点。
本机已标记回环在 LAN ACL 之前进入对应全局监听，
其余回环不进入 LAN ACL。随后是按顺序的 ACL，最后才是默认客户端。
关闭/失败都按整个匹配协议结束，只有 ready 协议再应用端口及目的集合策略。
ready 内部顺序为不代理端口、屏蔽、直连、代理/GFW、国内规则、默认代理、最终 RETURN。
失败隔离优先于普通目的策略，但保留前述本地基础设施豁免。
OUTPUT 如果某失败协议恰好也是成功核心的外层协议，仅凭 IP/端口不能区别核心与普通本机流量，
候选会明确拒绝安装；本轮不通过引入 UID、socket mark 或修改核心启动规避此限制。

iptables 的 nat 表不能 DROP，因此 IPv4 TCP REDIRECT 在 mangle 中先执行相同选择顺序的
丢弃/返回策略，nat 中只执行 REDIRECT/RETURN。TPROXY 在 mangle，OUTPUT 使用标记及
CONNMARK，回环按协议的真实全局端口接入。nft 使用 mark/ct mark 和 tproxy ip/ip6。
nft TPROXY 成功后 ACCEPT，紧接着的同条件 DROP 专门接住无可用透明 socket 的 NFT_BREAK。
iptables TPROXY 本身在无 socket 时 DROP，不能用相同的“始终转发成功”夹具代替两者。
nft 的静态集合与动态集合分别匹配；iptables 沿用原有已汇总的 ipset。
不生成 Hysteria 自身 ACL、FakeDNS、_shunt 或其他退休核心规则。

## 地址族、远端与生命周期

每个候选位于 `${TMP_PATH}/split-fw/generation.XXXXXX`，链前缀为 PWL 加随机后缀。
P4/O4 是 IPv4 mangle PREROUTING/OUTPUT，N4/R4 是 IPv4 nat PREROUTING/OUTPUT，
P6/O6 是 IPv6 mangle。所有链都是无 hook 的普通链。
没有创建/删除集合、DNS 链、策略路由、旧 PSW 链或其他代次的链。

只读取运行实例 JSON 中的 endpoint，不重新读取可能已编辑的 UCI address/port。
SS 按真实业务 TCP/UDP 绕行；Hysteria 按 protocol，FakeTCP 绕行 TCP，udp/wechat-video 绕行 UDP，
与业务协议角色无关。不同节点独立处理；同一上游元组去重，不按 TCP 节点机械生成 UDP 远端。
IPv6 外层远端在业务 IPv6 关闭时也需要 IPv6 OUTPUT 规则及对应后端能力。
未固定解析地址的域名当前明确拒绝生成/安装：独立 get_host_ip 的首地址查询无法证明与
核心实际选择的 A/AAAA、重试及轮换一致。没有实现新的解析器、修改 DNS 或修改运行实例 JSON。

B2/B3.1 ready 查询之后，额外核对进程 PID/启动时间及其持有的指定地址族 socket inode。
SS ACL 检查 relay 的 socket，不能把 SOCKS TCP 控制连接当成 TCP 透明监听。
Hysteria 只读现有运行记录，仍先经过其现有 ready 查询，不绕过管理器或更改所有权。
各地址族的结果及配置文件 MD5 会保存在候选快照中，seal、apply 前后再次核对；
运行 JSON 地址改动但节点 ID/端口未变时也拒绝安装。空或不完整的全局检查记录不能通过。
仅某地址族监听缺失时，该地址族失败隔离；不凭 PROXY_IPV6 或 generic ready 直接转发。

**已确认的后续依赖**：B2 全局 SS 当前 local_addr=0.0.0.0；它本身不保证 IPv6 listener。
IPv6 socket 可能具有 IPv4 双栈能力，但 /proc 的 tcp6/udp6 条目本身不能证明 IPV6_V6ONLY 状态。
本轮保守要求明确的地址族 socket；无法证明的地址族 DROP 并诊断，而不是推测双栈成功。
B4 必须协调真正的双栈监听/验证方法，不能直接启用新链并宣称 SS/Hysteria 双栈数据面完整。
当前 LuaSocket 夹具明确使用 V6ONLY，验证了这个隔离边界，不替代目标二进制双栈测试。

候选生成任一步失败后不可继续安装。seal 完整落盘后才允许 apply；先查询完整链清单，
确认随机链名没有外部预存对象，然后写 pending 所有权记录，才执行安装。
nft 以一个 batch 安装；iptables 按地址族和表 restore --noflush，跨表不具备整体原子性。
链尚未挂接使部分安装不能影响现有流量。安装后再次验证能力，失败则只回收本候选。
apply 返回 0=完整安装、2=安装失败但完全回收、1=状态或回收不可信。
安装/停止失败保留 pending；查询失败不能当作规则不存在。
清理先撤销 installed 收据，再删除链，最后才移除 pending，重试幂等。
installed 是安装完成收据，不是后台规则监控，不能用于证明今后的内核规则仍存在。
重复调用 apply 返回 1，不能仅凭旧收据返回成功；调用方应生成新代次或先解除挂接并回收。

## B3.3/B4 必须共同完成的集成

1. 保留本轮全局及 ACL 的完整有效请求快照、初始化 0/2/1 分类和 UCI 顺序；
   将端口全豁免等策略变成 B3.1 的有效关闭状态，避免启动不需要的实例。
2. 提供现有动态/静态集合，按协议/地址族把旧入口替换成完整的新分发链；
   **不能简单 jump 新链后再执行旧全局规则**，否则 closed 的 RETURN 会重新落入旧全局代理。
   即使紧邻新链使用 goto，祖先链还存在 jump 返回位置时，仍可能执行祖先的旧全局规则。
   需要从 hook 入口核查完整调用栈，而非只检查最后一个跳转。
   mangle 中 ACCEPT 也不阻止后续 nat 或其他 nft base chain；两处入口及其他 base chain 必须一起审查。
   挂接、跨表切换、策略路由和解除挂接的事务是下一阶段工作，不属于本轮 apply。
3. 保留已有 DIVERT/回环、mark 路由、表 999 以及 fw4 重载和停止顺序。
   必须先解除挂接才能调用 discard；本轮没有“停止一个已接管流量的新防火墙”的生产入口。
4. DNS/SOCKS：B2 不提供全局原生 SOCKS，也不发布 GLOBAL_SOCKS_server 或 DNS 端口。
   B3.1 仅证明原生入口，未启动独立 DNS helper。TCP-only/UDP-only、dns2socks、
   SmartDNS、远程 DNS 的业务协议依赖和专用端口仍由 B4 接入，不修改生产 DNS 架构。
5. 本地/LAN 目的地址先行返回，旧 DNS 链原样保留；LAN 主机名和 _vlmcs._tcp SRV/KMS
   必须做真实设备回归。文件夹具中旧 DNS 字符串未变不等于实际 DNS/KMS 已测试。
6. 多 A/AAAA、DNS 轮换、核心实际连接地址与解析快照的一致性及原生 SOCKS 新用途
   需要协调现有 VPS 集合/解析和启动快照；域名规则当前拒绝，不得以首地址旁路当作完整实现。
7. OUTPUT 失败协议与核心外层传输重合的组合，需要在后续启动集成中明确区分核心连接；
   本轮仅拒绝该候选，不创建新进程权限或 socket mark 体系。明确关闭 OUTPUT 的 LAN-only 组合仍可生成。
8. 独立 SOCKS 和新接入 DNS helper 的真实上游连接也必须登记/验证绕行能力。
   目前 remotes 来自 B2/B3.1 的透明实例，不能据此宣称接管 OUTPUT 后所有旧独立 SOCKS 或
   UDP-only SS 原生 SOCKS 新增 TCP 用途均已绕行。当前生产未接入，因此这些现有功能未受影响。

## 验证方法与限制

```sh
PASSWALL_FW_DOCKER=doocs/md:latest node tests/passwall-split-firewall.cjs
```

直接加载真实 B1/B2/B3.1/B3.2、缓存函数、生成器和 Hysteria 管理器。
容器中用真实 Lua 5.1、BusyBox ash、PID、socket、信号和临时目录；核心协议是监听夹具。
Docker 自带 init 回收测试孤儿进程；nixio 等待适配保留生产的 100ms，
避免把 ash 充当 PID1 或将等待缩短十倍的测试差异当成 procd 行为。
所有 nft/xtables/restore 均为文件状态夹具，既不操作宿主防火墙，也不操作容器内核规则。
Node 解释实际生成并安装到夹具的规则，对同一组数据包断言两种后端的转发、丢弃、直连、标记和回环结果。
最终审查新增父链剩余全局规则、jump/goto 调用栈、跨 mangle/nat、其他 base chain 及 NFT_BREAK 路径；
RETURN 是返回调用栈，不能在解释器中直接等价为“最终直连”。
该模型验证新建流的规则控制流，不模拟已有 conntrack NAT 映射、实际策略路由、透明 socket 握手或代理协议。
不能以这些结果声称 nft/iptables 内核语法、模块能力、真实路由和代理数据面已经通过。

覆盖配置五态/九种运行状态组合、两核心交叉和同节点选择、ACL 继承/禁用/关闭/失败、
IPv4/IPv6 地址族归属、TCP REDIRECT/TPROXY、UDP TPROXY、OUTPUT/回环、名单/端口顺序、
MAC/设备/集合/IP 范围、外层传输绕行、缓存查询/部分记录、安装后监听退出、部分规则写入、
回滚查询/删除失败、收据清理失败和重试、其他代次及旧 DNS/规则不受影响。
并发内核安装、系统掉电、真实二进制及目标 ImmortalWrt 的模块和数据面仍待专项验证。

## 本轮验证记录

- 首轮 B3.2：Alpine 3.24.2 / BusyBox 1.37 / Lua 5.1，64 个 nft/iptables 已安装规则快照的
  语义断言通过；外部同名链、不同代次隔离、安装/回滚/收据错误及重试通过。
- B3.1、B2 原生监听回归通过；B1、阶段 A UCI 迁移工具、缓存生命周期和两防火墙旧路径
  在 OpenWrt SNAPSHOT BusyBox ash 下通过；既有五组、Hysteria2 清理、init 状态及探测清理通过。
  合计执行 14 个测试入口，未执行可选的真实 Hysteria 二进制及并发 nixio 锁专项。
- 原生 Lua 5.1 loadfile 与 Lua 5.1 parser：41 个文件；OpenWrt BusyBox ash：28 个脚本；
  Node：16 个测试文件语法通过。未以这些结果替代 nft/iptables 内核校验。
- git diff --check、六个新增文件 UTF-8/尾随空白检查通过；已跟踪文件和 Git index 均未改变。
  没有接入生产入口、执行迁移、暂存、提交、推送或部署。

## 最终审查：拓扑、证明范围和设备验收

下面是**待 B3.3 挂接的契约**，当前所有链仍然无 hook：

```text
IPv4 PREROUTING mangle --goto--> P4: 本地/LAN/WAN、回复 -> 标记回环 -> 有序 ACL -> 默认客户端
IPv4 PREROUTING nat    --goto--> N4: 本地/LAN/WAN、回复 -> 有序 ACL -> TCP REDIRECT 默认
IPv6 PREROUTING mangle --goto--> P6: 同上，仅通过 IPv6 能力检查的协议可 TPROXY
IPv4 OUTPUT mangle    --goto--> O4: 本地等豁免 -> 实例远端 OUTPUT 豁免 -> 全局按协议标记
IPv4 OUTPUT nat       --goto--> R4: 本地等豁免 -> 实例远端 OUTPUT 豁免 -> TCP REDIRECT
IPv6 OUTPUT mangle    --goto--> O6: 同上，按实际 IPv6 能力标记
OUTPUT 标记 -> 策略路由表 999 -> lo PREROUTING -> P4/P6 中的该协议全局 TPROXY 端口
```

- Close：例如 ACL A 的 UDP，P4/P6 命中该源 UDP RETURN，跳过本链后续默认 UDP；
  只有整条祖先返回路径和后续 hook 都没有旧代理入口时，才可保证最终不落入旧全局代理。
- 禁用：没有该 ACL 的匹配规则，继续下一 ACL/默认规则；不会通过 RETURN 把源截断。
- Failed：例如 ACL B 的 TCP，非本地端点命中 DROP，访问另一个成功节点的公网 TCP 端点也 DROP；
  对本地 dnsmasq、路由器服务和 LAN KMS 的访问先按真实本地集合返回。
- Ready：TCP REDIRECT 经 mangle 的丢弃/返回策略，再到 nat 的该协议端口；
  TCP/UDP TPROXY 成功后结束当前 mangle 链，监听消失时按后端实际语义 DROP。
- nft 单 batch 拒绝在正常模型中没有部分对象；iptables 先前成功的 restore 表可能仍在，必须回滚。
  另有明确标注的“结果不确定”故障注入，故意留下部分对象验证保守回收；不能说这是 nft 正常事务语义。
- 所有权依赖现有生命周期锁和私有随机前缀。未证明与绕过锁、直接修改这些链的外部程序并发安全。

正式挂接前/设备验收（B3.3/B5）必须执行：

1. 在目标版本用 nft --check / 对应 restore 校验输入，并在隔离网络命名空间或测试机装载真实规则。
2. 用 nft monitor trace 或 xtables TRACE/计数器观察 Close、禁用、Failed、Ready 的完整 hook、祖先链及跨表路径。
3. 建立真实 IP_TRANSPARENT listener，覆盖双族 TCP/UDP、TPROXY 监听退出瞬间、REDIRECT、OUTPUT 回环、现有 conntrack 流。
4. 核对 fw4 reload、跨表切换/回滚、解除挂接后停止、内核模块、真实代理连接；不能让旧 nat/base chain 重新接管。
5. 测试 dnsmasq、本地域名、_vlmcs._tcp SRV、KMS 自动发现、远程 DNS 及泄漏；文件夹具保留 DNS 规则不等于这些测试通过。

语义依据（资料核对，不是目标设备运行证据）：
[Netfilter nft 手册](https://netfilter.org/projects/nftables/manpage.html) 的 verdict/TPROXY 章节、
[Linux v6.6 nft_tproxy.c](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nft_tproxy.c)、
[Linux v6.6 xt_TPROXY.c](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/xt_TPROXY.c)。

最终审查运行记录：68 个双后端已安装快照及完整父链/跨表语义断言通过；
多地址域名、OUTPUT 失败协议/外层传输冲突为明确拒绝场景，未计作“功能成功”。
摘要命令失败/错误输出、配置 JSON 改动、空检查记录、正常 batch 原子拒绝、跨表部分提交、
结果不确定的回收失败/重试和旧收据拒绝重入均通过。既有另外 13 个测试入口通过。
原生 Lua 5.1 41 文件、OpenWrt ash 28 脚本、Node 16 文件语法通过；
确认现有 OpenWrt 镜像提供 md5sum，未引入该镜像缺少的 cksum 或其他软件包依赖。
这些结果只支持未挂接模块的代码检查点，不支持直接部署新路径；上列 B3.3/B5 前置条件保持有效。
