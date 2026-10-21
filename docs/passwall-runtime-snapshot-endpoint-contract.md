# Passwall Lite B3.3-1：配置快照、端点和 OUTPUT 身份契约

基线：`1dceaf493c8c60c25217c29d577026c54ced2185`。本阶段仅有未接入的辅助接口和实验。
没有修改 start、acl_app、两防火墙 hook、DNS/SOCKS、LuCI、迁移、生成器、运行管理器或服务端。
本文的契约不表示 B3.3 完整集成或真实代理数据面已经通过。

## 一、配置快照接口：已实现，未接入

未来调用方在现有 Passwall 生命周期锁内加载 B1 和 `runtime_snapshot.sh`：

```sh
passwall_snapshot_capture
snapshot=$PW_SNAPSHOT_DIR
passwall_snapshot_check "$snapshot"
passwall_snapshot_pair "$snapshot" global
passwall_snapshot_pair "$snapshot" acl SID
passwall_snapshot_uci "$snapshot" show NODE_ID
passwall_snapshot_uci "$snapshot" get NODE_ID.address
```

这几个接口成功返回 0，失败返回 1；不发布 B2/B3.1 成功缓存。
capture 失败清空 PW_SNAPSHOT_DIR；pair 每次重置协议、布局、继承、启用状态返回变量及 B1 输出，不改写 PW_SNAPSHOT_DIR。
查询 global 与 ACL 使用显式角色参数，避免名为 global 的 ACL 与全局作用域冲突。

快照位于 `${TMP_PATH}/contracts/generation.XXXXXX`，目录权限 0700，内部文件使用 umask 077。
名称是一次运行准备的唯一代次，不是节点 ID 或配置摘要；相同配置再次 capture 也产生不同代次。
完整 `uci -N export passwall` 保存原节点、全部策略、DNS 字段、ACL 顺序及独立 SOCKS；包括 pending edits。
用私有唯一包名和私有 config/state 目录读取，复用阶段 A 已验证的隔离方式，避免 live delta 再应用。
不 import、commit、revert 或修改 live UCI。全局/ACL 仍含旧 node 字段时明确拒绝，不能默认为双协议关闭。
独立 socks section 的 node 仍允许且原样保留。schema 迁移留待正式集成。

sealed 清单检查 source、私有配置、包名、section 索引和摘要。检查时重新计算固定的完整文件集，并与清单完整比较；
不能只用 md5sum -c 接受截短后仍有有效记录的部分清单。读取 section 列表失败立即拒绝 capture，不能跳过旧字段检查。
公开冻结读取接口先检查状态，再输出完整结果，失败时不泄露部分 UCI 输出。MD5 仅检测意外改动，不是签名或防 root 篡改机制。
source.md5 是整个 UCI 视图的指纹；不能作为公开日志内容输出完整源文件，快照包含节点密码。

匿名 section 顺序保留，但其自动 ID 是快照代次内的标识，不能当作跨代或 live UCI 的永久 ID。
真实 UCI 实验确认：pending reorder 后，live 游标仍可保留旧自动 ID，导出再解析的私有快照则可能生成新 ID。
后续必须从本代 acls 索引遍历、读取并绑定实例/规则，携带 generation；不能混用 live SID 或仅用 SID 清理其他代次。

pair 返回：

| 变量 | 含义 |
| --- | --- |
| PW_SNAPSHOT_TCP_RAW / UDP_RAW | 保存的原始选择，tcp 与显式相同 ID 不归一化回写 |
| PW_SNAPSHOT_TCP / UDP | 经过启用开关、ACL mode/继承和 B1 跟随解析的请求节点 |
| PW_SNAPSHOT_LAYOUT | closed/tcp/udp/combined/split，只描述解析布局 |
| PW_SNAPSHOT_INHERIT | ACL 的全局继承意图，不证明已绑定成功 |
| PW_SNAPSHOT_ENABLED_RAW | section 原始 enabled（缺失为 0） |
| PW_SNAPSHOT_ENABLED | 有效 enabled；ACL 同时受全局 acl_enable 约束 |

缺失协议字段表示 Close；TCP 缺失加 UDP=tcp 仍是双关闭。mode=0 不验证无用节点和继承选择。
继承请求使用冻结全局的完整意图，不能把全局启动失败的协议改成 Close；实际成功子集仍由 B3.1 查询。
本接口不启动或验证代理，不将 layout 当作 ready。端口全豁免等有效策略必须由集成层从同一快照计算，
传给运行和防火墙的有效请求必须一致；本接口没有复制防火墙策略解析器。

check 在 capture 完成和未来发布/挂接前比较完整 live UCI 视图；修改节点参数、DNS、ACL 顺序或 pending 都会使其过期。
过期返回 1，不自动更改或停止旧实例。pair/uci 则保持读取原快照，以便诊断和按旧记录清理。
临时检查文件清理失败也返回 1。快照准备失败仅删除本次新目录，不清理旧快照、缓存或代理实例。

**隔离边界**：现有生命周期锁不锁住 LuCI 或外部 UCI 写入。首尾比较不能防止 ABA 修改，
也不能代替 B4 的配置维护窗口/受支持写入入口协调。没有声称支持任意并发在线迁移。
当前只冻结 passwall 包；dhcp、network、接口地址、证书/CA 文件内容和内核状态不是本包指纹的一部分。
未来调用方须在依赖检查中单独核对，不能把完整 passwall 快照称作整个系统的原子快照。

## 二、端点接口：已实现，未接入

`luasrc/passwall/endpoint_contract.lua` 返回普通 Lua 模块，不读取/写入 UCI、进程、缓存或防火墙。

```lua
local endpoint = require 'luci.passwall.endpoint_contract'
local binding = endpoint.bind(generation, source_md5, node_id, frozen_node, preference, resolver)
endpoint.check(binding, generation, source_md5, node_id, frozen_node)
local outer_protocols = endpoint.config(binding, generated_json_table)
local expectation = endpoint.instance(binding, config_path, config_md5, pid, birth)
endpoint.check_instance(expectation, binding, config_path, config_md5, pid, birth)
```

错误以明确 Lua error 返回，调用方必须捕获并按现有 0/2/1 清理分类，不能把错误当作成功能力。
bind 默认用 nixio.getaddrinfo(host, "any")；测试允许注入解析边界，不替换生产选择/校验逻辑。

规则：

1. 原始 node 深复制保存；UCI 中原域名不变。literal 不做 DNS 查询，域名每次 bind 只解析一次完整候选集。
2. 严格验证 literal；规范化 IPv6，去重 A/AAAA。按显式 ipv4/ipv6 优先，族内按规范文本排序；
   ipv4-only/ipv6-only 不允许退到另一族。不是延迟竞速或地址健康检测。
3. 只选一个 IP 给本实例。generator_node 是固定地址的完整节点副本；后续生成器必须消费这个副本。
   地址集和选中地址保留在 binding。防火墙必须读经校验的实际 JSON/同一 binding，不能独立重解析域名。
4. 同实例重试使用同一固定 IP。重新解析、地址变化或更换族应重新准备代次/实例/规则，不能修改仍被引用的旧 JSON。
5. DNS 失败、非法地址、指定族缺失均拒绝绑定，不产生 ready。暂拒绝 IPv4-mapped IPv6 端点，
   避免把文本 IPv6 错当作实际 IPv6 出站；zone ID 也不在本轮契约内，不能猜测出接口。
6. Hysteria 未显式 SNI 时，域名绑定保留原域名作为 server_name；显式 SNI 优先。
   tls_allowInsecure、Custom CA、obfs、认证及其余节点字段保留，不能因固定 IP 关闭证书验证。
7. config 校验真实生成 JSON 的 endpoint、SS 凭据、H1 TLS/obfs/认证与 transport。
   SS 的外层协议按实际 mode 返回；原生 SOCKS 的 TCP 控制能力不发布为 TCP 透明能力。
   H1 udp/wechat-video 外层 UDP，faketcp 外层 TCP，与透明业务角色分开。

注意：现有生成器仍从 api.uci_get_c 读 live UCI。**本轮没有把 generator_node 接进真实启动器**。
测试让生成器的 UCI 读取边界返回冻结节点，以验证已有字段映射；B3.3-2 必须提供正式冻结读取适配，
不能只加 server_host 覆盖而继续从 live UCI 读认证、SNI 或证书参数。

instance 返回 state=unverified，只是未来实例核对的期望，不是 ready、GID 或资源所有权证明。
check_instance 对代次、来源、节点、配置路径/摘要和 PID/birth 完整比较，但不代替 /proc/socket 实测。
未来实例持久记录必须在创建时绑定代次，规则候选必须引用同一已核对记录，并在安装前后重新 ready。
首版不允许仅给旧路径/PID 换一个 generation 标签来跨代复用；旧使用者仍由 B2/B3.1 引用机制保护。
跨代共享如确有必要，须明确核对不可变实例来源及配置兼容，不能通过本期望记录直接放行。
没有新建成功缓存、全局代次数据库或资源管理器；后续在现有实例目录和规则候选中保存这些少量关联字段即可。

## 三、OUTPUT 身份：源码事实与独立实验

已核对本仓库 api.lua 的 DIRECT_GID=9911、exec_call_as_gid，以及旧防火墙的
nft `meta skgid` / iptables `--gid-owner`。现有核心启动器没有使用该 GID 路径，本轮也未改动。

Linux v6.6 的 [nft_meta_get_eval_skugid](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nft_meta.c#L120)
和 [owner_mt](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/xt_owner.c#L57)
都读取 socket file 的 f_cred->fsgid。这里指没有 --suppl-groups 的相同精确 GID 条件。
没有 skb socket、socket file 或合适网络命名空间时不能当作命中，不能用进程 Gid 行代替 socket 证明。

源码参考：

- [SS-libev v3.3.5 local.c](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/local.c)：
  socket 创建见 187/1271 行；user/run_as 见 1604/1901 行。
- [SS-libev v3.3.5 redir.c](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/redir.c)：
  socket 创建见 166/761 行；user/run_as 见 1055/1287 行。
  当前 Lite 生成器及命令没有为这两个客户端传 user。目标发行包补丁仍需核对。
- [Hysteria v1.3.5 client.go](https://github.com/apernet/hysteria/blob/v1.3.5/app/cmd/client.go#L30)：三种传输工厂分发。
- [Hysteria v1.3.5 funcs.go](https://github.com/apernet/hysteria/blob/v1.3.5/core/pktconns/funcs.go)：
  24/57 行分别是 UDP/WeChat 客户端工厂，34/47/64/76 行使用 net.ListenUDP；
  86 行起 FakeTCP 工厂转到 faketcp.Dial。源码类别不能代替实际核心 socket 观测。
- [Hysteria v1.3.5 tcp_linux.go](https://github.com/apernet/hysteria/blob/v1.3.5/core/pktconns/faketcp/tcp_linux.go)：
  394 行 Dial 中 net.DialIP("ip:tcp") 和 net.DialTCP 创建 raw/普通 TCP；267 行发送 raw TCP；
  429 行后设置 TTL=1 并尝试添加 filter OUTPUT 丢弃规则。不能把 FakeTCP 当作只有一个普通 TCP socket。

**建议契约**：在 exec 核心及创建任何 socket 之前设置 root 客户端的 GID/fsgid，
保持 UID 和必要的 raw/透明代理权限。包括 ss-redir、ss-local、H1 主进程与后续 socket/子进程。
不要让 DNS helper 的代理请求一起继承直连豁免，也不能把 9911 当作每实例唯一身份。
原本使用该 GID 的可信直连解析/下载仍然有效；它是路由信任域，不是抵御 root 的安全边界。

豁免应放在 mangle/nat 的代理选择之前，不能按公网 IP/端口向所有本机进程放行。
**不能在 filter 中无条件 ACCEPT 这个 GID 而跳过 H1 的 TTL/HL DROP**。
实验为观察计数在容器 filter OUTPUT 上安装专用规则，不是建议把这组实验链复制到生产。
通用 GID 事实也不证明后续 fw4/mwan3/base chain 不覆盖标记或改变最终结果。

tests/passwall-output-identity.cjs 使用真实生产 exec_call_as_gid 函数、原生 Lua5.1/nixio 和 Linux socket。
nixio 实验源码固定为 openwrt/luci 580b6b1d9ec3a79edb8e2a5a9c4700b9c320ff6a，
只编译测试库，不构建/下载代理核心，不增加 IPK 依赖。
容器独立网络命名空间内使用 NET_ADMIN/NET_RAW，不使用 host network/PID 或宿主防火墙。

实验覆盖双族 TCP/UDP 以及与 H1 同类的 IP raw TCP socket；核对真实 nft/iptables 命中计数和 TCP/UDP 返回数据。
相同目标元组下，9911 socket 通过，普通 GID0 socket 被阻断；socket 创建后才改 GID 仍不通过；
9911 socket 创建后把进程 GID 改回 0，仍按原 socket 凭据通过。fork/exec 后新建 socket 也单独检查。
raw 发送遇本地 DROP 可以返回 EPERM，测试仍必须核对 DROP 计数，不能只把 EPERM 当作隔离成功。
另一个实际内核实验把 GID RETURN 放在 nft route OUTPUT / iptables mangle OUTPUT，
随后在 filter OUTPUT 检查 TTL/HL=1 并丢弃；双族分别验证前面的 GID 命中和后面的 DROP 计数都增加。
这证明该实验拓扑的代理选择豁免没有绕过 filter 防护，不代表真实 FakeTCP 的全部 socket/规则已经验收。
环境缺少内核能力时会明确 SKIP，不允许用字符串模型代替。

## 四、无法在本轮证明的部分及最小替代方案

尚未运行实际 ss-redir/ss-local、Hysteria v1.3.5 三传输双端握手或目标 ImmortalWrt 内核。
raw socket 计数通过不等于完整 FakeTCP 通过，未检查全部真实 Go goroutine/socket 或发行包降权行为。
未证明真实代理透明监听、IP_TRANSPARENT、双栈 V6ONLY、策略路由或 DNS/KMS 数据面。

若某真实核心的必要出站 skb 没有可匹配凭据：保留 B3.2 现有拒绝，不恢复公网端点全体豁免。
替代方案优先级：已由目标核心源码确认的 socket mark（当前不假定支持）→ 专用 UID（权限/证书风险更大）→
cgroup 等额外系统能力。后两者增加依赖和维护复杂度，本轮不实现，也不以复杂机制掩盖未确认能力。
GID 实验成功支持继续研究现有 GID 方案，不构成生产启用许可。

docs/passwall-lite-architecture-review.md 第 30 行的“缺少 iptables 即启动失败”是历史说明；
当前 hysteria_runtime.lua 客户端按实际地址族缺命令时告警后继续原生路径。本轮没有修改该管理器或旧报告。

## 五、测试入口与 B3.3-2 衔接

```text
PASSWALL_UCI_DOCKER=openwrt/rootfs:x86-64
PASSWALL_CONTRACT_NATIVE_DOCKER=doocs/md:latest
node tests/passwall-runtime-contract.cjs
node tests/passwall-output-identity.cjs
```

前者使用真实 UCI/ash、B1 和新快照函数；Lua 原生调用端点模块与真实 SS/H1 生成器。
后者真实 socket 与内核实验不运行代理二进制，必须与前者的配置测试区分。
所有写入留在一次性容器临时目录；不执行正式迁移或安装。

B3.3-2 可直接依赖以上 snapshot/pair/bind/check/config 接口；instance/check_instance 只作未验证期望。
必须继续完成：冻结节点读取适配、实例创建代次持久化与实际身份核对、地址族能力、核心 GID 启动实验、
DNS/SOCKS 归属及 hook 全链路径。B2/B3.1/B3.2 原有成功缓存、所有权、0/2/1 错误分类保持有效。

B4 正式入口切换前审查项：核查 SS-Rust、SSR、Naive 等历史类型仍存的 LuCI 注册、节点选择和启动可达性，
不能将 B2/B3.1 仅接受 SS/Hysteria 等同于旧生产入口已经完成双核心收敛。需确认正式入口符合双核心边界后再切换；
本轮仅记录该审查要求，不清理历史核心，不改变 Hysteria/FakeTCP 架构。

## 六、本轮验证记录

- 真实 UCI/ash：使用已有 openwrt/rootfs:x86-64，覆盖匿名/命名 ACL 顺序、pending 保持、
  双核心五态、跟随/显式 ID、全局继承意图、ACL 主开关、mode=0、过期/损坏快照和错误后重试。
  最终审查新增完整清单截短、section 清单读取失败、部分读取输出抑制、策略 list 字段、
  全局/ACL 旧 node 拒绝，以及 pending 匿名重排后的字段/顺序和旧快照隔离回归。
- 原生 Lua5.1：调用本轮端点模块及两个真实生成器，验证单次解析、完整多 A/AAAA 去重/选择、
  字面 IPv4/IPv6、原始域名不变、TLS/SNI/CA/obfs/认证保持、实际 JSON 外层协议、代次/进程期望不匹配拒绝。
  最终审查增加结果乱序的确定性、认证配置变化拒绝；真实 nixio 容器还验证默认 localhost A/AAAA 解析，
  以及真实 H1 生成器对 Base64 二进制认证（含 NUL）的保持。普通 Lua 配置容器缺少 nixio 时明确跳过该 Base64 个案，
  不能把它作为通过证据；该个案由 passwall-output-identity.cjs 的原生 nixio 执行补足。
- 真实 socket/内核实验：doocs/md:latest 容器，Linux 6.18.54.1-microsoft-standard-WSL2 / x86_64，
  原生 nixio，IPv4/IPv6 TCP/UDP/IP-raw 的 nft 与 iptables 计数断言通过。
  实际工具为 nftables v1.1.6、iptables/ip6tables v1.8.13 (nf_tables)。
  此环境没有选中 legacy 二进制，故不是 legacy xt_owner 独立内核路径验收；后者只有上述源码依据，仍待实测。
  最终审查新增 nft route / iptables mangle GID RETURN 后的双族 TTL/HL filter DROP 计数检查。
  测试端点为隔离命名空间内本机地址，不连接公网服务器，不代表目标 OpenWrt/ImmortalWrt 验收。
- 既有 14 个测试入口通过，包含 B3.2 68 项规则断言、B3.1/B2、B1、阶段 A、缓存/两防火墙/ACL、
  两核心及启停/探测回归。这些旧运行测试没有证明尚未实现的“冻结读取→核心启动→挂接”集成路径。
  最终审查首轮并行回归中，B3.2 有一次夹具进程清理报 cannot stop owned process；随后独立串行执行
  B3.2/B3.1/B2 全部通过。该首次失败原因尚未确认，不将其静默算作通过，也未修改旧管理器或放宽断言。
- 当前生产文件保持不变；只调整 B1 测试的未接入模块允许清单以容纳新的快照辅助函数。
  本阶段没有新运行依赖；使用的 uci/md5sum/cmp/mktemp 等已有调用或 OpenWrt BusyBox 能力经测试可用。
