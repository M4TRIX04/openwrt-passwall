# Passwall Lite 阶段 B1：TCP/UDP 配置与运行契约

基线：`17f4d144b7d94e108d825316d46209a506a5095a`。本地 main 参考：
`1294c9aa4a6faadc1d583e05191ca4e7f056e817`。

## 状态与边界

- **已实现**：未接入的纯配置解析函数；使用真实解析、缓存、端口分配函数的契约测试。
- **设计契约，未实现**：下述协议缓存命名、实例复用及在线迁移接入。
- **未改变**：LuCI、当前单节点启动、ACL、防火墙、DNS、Client/Server、Hysteria 运行管理器。
- **尚待实测**：B2～B4 完整集成后的真实监听、数据面、目标 ImmortalWrt 升级。

`node_config.sh` 仅定义函数，没有顶层运行操作。当前没有生产调用方，不能把本文件中的
缓存名称理解为已经生效的运行接口。阶段 A 离线迁移工具也仍未接入安装、升级或启动。

## 一、配置解析

全局和独立代理 ACL 使用同一规则，空字符串与 UCI 缺失字段等价：

| tcp_node | udp_node | 有效 TCP | 有效 UDP | 布局 |
| --- | --- | --- | --- | --- |
| A | tcp | A | A | combined |
| A | B（B 不等于 A） | A | B | split |
| A | 缺失 | A | 关闭 | tcp |
| 缺失 | B | 关闭 | B | udp |
| 缺失 | 缺失 | 关闭 | 关闭 | closed |

补充：`A/A` 显式同 ID 的有效布局也是 combined，但持久化仍保留 A；`udp_node=tcp`
持久化保留 tcp。后续 TCP 改成 B，前者仍为 UDP=A，后者变为 UDP=B。
TCP 缺失且 UDP=tcp 时没有可跟随节点，实际全部关闭，不能擅自选择其他节点。
combined 只表示请求同节点双协议，不代表已有一个双协议进程。

两种目标核心 SS-libev、原版 Hysteria v1.3.5 均允许承担表中任意角色。
节点存在性、类型、算法、认证及监听就绪校验仍由现有生产校验/启动链负责；纯解析不替代它们。
解析不读取 UCI、不接受旧单字段作为隐式回退、不写默认值、不改变调用者的 `node` 变量。
独立 SOCKS section 的 `node`、生成器 JSON 的 `node` 都不重命名。
全局 enabled、ACL enabled/acl_enable 仍由现有调用层控制；解析器只描述请求，不代替这些开关。
全局未启用时即使保留节点选择也不得发布全局能力，不影响现有独立 ACL/SOCKS 的开关语义。

新配置的跟随默认值只在创建全局配置/ACL 时写入；读取已有配置、重装、普通保存、重启时不补值。
两个核心的 UDP 业务能力与 Hysteria 的 udp/faketcp/wechat-video 外层传输是不同维度。

### 稳定纯解析接口（可供 B2 调用，当前不调用）

```sh
. /usr/share/passwall/node_config.sh
passwall_resolve_node_pair "$tcp_selector" "$udp_selector"
passwall_resolve_acl_node_pair "$mode" "$use_global_config" \
    "$acl_tcp_selector" "$acl_udp_selector" "$ready_global_tcp_id" "$ready_global_udp_id"
```

函数在当前 Shell 设置以下结果，调用方检查返回码后读取；不要使用命令替换获取这些变量：

- `PW_NODE_TCP` / `PW_NODE_UDP`：解析后的请求节点 ID，空表示关闭。
- `PW_NODE_UDP_SELECTOR`：实际参与解析的原始 UDP 选择值；保留 tcp 与显式 ID 的区别。
- `PW_NODE_LAYOUT`：closed / tcp / udp / combined / split。
- `PW_NODE_INHERIT`：ACL 明确继承全局时为 1，否则为 0。

`PW_NODE_INHERIT=1` 表示选择了继承策略，不是启动成功标志；全局没有成功能力时可同时为
layout=closed。不能仅凭该值发布 default 或转发规则。

全局解析恰好接受 2 个参数；ACL 解析恰好接受 6 个参数。参数个数或生效 Flag 不合法返回 1，
并将结果清为空关闭状态，防止调用者误用上次结果。空 mode/use_global_config 延续当前 0/0 默认。
函数只有结果变量副作用，不读文件、不执行 UCI、不启动进程。

ACL 优先级：

1. mode=0：关闭两种代理，忽略遗留节点、继承 Flag、DNS；后续防火墙仍保留源匹配直连豁免。
2. mode=1、use_global_config=1：忽略独立节点字段；只继承本轮完整成功缓存解析出来的全局能力。
   全局 TCP 或 UDP 关闭/失败时，对应输入为空，不能从 UCI 或上次缓存补回。
3. mode=1、use_global_config=0：按 ACL 自己的两个字段解析；独立 DNS 仍执行现有校验。

继承接口的两个全局参数必须是已解析的成功节点 ID，不能传原始 `udp_node=tcp`。
解析本身不能证明传入缓存完整、监听存活或属于本次启动，这些是 B2 调用方的责任。
mode=0 在函数内部先于节点处理返回；Shell 会在进入函数前展开参数，B2 调用方也必须先判断
不代理模式，不能先通过命令替换读取/校验无用节点，再指望本解析器阻止这些操作。
单协议与全局节点 ID 相同只允许复用该协议资源，不能据此把整个 ACL 改成全局配置。
独立 ACL 的 DNS 不因某个协议 ID 相同而自动跳过；只有确认实际继承全局 DNS 才忽略无用 DNS 字段。
现有两协议 no_redir_ports 均覆盖全部端口时的直接豁免优先级也要在 B2 调用层保留；
解析器不读取端口策略，不能据此重新校验完全不使用的节点/DNS。
旧 ACL `default` 哨兵须在迁移/兼容层明确处理，不能当普通 ID 运行，也不能无条件提升整条 ACL 为全局继承。

## 二、协议缓存与实例归属（B2 实施契约）

复用 main 的协议节点/端口命名及 Lite 的 `set_cache_vars()`，只补充实例归属。
**完整协议记录就是能力表示**，不新增掩码、引用计数器、独立 ready 标志或缓存框架：

| 用途 | 一个协议的必需字段 |
| --- | --- |
| 全局 TCP | ACL_GLOBAL_TCP_node / ACL_GLOBAL_TCP_redir_port / ACL_GLOBAL_TCP_instance |
| 全局 UDP | ACL_GLOBAL_UDP_node / ACL_GLOBAL_UDP_redir_port / ACL_GLOBAL_UDP_instance |
| ACL TCP | ACL_sid_tcp_node / ACL_sid_tcp_redir_port / ACL_sid_tcp_instance |
| ACL UDP | ACL_sid_udp_node / ACL_sid_udp_redir_port / ACL_sid_udp_instance |

表中 sid 替换为实际 ACL ID。instance 为本轮实际配置文件的绝对路径，直接关联现有进程/运行记录；
Hysteria 继续使用当前按配置路径登记实例的管理器。不同节点、独立进程不得共用路径。
同一实例已验证两个协议监听时，两条记录可以引用同一路径。SS ACL 的 ipt2socks 及其后端
SOCKS 依赖需一起归属于该透明入口，保留现有依赖记录，不另造资源管理器。

共享索引从现有 `acl_node_${node}_...` 按 tcp/udp 拆分端口和 instance；原生 SOCKS 端口及日志
仍关联实际实例，不能继续只凭节点 ID 覆盖记录。B2 应优先扫描现有成功绑定寻找可复用入口；
如保留共享索引，也必须与绑定及实例记录一致，不能作为额外的成功来源。

复用条件同时满足：本轮发布、相同节点 ID、所需协议三字段完整、实例仍就绪、监听方式/地址族及
日志要求兼容。只存在 TCP 三字段不能证明 UDP-ready；同核心但不同节点也不能复用。
同节点需要新增协议时，可启动缺失协议实例，不得重写或停止已有使用者的实例。
combined 布局优先复用已就绪双协议实例；已存在两个合法单协议实例时允许分别复用。

### 发布与清理顺序

1. 启动边界使上次全局协议记录失效；保持既有独立 SOCKS、其他 ACL 和共享实例隔离。
2. 分配端口、生成独立配置、执行现有版本/配置校验、启动并确认必要监听。
3. 用一次 `set_cache_vars()` 发布一个完整协议三字段和相关必需绑定；双协议同实例需一起发布。
4. ACL 继承的协议记录和对应 `tcp_default` / `udp_default` 必须同组发布，不提前写 default。
5. DNS 继续使用现有单套后端；需要它的绑定必须在实际 DNS 就绪后发布。总启用标志不能代替协议成功记录。

写入失败时，不出现新能力记录；旧的其他成功记录保持不变。清理当前失败尝试时，使用启动前明确
保存的本次配置路径/进程记录，不能从节点共享缓存反查后停止。失败实例从未发布的记录不得反向删除
其他成功绑定。替换失败时仍需确认保留的旧实例真实可用，不能仅因旧缓存存在就当作替换成功。

解绑一条 ACL 仅删除该条绑定。仍有全局、其他 ACL 或独立 SOCKS 使用的实例不得停止。
不增加引用计数：在当前序列化启动/清理流程内核对已有绑定及实例记录；无法确认归属时不能宣称已清理。
这里不新增的是节点/ACL 引用计数；Hysteria FakeTCP 已有的规则所有权和引用计数保持不变。
最后一个绑定释放后，才可用明确实例路径回收其进程、配置及依赖；显式整服务 stop 保留现有完整清理。
不借本轮扩大并发进程管理架构。

现有 `get_cache_var()` 文件优先，子 Shell 删除不修改父变量，但父调用者下次读文件不得复活旧值。
`set_cache_vars()` 在同目录临时文件准备后 rename，失败不修改 Shell 成功状态。
单键 `set_cache_var key ''` 删除后仍返回非零；关闭协议使用分组空值删除或显式 del，不误判为发布故障。
文件 rename 保证完整发布，不提供多写者事务；B2 仍须遵循现有生命周期串行约束。

失败结果沿用 Lite：安全隔离的单 ACL 错误允许其他合法 ACL/全局规则继续（现有状态 2）；
清理失败、标记失败且无法证明隔离、归属不可信时不得继续危险规则（非 0/2）。
全局某协议失败只能生成另一已验证成功协议的规则，不能借总启用标志使用旧端口。
B1 不实现新缓存键的启动、读取、回滚消费者，也不声称这些路径已集成测试。

## 三、迁移写入隔离调查与接入方案（未执行）

已确认的仓库内路径：

- `api.lua::uci_save()`（120 行起）存在 save/commit 和 shell commit 路径，未持有 init 锁。
- CBI 保存、控制器 `set_node()`、节点删除等都是配置写入者；只锁一处控制器不足以覆盖写入。
- `init.d/passwall::start/stop/restart` 的 `/var/lock/passwall.lock` 保护生命周期，不保护所有 UCI 写入。
- `uci-defaults/luci-app-passwall` 先写 firewall/dhcp/uhttpd，再初始化配置、重命名 section、反向迁移，
  最后 commit passwall、sed 改配置、清 LuCI 缓存。它不是一个原子配置事务。
- 当前反向迁移 84～85、92～93 行会把 tcp_node 变回 node 并删除 udp_node，B4 必须替换。
- `Makefile` 将客户端和服务端配置列为 conffiles；其自定义 postinst 本身没有调用本迁移工具。
  通用 `luci.mk` / opkg 的执行顺序不在本仓库，目标固件上必须核实，不能假定固定先后。
- 阶段 A 工具的 export 包含 pending changes；私有唯一包名避免 live delta 重入，但不能避免候选过期。

安全方案不以“生成后 cmp 一次”代替写入隔离：

建议首版采用明确的维护窗口/离线应用，不为了自动迁移而先引入通用配置锁框架。
在该窗口暂停 LuCI/UCI 写入及相关自动任务，再升级和应用候选；不能保证排他时拒绝迁移。
若后续要求在线自动升级，则须先补齐所有受支持写入入口的协调，不能只增加一个锁文件。

1. 在维护窗口暂停配置编辑及自动配置写入，取得与启停一致的维护排他边界。
   现有 init 锁不够。B4 要么让受支持的 LuCI/CBI/API 写入遵守同一配置维护锁/维护拒写机制，
   要么在明确离线维护环境应用；任意外部 `uci` 命令不遵守应用锁，不能承诺无条件在线迁移安全。
2. 在该边界内检查 live pending changes；非空就失败保留，不自动 commit/revert 用户修改。
3. 现场生成候选、校验、备份，在同一写入隔离边界内比较来源并以同文件系统 rename 发布。
   任何来源变化都丢弃候选后重试；没有有效隔离就不应用。
4. 全部 passwall 相关升级改写在候选中完成，不能在覆盖后继续旧 commit/sed 把旧 cursor/delta 写回。
   失败不留下迁移 pending，不自动启动只能理解新字段的运行脚本。
5. 备份/恢复原配置、保留诊断及非零退出。升级可能已安装新程序，失败时阻止服务启动，
   不能只说“保留旧配置”就视为恢复了可运行状态；回退须代码与配置成对恢复。

| 场景 | 接入策略 |
| --- | --- |
| 新安装 | 在确认无已有配置时安装 canonical 模板；只在此时设置跟随默认；启动前校验 schema |
| 旧配置升级 | 上述维护边界内，拒绝 pending，fresh snapshot → 私有候选 → 校验/备份 → 原子发布；移除反向迁移 |
| 软件包重新安装 | 已 canonical 则不补字段、不覆盖用户配置；仍是旧格式按升级处理；不得使用旧候选或预设“重装即新装” |

`IPKG_INSTROOT` 镜像构建与实际设备安装应区分，不能在构建宿主执行 live UCI 迁移。
原先被删除的 UDP 选择无法推断恢复，只能备份恢复或手工选择。

## 四、验证范围与后续依赖

`passwall-node-contract.cjs` 执行真实未接入解析器和真实缓存/端口函数。netstat 为边界夹具；
协议记录是契约夹具，不是 B2 启动器替身。测试覆盖五态、两核心角色、同 ID/跟随的后续修改区别、
mode=0、全局部分成功继承、共享引用、追加/部分追加/rename 故障、清理错误和端口占用。
存在 UCI 时额外在私有目录用真实 UCI 读取两核心、全局/ACL 的五种状态，确认缺失值与独立 SOCKS 保留；
无 UCI 时明确报告该组跳过，不能用 bash 结果代替。
提交前复核增加了先产生非空继承结果、再调用两解析器或注入非法 Flag/参数个数的连续测试，
逐一检查全部五个返回变量；另外以命令边界探针确认 mode=0 和全局继承不读取 UCI/缓存或校验无用节点。
复核时还仅在内存源码中逐个去掉五个返回变量的初始重置，新增断言均能检出；未改写生产解析器。
既有 Hysteria/SS 回归负责当前真实生成器及启动/清理分支；这些通过不代表未来分协议路径已实现。

B2 可依赖纯解析接口、既有缓存 API、阶段 A 的 Hysteria 独立监听参数和 SS 三种 mode。
B2 必须落实就绪验证、协议记录、独立配置路径、共享归属和错误传播；B3/B4 必须共同接入
ACL/两防火墙、LuCI/控制器、默认配置和迁移后才能部署完整功能。
仅 UDP 配置与当前 TCP DNS 后端、原生 SOCKS 的归属关系仍须在不改变 DNS 架构的前提下明确；
不能自动改 DNS 后端或把未启用的 TCP 透明代理伪装为已启用。

### 本轮实际验证（2026-10-21）

- 本机已有 OpenWrt SNAPSHOT r37478-8975977f7a / x86_64 容器：B1 契约、真实 UCI 输入、
  缓存生命周期/七项 ACL/两防火墙错误传播、阶段 A 迁移五态及 17 类失败注入通过。
- 现有五组测试（manual、blockers、hysteria1、client-isolation、core-removal）通过；
  Hysteria2 清理、init 状态和临时探测清理回归也通过。
- Lua 5.1 语法由 luaparse 检查 37 文件；Lua 执行回归使用 Fengari 和现有 OS 边界夹具，
  不是目标固件上的原生 Lua/真实代理进程测试。
- Shell 语法在 OpenWrt BusyBox ash 检查 20 文件；Node 语法检查 13 文件；
  新文件 UTF-8/尾随空白检查及 git diff --check 通过。
- 未进行目标 ImmortalWrt 二进制监听、数据面、并发在线升级测试；未运行生产迁移。
