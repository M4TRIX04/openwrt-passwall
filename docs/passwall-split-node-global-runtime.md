# Passwall Lite 阶段 B2：未接入的全局 TCP/UDP 链路

基线：`51a6868b85e109be583ac38b00ad4af7bb8eb299`。

## 实施边界

新增 `root/usr/share/passwall/global_nodes.sh`，只定义函数，不自动 source B1 或调用 start。
现有 app.sh、init、LuCI、ACL、两种防火墙、DNS、UCI 配置和迁移入口均未改动。
两种核心服务端和 Hysteria 的 start/stop、版本、三种传输及 FakeTCP 管理逻辑保持原样。
Hysteria 运行管理器仅新增 ready 查询及 CLI 分发，查询会取得原有锁，不安装或释放规则。

这是待 B3/B4 集成的代码，不应直接替换正在运行的单节点服务入口。

## 可供后续阶段调用的接口

未来调用方提供现有 app.sh/utils.sh 函数，加载 node_config.sh 和 global_nodes.sh，
在现有服务生命周期锁内串行调用；本轮没有增加第二把生命周期锁或并发缓存系统。

| 接口 | 语义 |
| --- | --- |
| passwall_start_global_nodes TCP_SELECTOR UDP_SELECTOR | 使用 B1 解析，释放上一轮全局绑定，按协议启动并发布成功监听 |
| passwall_global_node_ready TCP/UDP | 校验协议三字段、节点/端口与实例记录一致，再确认实际监听仍就绪 |
| passwall_stop_global_nodes | 原子撤销新全局三字段；仅回收没有其他绑定使用的 B2 实例 |

启动返回：0=所有请求能力已发布或全部关闭；2=至少一个请求失败但已安全回收，其他成功协议保留；
1=清理、缓存撤销或状态可信度有问题，调用方不得继续依据不可信状态构建规则。
停止返回 0/1；失败保留诊断和可用的实例记录供重试，不调用整个服务 stop。

global enabled 和 ACL enabled 仍属于调用层职责。接口不读取 tcp_node/udp_node、不写 UCI，
只解释参数；跟随与显式同 ID 不回写，缺失值不会补默认。
函数内以 GLOBAL_ACL_PATH 属于 TMP_PATH 为必要边界，未提供有效上下文就拒绝清理。

## 启动和端口

参考本地 main 的 start_redir/run_redir 协议分发：TCP 从 1041、UDP 从 1051 分配。
非空同 ID（包括跟随）使用一个实例和同一端口，分配时检查 TCP、UDP 两种占用。
不同 ID 分别分配实例与监听；TCP、UDP 均可选择 SS 或 Hysteria。空 TCP + UDP=tcp 全部关闭。

- SS：使用真实生成器的 tcp_only / udp_only / tcp_and_udp，运行现有 `ss-redir -c ... -v` 命令，
  不传会覆盖 JSON mode 的 -u/-U。全局原生 redir 不需要 ipt2socks；既有 SS ACL 依赖不删除也不改写。
- SS 启动局部捕获 PID 和启动时间，写入既有 PID/启动时间/命令记录格式；没有修改通用 ln_run。
  原因是现有 ln_run 的 PID 为局部变量，调用者不能可靠取得本次失败实例的身份。
- Hysteria：分别传 local_tcp_redir_port/local_udp_redir_port，继续调用现有 start_hysteria/运行管理器。
  udp/faketcp/wechat-video 由节点与原生成器决定，与业务 TCP/UDP 角色独立。
- 每个实例使用 `${GLOBAL_ACL_PATH}/split/instance.XXXXXX/config.json`，避免管理器按路径替换别人的实例。

本轮只建立透明入口。没有新增全局 SOCKS/HTTP 或 DNS 归属策略；现有单节点、独立 SOCKS/HTTP 不受影响。
B3/B4 须利用现有原生监听补齐 DNS 所需依赖，不能仅以这里的透明端口就绪视为整个服务可转发。

## 成功缓存与生命周期

沿用 B1 的 ACL_GLOBAL_TCP/UDP_node、redir_port、instance 三字段；instance 为 config.json 绝对路径。
SS 校验进程启动时间、非僵尸状态，核对该 PID 的 fd socket inode 与 /proc/net/tcp[6]/udp[6]；
TCP 必须 LISTEN，UDP 必须绑定对应端口。端口被其他进程占用或只有 PID 存在不能通过。
Hysteria ready 同样检查已有实例身份和实际 fd/listener；不以启动返回码代替发布前检查。
B2 调用 ready 时同时传入实例 meta 中的 TCP/UDP 端口，核对 JSON 的透明监听能力与记录一致，
避免修改后的 JSON 只检查 SOCKS 或另一个协议就错误认可原缓存能力。旧的不带端口查询接口仍可使用。

校验成功后调用现有 set_cache_vars 原子发布，再次校验监听，才报告成功。合并实例一次发布六字段；独立协议各自完整发布。
发布失败回收本次新建实例；安全回收返回 2，回收失败返回 1，不删除其他协议、ACL 或 SOCKS 缓存。
如果进程在写缓存期间退出，原子撤销本次尝试的协议字段后再回收；撤销失败则返回 1，
保留精确实例记录和诊断，供停止接口重试。内部发布函数返回 3 表示此种不能安全回收的状态，
启动函数将其转换为对外的 1；不得继续把该记录用于规则生成。
用于即时回滚的内存 PID 只在当前未发布尝试有效，成功发布后立即清空，正常停止以持久记录为准。

`passwall_global_node_ready` 每次都重新校验身份和全部声明的监听。合并实例缺少任一监听时，
两项查询均保守返回失败。进程发布后崩溃不会自动抹去缓存或自动重启，缓存仅为历史成功及所有权记录，
不能绕过 ready 查询把原始端口缓存当成当前可用能力。B3/B4 接入时必须遵守这一调用约定。

新一轮启动先撤销六个全局键，不沿用上轮全局端口。旧单节点缓存/DNS/SOCKS 标志完全不动，
旧路径不在 B2 所有权范围内。若撤销失败，保留仍被缓存引用的进程并返回错误，避免主动造成死端口。

停止核对缓存中的其他 *_instance 精确引用。仍被引用则保留；读取引用失败则保留并报错。
只有确认无人使用才按具体实例回收。B3 必须先正确解绑自己的引用；共享索引若也持有 instance，
应随最后一个真实使用者清理，否则保守判断会保留该实例。
当前不跨启动周期自动复用旧实例；共享 ACL 仍使用的旧实例保留，新全局使用新的路径和可用端口。

Hysteria stop 始终带 client 和具体 config 路径，保留现有 FakeTCP 规则所有权、共享引用和失败重试。
SS 只按 PID+启动时间终止本实例。身份不可确认、停止失败或目录删除失败时不假装已回收。
不引入自动守护、跨实例资源框架或新增引用计数器。

## 测试方法及边界

`PASSWALL_B2_DOCKER=doocs/md:latest node tests/passwall-global-nodes.cjs` 使用本机已有 Alpine 镜像，
只在一次性容器安装 lua5.1、cjson、dnsmasq 测试工具，不改变 IPK 依赖、代理二进制或宿主服务。

直接执行生产 Shell、缓存 API、两个真实生成器和 Hysteria 管理器。真实 /proc、PID、socket、
TERM/KILL、目录和配置清理均参与测试。dnsmasq 只是前台监听夹具，不能证明真实代理数据面，
且它会额外打开两种协议；所请求的单协议配置由真实生成器 JSON 断言验证。
测试容器增加 SYS_PTRACE，只用于读取 dnsmasq 加固后的 fd；不共享宿主 PID 命名空间。
nixio 锁为串行测试适配，iptables/ip6tables 为规则操作边界夹具，不能据此宣称真实内核 FakeTCP 或并发锁通过。

覆盖：两核心所有角色、同 ID/不同 ID、三种 Hysteria 传输、TCP REDIRECT/TPROXY、UDP TPROXY 配置、
单协议/全关闭、配置失败、立即退出、监听缺失、真实端口冲突、错误 PID 的 socket、双向缓存/部分写入故障、
合并发布原子性、撤销失败、SS/Hysteria 回收失败及重试、共享 ACL 引用、独立原生 SOCKS 配置实例保留（监听夹具）、
FakeTCP 多实例规则归属、旧缓存与新周期路径边界。

最终审查补充：使用只打开 TCP 或只打开 UDP 的真实 BusyBox nc 进程，验证合并发布必须具备两个监听；
发布后杀死实例，ready 必须失败；PID 启动时间不匹配时不得接受或终止该进程；
真实缓存 rename 后杀死本次进程，覆盖两核心、两协议及合并发布，检查撤销失败、保留记录与重试；
SS/Hysteria 均覆盖两个 ACL 引用逐个解绑，最后一个使用者退出前实例及 FakeTCP 规则保留。

DNS/SOCKS 只读核对：现有 `app.sh::start_dns` 的 dns2socks 模式需要 GLOBAL_SOCKS_server，
SmartDNS 也接收该参数和单节点 NODE；现有 TCP/UDP DNS 模式分别标记 TCP_PROXY_DNS/UDP_PROXY_DNS。
B2 不创建原生 SOCKS，不发布这些旧字段，也不调用 start_dns。B3/B4 必须明确 DNS 所依赖的业务协议能力及
原生 SOCKS 归属；不能在 UDP-only 配置下默认为已有 TCP 透明代理，反向情况同理。旧单节点运行路径保持原样。

## 后续衔接与待实测

1. B3 将 ACL 和两防火墙改为消费实际协议能力，继续保留 mode=0、继承、状态 2 隔离与不可恢复错误传播。
   同时处理两个远端节点的绕行，区分 Hysteria 外层传输与业务 TCP/UDP；本轮没有写旧 direct_node_list。
2. 仅透明入口成功不代表 DNS 成功；DNS 及原生 SOCKS 归属、完整继承发布仍须在接入时完成。
3. B4 才接入启动/停止、LuCI、默认配置与安全迁移，并清理新旧缓存兼容边界；现在不能启用新入口。
4. SS 的本地 bind 保留当前 0.0.0.0 行为；Hysteria 继续使用生成器的 proxy_ipv6 参数。
   实际 IPv4/IPv6 双栈监听、SS 目标构建及 Hysteria 三种外层协议的数据面必须在目标 ImmortalWrt 核验。
5. B2 的 SS 命令记录位于实例目录，没有启用通用 monitor 重启；未来接入时须审查进程重启后的身份、端口和缓存，
   不能直接让旧 monitor 重启后继续信任原 PID。运行后崩溃的完整自动恢复不在本轮实现范围。
6. 进程身份或文件系统不可读、同时无法写记录且无法停止进程等极端故障必须人工处置；错误会向调用方传播，
   不能把这些情况视作安全隔离。目标设备二进制连接、真实规则及 LAN/KMS 回归仍未由监听夹具替代。
7. 查询成功与后续规则写入之间仍可能发生进程退出；本轮没有后台监控。PID+启动时间检查与发送信号也不是内核原子操作。
   实例目录和缓存操作依赖调用方持有现有生命周期锁；测试的串行 nixio 适配不证明真实并发正确性。
   端口检查证明指定 PID 持有相应协议 socket，不证明目标 IP 地址族覆盖、IP_TRANSPARENT 或远端代理数据面可用。

## 本轮验证记录（2026-10-21）

- 原生 B2 夹具：Alpine 3.24.2 / BusyBox 1.37.0 / Lua 5.1.5，上述组合、生成器、真实进程/socket、
  缓存故障、共享归属、FakeTCP 记录和清理重试通过；nixio 锁和规则操作的夹具边界如前所述。
- 既有五组回归、Hysteria2 清理、init 状态、探测清理通过。
- B1、阶段 A 真实 UCI 及缓存/七项 ACL/两防火墙错误传播在 OpenWrt SNAPSHOT r37478-8975977f7a
  的 BusyBox ash 下通过，生产迁移仍未执行。
- Lua 5.1 语法、22 个 Shell 文件的 OpenWrt ash 语法、14 个 Node 测试文件语法及 diff/UTF-8/空白检查通过。
- 代码核对确认旧 Hysteria start/stop 函数体不变；app.sh、LuCI、ACL、防火墙、DNS、服务端、Makefile、Actions 未修改。
