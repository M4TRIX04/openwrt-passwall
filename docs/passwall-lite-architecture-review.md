**最终功能边界与本轮实施状态（2026-10-19）**

Passwall Lite 仅供私人使用，目标只保留 Shadowsocks-libev 与指定原版 Hysteria，**两者均必须保留 Client 与 Server 完整链路**。节点全部通过 LuCI 手动配置；取消全部代理订阅、分享链接导入导出，以及 SS-libev 的 SIP003 插件。不保留或重实现 `_shunt`、`_balancing`、`_urltest` 等核心级特殊节点。必须保留原生国内外域名/IP 分流、自定义直连/代理/屏蔽规则、DNS 和本地域名解析、KMS SRV、ACL、TCP/UDP 透明代理及 nftables/IP 集合。

本轮已实施：

- 删除订阅专用 CBI 页面、模板、订阅及 Clash 转换脚本；删除菜单、控制器操作、定时/循环/开机订阅任务，以及默认订阅设置和仅转换器使用的 `lyaml` 包依赖。
- 删除节点分享模板、二维码库、列表链接导入弹窗及接口、分享缓存重导入和仅分享工具栏使用的配置导出接口。保留普通节点编辑、类型切换、复制/删除、分组及公共表单校验。
- 删除 SS-libev 插件表单和客户端启动传递的插件包装参数；生成器忽略旧 SS 节点的插件字段。服务端写出配置前也剔除 SS 自定义 JSON 中的 `plugin`/`plugin_opts`。三种 AEAD、TCP/UDP 模式和 `ss-local`/`ss-redir`/`ss-server` 启动能力保留。
- 删除上一轮未提交的订阅/链接测试，改为手动配置和 Client/Server 回归测试。此前新增的默认手动创建 SS 节点行为保留。
- 升级初始化只删除旧订阅配置 section，保留已有节点。旧订阅 cron 仅保留清理语句，不再调度；规则更新继续使用原锁文件名 `_sub_rule.lock` 与服务重启互斥，避免无关的锁迁移。

保护范围：当前 Hysteria 客户端/服务端类型和生成器不改协议；`server_app.lua` 的 Hysteria 启停、监听和 firewall UCI 放行逻辑保留。SS 服务端类型、用户管理、UDP 开关及防火墙处理保留。共享的 Base64 API 仍被服务端自定义 JSON 和规则更新使用；SS-Rust 的插件生成/包装/清理以及其他核心的插件构建选项暂时保留，不能因取消 libev 插件而一起删除。

本轮不删除 Xray、sing-box、SSR、SS-Rust，也不实施 Hysteria 原版适配或特殊节点清理。后续删除 Xray/sing-box 时，仍需处理核心 DNS 后端、普通 SOCKS 转接、HTTP 转换和旧配置引用；订阅/链接已不再构成保留它们的理由。地理数据工具、规则下载、测速和自动切换仍按公共用途保留。

验证：全部现存 Lua 文件按 Lua 5.1 解析；修改的节点模板 JavaScript 进行语法检查；使用真实 SS/Hysteria 生成器及完整服务端 dispatcher，在内存替身环境验证旧插件隔离、端口、启动停止及防火墙规则，回归 SS-Rust/SSR；检查删除引用和 shell 语法。运行时验证不等于真实 OpenWrt/LuCI 集成测试，真实设备的保存、透明代理、DNS/KMS 与服务生命周期仍需回归。本轮不提交、不推送。

**以下保留此前审查记录，涉及订阅、链接及算法导入的内容均为历史背景；当前范围与实施状态以上述最终决策为准。**

审查结论（早期决策）：**Passwall Lite 保留 Shadowsocks-libev 与目标 Hysteria 两种代理核心，保留原生基础分流；不保留或重新实现 `_shunt`、`_balancing`、`_urltest` 等核心级特殊节点。Xray、sing-box 可以整体退出目标架构，无需为高级分流建立替代执行层。** 实施删除前仍须处理它们承担的 DNS 后端、SOCKS 转接和 HTTP 代理转换入口，以及旧配置引用。

Shadowsocks-libev 已恢复主要运行链路；订阅、链接导入导出及默认节点选择已完成工作区修复，待人工审查和设备验证，**构建依赖仍未补齐**。局域网 DNS 的主要风险集中在 SmartDNS 接管路径，尤其是 dnsmasq 提供的 KMS SRV 记录。

初次审查仅进行了本地静态阅读与引用追踪。此版本报告纳入后续架构决策及 SS-libev 节点管理修复状态；本次更新只修改本报告，不删除或修改代码，不提交、不推送。当前分支为 `passwall-lite`；工作区已有上一项 SS-libev 功能修复和测试，不能再将其描述为无 Git 差异。

下文使用：

- **【确认】**：由当前代码直接支持。
- **【推断】**：根据调用关系推导出的影响。
- **【待测】**：需要目标 OpenWrt、实际核心或网络环境验证。

**一、项目架构概览**

当前工作区主要是 `luci-app-passwall` 软件包，而非完整 OpenWrt 构建树。代理核心二进制和对应软件包源码不在本仓库内，因此无法仅凭这里的代码确认具体 libev、Hysteria 版本及编译能力。

| 层次             | 主要目录/文件                                                              | 职责                                            |
| ---------------- | -------------------------------------------------------------------------- | ----------------------------------------------- |
| 打包与依赖       | `luci-app-passwall/Makefile`                                               | OpenWrt 包依赖、可选核心、安装后处理            |
| LuCI 控制入口    | `luasrc/controller/passwall.lua`                                           | 页面路由、节点操作、状态、日志、更新接口        |
| LuCI 配置模型    | `luasrc/model/cbi/passwall/client/`、`server/`                             | 全局、节点、订阅、规则、ACL、服务端配置         |
| 页面与浏览器逻辑 | `luasrc/view/passwall/`、`htdocs/luci-static/resources/view/passwall/`     | 页面模板、链接解析、交互                        |
| 公共 Lua API     | `luasrc/passwall/api.lua`                                                  | UCI、节点枚举、二进制检测、下载、版本、CBI 兼容 |
| 核心适配         | `luasrc/passwall/util_*.lua`                                               | 生成客户端、服务端、协议转换配置                |
| 客户端运行编排   | `root/usr/share/passwall/app.sh`                                           | 全局代理、SOCKS、DNS、ACL、启动停止             |
| 防火墙           | `nftables.sh`、`iptables.sh`                                               | 透明代理、DNS 重定向、集合与策略路由            |
| DNS              | `helper_dnsmasq.lua`、`helper_chinadns_add.lua`、`helper_smartdns_add.lua` | DNS 配置、域名规则、IP 集合联动                 |
| 运维任务         | `utils.sh`、`monitor.sh`、`tasks.sh` 等                                    | 进程记录、守护、定时更新、测速、切换            |
| 系统集成         | `root/etc/init.d/`、`hotplug.d/`、`uci-defaults/`                          | 服务生命周期、联网重启、初始化与迁移            |

客户端主流程为：

```text
LuCI / UCI
    ↓
/etc/init.d/passwall：锁、启动延迟、重启协调
    ↓
app.sh start
    ├─ get_config
    ├─ start_haproxy / start_socks
    ├─ check_run_environment
    ├─ start_global → 核心配置生成与启动
    ├─ start_dns → DNS 转发与分流
    ├─ nftables.sh start
    │    └─ load_acl → acl_app → ACL 专用核心和 DNS
    └─ start_crontab → 定时任务及守护
```

【确认】服务端是另一条独立链路：

```text
/etc/init.d/passwall_server
    → server_app.lua start/stop
    → util_*.gen_config_server
    → 启动服务端二进制
    → 创建/清理 firewall UCI 放行规则
```

关键入口见 [app.sh](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:1725)、[server_app.lua](/D:/Passwall/openwrt-passwall/luci-app-passwall/luasrc/passwall/server_app.lua)。

**二、代理核心配置、启动和进程管理入口**

| 核心/类型  | 配置生成                                  | 客户端启动                                                | 服务端启动                          |
| ---------- | ----------------------------------------- | --------------------------------------------------------- | ----------------------------------- |
| SS/libev   | `util_shadowsocks.lua`                    | `run_socks()` → `ss-local`；`start_global()` → `ss-redir` | `server_app.lua` → `ss-server`      |
| SS-Rust    | 同一 `util_shadowsocks.lua`               | `sslocal`                                                 | `ssserver`                          |
| SSR        | 同一 `util_shadowsocks.lua`               | `ssr-local`、`ssr-redir`                                  | `ssr-server`                        |
| Xray       | `util_xray.lua`                           | `run_xray()`                                              | `server_app.lua`                    |
| sing-box   | `util_sing-box.lua`                       | `run_singbox()`                                           | `server_app.lua`                    |
| NaiveProxy | `util_naiveproxy.lua`                     | `run_socks()`、`start_global()`                           | 当前服务端类型目录无独立 Naive 类型 |
| Hysteria2  | `util_hysteria2.lua`                      | `run_socks()`、`start_global()`                           | `server_app.lua`                    |
| SOCKS      | `gen_proto_config()` 或直接使用远端 SOCKS | 部分转接依赖 Xray/sing-box；透明入口使用 `ipt2socks`      | `microsocks`                        |

【确认】Trojan、VMess、VLESS、TUIC 等大量协议并不是各有独立启动脚本，而是嵌在 Xray/sing-box 适配器及类型页面中。删除时需要同时检查 `type` 和 `protocol`，不能仅按二进制名称搜索。

主要位置：

- [app.sh:97](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:97)：`run_singbox()`。
- [app.sh:214](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:214)：`run_xray()`。
- [app.sh:350](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:350)：`run_socks()`。
- [app.sh:555](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:555)：`start_global()`。
- [app.sh:1438](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:1438)：`acl_app()`。

进程管理存在客户端和服务端两套实现：

- 【确认】客户端 `utils.sh::ln_run()` 创建临时二进制链接，记录 PID、进程启动时间及重启命令；`monitor.sh` 依据这些记录恢复退出进程，每个记录每日最多重启 10 次。
- 【确认】客户端 `app.sh::stop()` 清理防火墙、策略路由、插件 PID、临时路径进程、定时任务，并恢复部分 DNS 和桥接设置。
- 【确认】服务端 `server_app.lua` 自行后台启动，停止时通过临时路径匹配进程并 `kill -9`；没有接入客户端同一套进程记录。
- 【待测】多服务实例、异常退出、核心升级和重复启动情况下，服务端进程清理是否可靠。

**三、代理核心与公共功能的依赖关系**

| 公共功能                                      | 对 Xray/sing-box 的依赖                     | 精简判断             |
| --------------------------------------------- | ------------------------------------------- | -------------------- |
| nftables TCP REDIRECT                         | 基础路径不依赖                              | 保留                 |
| TCP/UDP TPROXY、策略路由                      | 基础路径不依赖，要求接收端支持              | 保留                 |
| 国内 IP、直连/代理/屏蔽集合                   | 基础路径不依赖                              | 保留                 |
| dnsmasq / ChinaDNS-NG 分流                    | 基础路径不依赖                              | 保留                 |
| SmartDNS 分流及 SOCKS 上游                    | 基础路径不依赖                              | 保留或作为可选后端   |
| ACL 按设备选择节点                            | 普通节点存在独立路径                        | 保留                 |
| `_shunt` 高级分流节点                         | 当前实际路由决策依赖核心                    | 删除，不重实现       |
| `_balancing`、`_urltest`、`_iface` 等核心级特殊节点 | 与核心能力绑定                         | 随核心移除，清理旧引用 |
| Xray/sing-box DNS、FakeDNS                    | 直接依赖                                    | 迁移配置后删除       |
| SS 的 HTTP 代理转换                           | 当前依赖 Xray/sing-box                      | 删除该选项或另行适配 |
| 部分 SOCKS 转接                               | 当前依赖 `gen_proto_config()`               | 先重构               |
| GeoIP/GeoSite 规则展开                        | 依赖 geoview/数据文件，不等同于依赖代理核心 | 按规则需求决定       |

【确认】`nftables.sh` 自己实现了独立的 `inet passwall` 表、集合、DNS 链、TCP 重定向、UDP TPROXY、fwmark 及路由表 999。它不需要通过 Xray/sing-box 才能建立基础透明代理。

参考 [nftables.sh:951](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/nftables.sh:951)、[nftables.sh:1227](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/nftables.sh:1227)。

但应区分两类“分流”：

1. **基础分流**：国内外、直连/代理/屏蔽域名及 IP、ACL，现有公共框架可以继续承担。
2. **高级分流**：按规则选择不同节点、核心内路由、特殊出站等，当前 `_shunt` 与 Xray/sing-box 深度结合。

【架构决策】保留基础规则对目的域名/IP 的直连、代理、屏蔽判断，以及 ACL 按设备/IP 选择普通节点。取消核心内按规则选择多个出站的特殊节点功能，不建设替代 `_shunt` 的规则执行层。ACL 仍可为不同设备选择不同普通节点，不能将“取消高级分流”解释为所有设备只能共用同一节点。这里的 DNS `dns_shunt` 是 DNS 后端选择，与节点 `protocol="_shunt"` 不同，必须保留前者。

**公共依赖复查与删除前置条件**

| 功能 | 代码确认的位置 | 无 Xray/sing-box 时的处理 |
| --- | --- | --- |
| 独立及合并 DNS 后端 | `app.sh::start_dns()` 的 `sing-box`/`xray` 分支（约 1170、1213 行），`start_global()`、`acl_app()::run_dns()`（约 1573 行） | 删除这些核心后端及 FakeDNS 配置；保留 dnsmasq/ChinaDNS-NG/所选 SmartDNS 后端。必须迁移或明确拒绝旧全局和 ACL DNS 模式，避免空监听或假启动成功 |
| 全局普通 SOCKS 节点的透明转发 | `app.sh::start_global()` 的 `socks` 分支与 `run_ipt2socks()`（约 74、568、615、859 行） | 已有直接 SOCKS → ipt2socks 的透明转发路径，不必保留多协议核心；但其附加本地 SOCKS/HTTP 监听仍调用下述转接路径，不能据此认定全部 SOCKS 功能无依赖 |
| 本地 SOCKS 转接/再暴露 | `app.sh::run_socks()` 的 `socks` 分支（约 415–443 行） | 当前只选择 sing-box/Xray 的 `gen_proto_config()`，没有二者时不生成对应转接进程。若保留普通远端 SOCKS 节点，需明确关闭该转接能力或单独适配；若只接受 SS/Hysteria 普通节点，可移除该输入类型。保留 SS 的 `ss-local` 输出及目标 Hysteria 的已验证 SOCKS 输出 |
| HTTP 监听与 SOCKS → HTTP 转换 | `app.sh::run_socks()` 的 HTTP 转换块（约 525–549 行）；`client/socks_config.lua` 的 `http_port`；`global.lua` 的全局 HTTP 选项当前被注释 | libev 没有通过当前生成器提供 HTTP 入口，转换依赖 `gen_proto_config()`。HTTP 监听不是本次必保留能力，建议移除依赖核心的转换及 UI/旧配置入口，无需新增转换器；目标 Hysteria 是否有原生 HTTP 能力须另行确认 |
| 订阅、规则下载、测速、自动切换 | `api.lua::curl_proxy()`（约 328 行）、`test.sh`、`socks_auto_switch.sh` 调用 `app.sh run_socks` | `curl_proxy` 使用 `GLOBAL_SOCKS_server` 和 curl 的 `socks5h://`，本身不要求 Xray/sing-box；保留 SS/Hysteria 的 SOCKS 输出及进程管理。测速与自动切换不等同于 `_urltest` 特殊节点，不应一并删除 |
| GeoIP/GeoSite 展开 | `helper_*.lua` 的 geoview 调用、`utils.sh::get_geoip()`、`rule_update.lua` | 数据工具不依赖 Xray/sing-box 二进制；基础自定义列表也接受相应语法，不能因删除 `_shunt` 就自动删除 geoview/数据文件。是否保留这类规则语法应单独决定 |
| SS 插件 | `client/type/4_ss.lua`、`util_shadowsocks.lua` | `xray-plugin`、`v2ray-plugin` 是独立插件二进制，不等于 Xray 核心。删除核心不会自动替代或删除插件需求；按 SS 插件支持范围另行处理 |

【确认】以上剩余依赖不要求保留 `_shunt`。核心生成器可以在对应入口清理后整体删除，而不是为了公共转换长期保留一个缩小版 Xray/sing-box 适配器。

【待测】实际删除核心后需在完全未安装二者的设备上验证 DNS 监听、普通 ACL、订阅下载和测速。尤其不能只验证浏览器代理连通性。

**四、Shadowsocks-libev 当前集成状态**

**已恢复的部分**

- 【确认】客户端 `client/type/4_ss.lua` 注册 `type="SS"`，设置地址、端口、密码、三种 AEAD 加密、超时、TFO 和插件。
- 【确认】服务端 `server/type/4_ss.lua` 注册 `SS`，支持用户密码引用、JSON 自定义配置、UDP 和防火墙放行。
- 【确认】`util_shadowsocks.lua::gen_config()` 已有 `SS` 分支，输出 `mode`、插件和基础连接参数。
- 【确认】`run_socks()` 使用 `ss-local -c ... -v`，生成 `mode="tcp_and_udp"`。
- 【确认】`start_global()` 使用 `ss-redir -c ... -v`，生成相同模式，并在 TCP TPROXY 时传入 `tcp_tproxy`。
- 【确认】服务端使用 `ss-server -c ...`，按 `udp_forward` 添加 `-u`。
- 【确认】`REDIRECT_LIST`、`TPROXY_LIST` 均包含 `ss`。
- 【确认】普通 SS ACL 走 `ss-local → ipt2socks`，而非全局的 `ss-redir` 路径。
- 【确认】节点被加入 `direct_node_list`，供防火墙排除代理服务器连接，避免回环。

配置生成见 [util_shadowsocks.lua](/D:/Passwall/openwrt-passwall/luci-app-passwall/luasrc/passwall/util_shadowsocks.lua)，全局启动见 [app.sh:800](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:800)。

**初次审查发现的遗漏及后续状态**

本节下表保留初次发现作为背景。后续 SS-libev 功能修复已在当前工作区补齐订阅实现选择、全局/单订阅列表、链接导入导出和默认新建节点；选择值为 `shadowsocks-libev`，节点类型为 `SS`，订阅和链接对三种指定算法做明确校验。这些改动尚待人工审查及真实 OpenWrt 验证。构建依赖仍未补齐，客户端/服务端启动逻辑未改。

| 问题                            | 证据与影响                                                                                         |
| ------------------------------- | -------------------------------------------------------------------------------------------------- |
| 构建依赖未恢复                  | `Makefile` 没有 libev 客户端/服务端选择项，也未声明三个目标二进制的软件包依赖                      |
| 订阅不支持选择 libev            | `subscribe.lua` 无 `has_ss`；`DEFAULT_SS_TYPE`、`core_has`、`set_ss_implementation()` 均没有 libev |
| 仅安装 libev 时 SS 订阅会被跳过 | `set_ss_implementation()` 无匹配后直接返回 `nil`                                                   |
| 全局及单订阅界面缺少 libev      | `node_subscribe.lua`、`node_subscribe_config.lua` 的 SS 核心列表仅包含 Rust/Xray/sing-box          |
| 浏览器 SS 链接导入缺少 libev    | `link_share_man.htm` 未匹配 Xray/sing-box 时回落到 `SS-Rust`                                       |
| SS 链接导出判断缺少 `SS`        | 相关分支接受 `SS-Rust` 或核心内 shadowsocks，没有独立 `SS`                                         |
| 新建节点默认选择缺少 SS         | `controller/passwall.lua::add_node()` 无 `ss-local` 分支，安装 ipt2socks 时优先创建 Socks 类型     |

最直接的证据见 [subscribe.lua:521](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/subscribe.lua:521)、[link_share_man.htm:995](/D:/Passwall/openwrt-passwall/luci-app-passwall/luasrc/view/passwall/node_config/link_share_man.htm:995)、[controller/passwall.lua:482](/D:/Passwall/openwrt-passwall/luci-app-passwall/luasrc/controller/passwall.lua:482)。

**需要继续验证的边界**

- 【确认】客户端类型显示条件是“存在 `ss-local` 或 `ss-redir`”，并不要求两者同时存在。**【推断】**可能出现界面可选、某条启动路径缺二进制的情况。
- 【确认】插件生成器依据 `node.plugin` 决定是否启用，没有直接检查 `plugin_enabled`。**【待测】**关闭插件开关后旧字段是否被 CBI 清理，避免插件仍被加载。
- 【确认】SS UI 仅列出三种 AEAD，而 Clash 转换器接受包括 SS2022 在内的更多方法。需要统一目标 libev 的算法白名单。
- 【待测】目标 libev 是否接受当前 JSON `mode`、`tcp_tproxy`、IPv6 监听格式，及对应 UDP 行为。不能仅以存在配置字段认定功能通过。
- 【待测】全局 `ss-redir` 和 ACL `ss-local + ipt2socks` 两条路径都需要独立验证 UDP、IPv6、DNS 与回环排除。
- 【确认】SS 的 HTTP 输出当前借助 Xray/sing-box 转换；移除二者后该功能不能自然保留。

**五、局域网 DNS、本地域名与 KMS SRV**

这是本次最应优先保护的部分。

**dnsmasq 路径**

【确认】`helper_dnsmasq.lua::copy_instance()` 会读取系统生成的 dnsmasq 配置：

- 过滤 DHCP、ubus、默认上游、监听端口等配置。
- 保留 `address=`。
- 保留含 `/` 的按域 `server=`。
- 复制 `conf-dir` 中的文件，再清理 Passwall 自身配置。
- 添加由 `lease2hosts.sh` 维护的 hosts 文件。

参考 [helper_dnsmasq.lua:116](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/helper_dnsmasq.lua:116)。

【推断】普通 `srv-host=` 行没有被明确过滤，因此系统主配置中直接生成的 KMS SRV 记录具备保留路径。但不能保证所有安装方式：

- KMS 配置可能由外部插件、`conf-file` 或配置目录提供。
- ACL 的 ChinaDNS-NG 模式和不同配置目录加载方式仍需验证。
- 当前工作区没有设备实际 `/etc/config/dhcp` 及生成配置，无法确认真实 KMS 记录来源。

**SmartDNS 接管路径**

【确认】`app.sh::start_dns()` 在 `DNS_REDIRECT=1` 且使用 SmartDNS 时，直接将 DNS 重定向端口设置为 SmartDNS，跳过额外 dnsmasq 转发实例。

【确认】`helper_smartdns_add.lua` 导入：

- `local-domain`；
- `/etc/hosts`、`/tmp/hosts/*`；
- 静态 DHCP IPv4 主机；
- dnsmasq 和部分 odhcpd 租约文件。

**【确认】未发现该路径导入 dnsmasq 的 `srv-host`、UCI SRV 记录，或将本地域的所有查询转回系统 dnsmasq 的明确逻辑。**

参考 [helper_smartdns_add.lua:197](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/helper_smartdns_add.lua:197)、[app.sh:1390](/D:/Passwall/openwrt-passwall/luci-app-passwall/root/usr/share/passwall/app.sh:1390)。

**【推断，高优先级】SmartDNS 下主机 A/AAAA 正常，不代表 `_vlmcs._tcp.<本地域>` SRV 正常。** KMS 自动发现可能被送往外部 DNS 或得到空响应。

建议后续重构明确一个规则：**系统 dnsmasq 继续作为局域网 DNS 记录的权威入口，本地域及相关反向域的查询应完整保留其语义。** 若采用转发实现，需要同时处理回环和 DNS 重定向豁免。

此外：

- 【确认】`lease2hosts.sh` 启动时只读取一次静态 DHCP 配置，动态租约每 60 秒更新。
- 【推断】服务运行中修改静态 DHCP 主机后，复制 dnsmasq 路径可能需要重启 Passwall 才能同步。
- 【待测】PTR、CNAME、SRV、TXT、负缓存、无点主机名与 IPv6 本地记录均应单独检查。

**六、Hysteria 适配风险**

当前代码中的独立核心实际上是 `type="Hysteria2"`，不能因为二进制叫 `hysteria` 就认定与目标实现兼容。

| 接口           | 当前入口                                                        | 替换时关注点                            |
| -------------- | --------------------------------------------------------------- | --------------------------------------- |
| 类型与表单     | `client/type/5_hysteria2.lua`、`server/type/5_hysteria2.lua`    | 类型标识、字段、能力声明                |
| 配置生成       | `util_hysteria2.lua`                                            | JSON schema、认证、TLS、带宽、QUIC      |
| 客户端 CLI     | `app.sh::run_socks/start_global`                                | 当前为 `-c <file> client`               |
| 服务端 CLI     | `server_app.lua`                                                | 当前为 `-c <file> server`               |
| 透明入口       | `util_hysteria2.lua::gen_config`                                | `tcpRedirect`、`tcpTProxy`、`udpTProxy` |
| ACL            | `app.sh::acl_app`                                               | SOCKS5 UDP 能力及 ipt2socks 兼容        |
| 订阅/链接      | `subscribe.lua`、`clash_subconverter.lua`、`link_share_man.htm` | URI、参数、类型选择                     |
| 节点校验与展示 | `api.lua`                                                       | 端口跳跃、Realm、节点有效性             |
| 回环豁免       | `nftables.sh::filter_node`                                      | 当前识别 `hysteria2_hop`                |
| 下载更新       | `com.lua`、`api.lua`、更新页面                                  | 仓库、版本解析、文件格式                |
| 打包/默认值    | `Makefile`、`0_default_config`                                  | 包来源、二进制路径                      |

【确认】当前 `com.lua` 将 Hysteria 更新来源绑定到 HyNetwork 及 Passwall 的 release 缓存，并假定特定 `version` 输出格式。若目标是私有或不同实现，保留这条更新链可能安装错误二进制。

参考 [com.lua:29](/D:/Passwall/openwrt-passwall/luci-app-passwall/luasrc/passwall/com.lua:29)。

**已发现的具体问题：**

- 【确认】`clash_subconverter.lua:386` 的旧 Hysteria 编码函数被命名为 `encode_hysteria2`。
- 同文件 `:411` 又声明一个 `encode_hysteria2`。
- `:561` 的旧 Hysteria 分支调用 `encode_hysteria(node)`，未找到对应定义。
- 【推断】处理该类 Clash 节点时会产生调用不存在函数的错误；具体影响一个节点还是整批订阅，需结合异常处理运行验证。

另外，`util_hysteria2.lua` 中 `disablePathMTUDiscovery` 使用字段是否存在进行判断，字符串 `"0"` 在 Lua 中也为真。**【确认】**这与明确比较 `"1"` 的写法不同；**【待测】**需要检查 UI 实际保存形式。

目标版本和 CLI 确认前，建议只定义适配契约，不复用协议配置：

- 配置文件格式与启动、停止方式；
- SOCKS5 TCP/UDP；
- 原生 REDIRECT/TPROXY 是否支持；
- IPv4/IPv6 监听；
- 服务器连接、端口跳跃及回环豁免；
- 日志、环境变量和退出状态；
- 订阅 URI 与迁移规则。

**七、可删除模块清单**

“可直接删除”指它们没有必须保留的公共职责，仍需同时清理注册、构建选项和旧配置引用。

| 分类                 | 模块                                               | 条件                                     |
| -------------------- | -------------------------------------------------- | ---------------------------------------- |
| 可直接移除的独立适配 | `util_naiveproxy.lua`、`client/type/6_naive.lua`   | 确认废弃 Naive                           |
| 可直接移除的类型页面 | 客户端/服务端 `4_ssr.lua`、`3_ss-rust.lua`         | 同时移除启动及订阅分支                   |
| 可删除的核心专属内容 | Xray/sing-box 页面内协议字段、专属默认配置         | 公共入口已解耦、旧节点已迁移             |
| 可选功能             | HAProxy 配置、脚本、页面                           | 用户需求未强制保留负载均衡，需先确定范围 |
| 可选插件             | Shadow-TLS、v2ray-plugin、xray-plugin、Simple-obfs | SS 插件需求明确后决定                    |
| 可删除的旧防火墙后端 | `iptables.sh`                                      | 先强制 nftables 并移除回落路径           |
| 可选地理数据功能     | geoview、GeoIP/GeoSite 下载与展开                  | 已不再接受对应规则语法                   |

**可随核心删除、无需替代的高级功能：**

- `client/shunt_rules.lua`、`client/include/shunt_options.lua`、`view/passwall/rule/shunt_rule_list.htm`、`view/passwall/include/shunt_options.htm`：删除高级分流配置入口及模板，同时清理控制器菜单、增删接口和引用。
- 客户端 Xray/sing-box 类型文件中的 `_shunt`、`_balancing`、`_urltest`、`_iface` 配置与核心实现：随对应核心删除，无需迁移为等价特殊节点。这里不涉及公共 ACL 的 `interface` 匹配。
- `0_default_config` 的 `myshunt` 节点及 `shunt_rules` 示例、专属路由选项和特殊节点选择 UI：停止生成。已有特殊节点必须明确标记不支持并解除全局/ACL/备选节点引用，不能静默变成普通节点或改变代理意图。
- `helper_dnsmasq.lua`、`helper_chinadns_add.lua`、`helper_smartdns_add.lua` 中受 `_shunt`/`IS_SHUNT_NODE` 控制的高级规则展开，以及 `nftables.sh` 的 `USE_SHUNT_NODE`/`use_shunt_node` 与 `psw_shunt*` 专属分支，可定点移除。保留同文件的基础直连、代理、屏蔽和国内集合；不能整文件删除或按单词 `shunt` 批量删除。

**需要先清理公共入口与旧配置才能整体删除：**

- `util_xray.lua`、`util_sing-box.lua`：高级分流已确定取消；剩余阻碍仅为上表列出的核心 DNS 与协议转换调用、普通核心节点和服务端入口。相关功能退出或配置迁移后可整文件删除，无需重实现高级分流。
- `app.sh` 内相关启动函数：被多个公共路径调用。
- `util_shadowsocks.lua` 内 Rust/SSR 分支：同文件承载必须保留的 libev。
- `subscribe.lua`、`clash_subconverter.lua`、`link_share_man.htm`：应收敛协议范围，不能整文件删除。
- `api.lua`、`com.lua`：包含公共能力及核心专属内容，需要拆分。
- Xray/sing-box 的客户端/服务端类型、`server_app.lua` 分支、订阅/链接选择与回落、`com.lua` 更新项、`global.lua`/`acl_config.lua` DNS 选项、Makefile 依赖和默认配置：随功能一起清理，防止安装或选回已删除核心。
- `util_hysteria2.lua`：目标适配完成后替换，不能仅改文件名和类型名。

**八、必须保留的公共模块**

至少应保留以下职责及对应实现：

- `controller/passwall.lua`：管理入口、状态、日志和节点操作。
- 全局、节点、订阅、规则、ACL、服务端用户的 CBI 模型及必要模板。
- `api.lua` 中 UCI、节点管理、地址处理、公共 CBI 兼容功能。
- `app.sh` 的服务编排和 ACL。
- `utils.sh` 的配置、端口、进程、日志、缓存及路由辅助。
- `nftables.sh` 的透明代理、DNS 重定向、集合、回环保护及恢复。
- `helper_dnsmasq.lua`；保留所选 DNS 后端的生成器。
- `lease2hosts.sh`，只要仍使用额外 dnsmasq 实例。
- `rule_update.lua`、必要的规则文件和用户规则目录。
- `subscribe.lua` 及需要支持的订阅转换。
- `monitor.sh`、`tasks.sh` 和服务启动停止入口。
- `server_app.lua`、服务端用户及防火墙管理。
- hotplug、ucitrack、rpcd ACL、初始化及配置迁移逻辑。

**【确认】`ipt2socks` 名称虽然带 `ipt`，当前 nftables ACL 路径仍使用它。不能因精简为 nftables 而删除。**

**九、推荐的分阶段精简方案**

1. **固定能力和配置边界**
   已确认取消核心级特殊节点；自定义规则保留基础直连、代理、屏蔽，ACL 保留按设备/IP 选普通节点。继续固定 SS 插件、DNS 后端、IPv6、核心版本和软件包来源；建议去除依赖多协议核心的 HTTP 转换，普通 SOCKS 输入类型及转接需求另行收敛。

2. **先补齐 libev 闭环**
   完成构建依赖、类型能力检测、默认新建节点、订阅选择、链接导入导出及算法校验。先达到“系统完全没有 Xray/sing-box 也能管理和使用 SS”。

3. **优先保护本地 DNS**
   明确 dnsmasq 权威入口，处理 SmartDNS 接管下的 SRV、本地域和反向解析；建立启动、停止、异常失败后的 DNS 恢复基线。

4. **建立目标 Hysteria 适配**
   版本和 CLI 确认后实现新 schema、启动参数、能力检查、订阅和回环豁免；不静默复用 Hysteria2 节点。

5. **解除公共功能对多协议核心的依赖**
   收敛 DNS 模式与旧全局/ACL DNS 配置；移除不需要的 HTTP 转换，处理普通 SOCKS 转接入口。随后取消 `_shunt` 等特殊节点及 UI/默认值，明确处置旧引用；不编写新的高级路由执行层。此处“迁移”指配置清理及用户明确重选普通节点，不承诺特殊节点行为等价。

6. **删除核心与旧后端**
   再删除 Xray、sing-box、Rust、SSR、Naive 等内容；nftables 环境缺失时明确失败，避免留下指向已删除 iptables 的回落。

7. **整理长期同步边界**
   保持核心适配、DNS、防火墙、订阅的清晰接口，再收敛翻译、页面、更新项和文档。

**十、上游同步的维护问题**

- 【确认】Lite 的主要改动会集中在 `app.sh`、`api.lua`、`subscribe.lua`、`global.lua`、`Makefile` 等上游高耦合文件，合并冲突风险较高。
- 【确认】`0_default_config` 仍创建 `type=Xray` 的 `myshunt`，并保留核心专属配置和 GeoSite 规则。只清包依赖会留下无效默认节点。
- 【确认】初始化脚本包含节点字段迁移，例如删除旧 `udp_node`。后续直接同步上游迁移脚本可能改变 Lite 配置语义。
- 【推断】上游新增协议或默认核心选择时，可能再次引入被删除依赖，应检查构建项、订阅回落和默认配置。
- 【推断】整体替换 `app.sh` 等大文件会让后续 DNS、防火墙修复难以合并；按职责保持小补丁更容易追踪。
- 【确认】当前自身更新和组件更新沿用上游身份与下载链。私有版应处理包身份及更新来源，避免被官方包覆盖。
- 【待测】本仓库不含依赖 feed 的实际版本，必须在 OpenWrt 构建环境确认包名、功能和编译选项。

**十一、风险与测试建议**

优先级建议为：

| 优先级 | 风险                                                      |
| ------ | --------------------------------------------------------- |
| 高     | SmartDNS 接管可能丢失 KMS SRV 及其他 dnsmasq 本地记录语义 |
| 高     | 删除 Xray/sing-box 后旧 DNS、SOCKS/HTTP 转换及特殊节点残留引用失效；高级分流本身已明确取消 |
| 高     | libev 订阅及链接导入尚未适配，产生跳过节点或错误类型      |
| 高     | 目标 Hysteria schema/CLI 未确认                           |
| 中     | libev UDP、TCP TPROXY、IPv6 行为尚未验证                  |
| 中     | 服务端进程清理与客户端守护机制不一致                      |
| 中     | 插件开关、旧字段和算法白名单不一致                        |
| 中     | nftables 环境不满足时可能仅警告，未形成明确启动失败       |

后续测试应覆盖：

- **纯 Lite 环境**：物理不安装 Xray/sing-box/Rust/SSR，验证启动、订阅和节点操作。
- **透明代理**：SS/Hysteria × 全局/ACL × TCP/UDP × IPv4/IPv6；分别测试 REDIRECT 和 TPROXY。
- **DNS**：dnsmasq、ChinaDNS-NG、SmartDNS 的所保留组合，UDP/TCP 53、DNS 大响应和回退。
- **局域网解析**：静态/动态主机、无点名称、A/AAAA、PTR、CNAME、SRV、TXT，以及查询不外泄。
- **KMS**：查询 `_vlmcs._tcp.<实际本地域>` 的 SRV，并继续解析目标主机；分别覆盖全局代理、独立 ACL 和 DNS 重定向开关。
- **生命周期**：启动失败、核心崩溃、连续重启、停止、WAN 重连、fw4 reload、NTP 跳时及升级后恢复。
- **分流与回环**：规则优先级、域名集合更新、节点域名解析、服务器连接豁免和端口跳跃。
- **服务端**：用户密码、UDP 开关、WAN 放行、多实例和停止后残留。
- **迁移**：旧核心节点、旧 DNS 模式、默认 `_shunt`、备份恢复和无效配置提示。

现有 `test.sh` 主要是连通性和节点探测工具，不能替代上述回归验证。

本次架构分析更新完成，仅本报告发生本轮编辑；已有功能修复保持原状，等待下一步指令。
