# Xray、sing-box 与远端 SOCKS 客户端清理

日期：2026-10-20。仅修改工作区，不暂存、不提交、不推送、不部署；GitHub Actions 保持不变。

## 范围与依赖

最终目标只有 Shadowsocks-libev 和 Hysteria v1.3.5。这一批按已批准的顺序完成公共依赖解耦、专用运行代码删除、界面与引用清理。此前独立 Hysteria2 删除也仍保留在当前未提交工作区中。

必要链路：

| 用途 | 保留的实现 |
| --- | --- |
| SS 全局透明代理 | ss-redir，现有 TCP REDIRECT / TPROXY 与 UDP 支持 |
| SS 设备 ACL | ss-local → ipt2socks；dns2socks → 本地 SOCKS |
| Hysteria 全局、ACL | 原生 TCP REDIRECT、TCP/UDP TPROXY，同时保留本地 SOCKS |
| 独立本地 SOCKS 服务 | SS-libev 或 Hysteria 对应节点生成并启动 |
| HTTP | Hysteria 原生入口；没有为 SS-libev增加 HTTP 转换 |
| DNS 分流 | dnsmasq、ChinaDNS-NG、可选 SmartDNS、dns2socks 和现有 helper |
| 基础规则 | 国内外域名/IP、直连/代理/屏蔽列表、规则更新与 nftables/IP 集合 |

`ipt2socks` 在 Makefile 两种透明代理配置下仍被选择，`dns2socks` 仍是 LuCI 包依赖。`xray-plugin`、`v2ray-plugin` 是 SS-Rust 当前仍可使用的独立插件包，不等于 Xray-core；与 SS-Rust 一同留待后续阶段处理。Geo 数据、geoview 仍被基础规则转换和查询使用，保留数据路径及规则源 URL。

## 实际删除的文件

以下均以 `luci-app-passwall/luasrc/` 为根：

- `model/cbi/passwall/client/type/0_socks.lua`
- `model/cbi/passwall/client/type/1_sing-box.lua`
- `model/cbi/passwall/client/type/2_xray.lua`
- `model/cbi/passwall/server/type/1_sing-box.lua`
- `model/cbi/passwall/server/type/2_xray.lua`
- `passwall/util_xray.lua`
- `passwall/util_sing-box.lua`
- `model/cbi/passwall/client/include/shunt_options.lua`
- `model/cbi/passwall/client/shunt_rules.lua`
- `view/passwall/rule/shunt_rule_list.htm`
- `view/passwall/include/node_change.htm`

此前一批删除的 `client/type/5_hysteria2.lua`、`server/type/5_hysteria2.lua` 和 `passwall/util_hysteria2.lua` 继续保持删除状态。

公共文件中的对应入口同步清理：`app.sh` 的核心启动函数与 DNS/全局/SOCKS/ACL 分支，`server_app.lua` 的核心分支，`com.lua` 下载与版本注册，Makefile 的核心选项，LuCI 全局、ACL、组件设置和高级分流菜单，默认配置的旧核心节点与新安装用高级分流种子。没有批量删除用户现有 UCI section。

## 失败隔离与配置迁移

- `check_node_supported()` 拒绝旧 Xray、sing-box、Hysteria2、远端 Socks 类型，以及把独立 SOCKS 服务作为节点使用的旧引用。核心级 `_shunt`、`_balancing`、`_urltest`、`_iface` 不作为可用节点。
- `check_dns_config()` 在启动进程、发布全局端口或初始化 ACL 前拒绝失效 DNS 后端。全局无效会设置失败标志并取消全局透明代理；合法独立本地服务和独立配置 ACL 继续初始化。依赖失效全局配置的 ACL 会明确跳过。
- `fail_acl()` 只清理该 ACL 的节点、端口、DNS、默认及 FakeDNS 缓存和生成目录，不按共享节点缓存寻找或停止其他实例。nftables 继续使用既有失败标志保护。
- 全局 dns2socks 使用当前全局节点自己的本地 SOCKS 监听。旧 `socks_server` 若指向其他地址或端口则拒绝，不自动改到其他后端。请在 LuCI 重新选择 DNS 模式并保存，以清除旧字段；也可人工核对后清除该旧 UCI 选项。
- 旧 SS 的非零 HTTP 端口记录会明确告警并停用 HTTP 转换，保留其 SOCKS。Hysteria 原生 HTTP 的编辑与状态显示保留；同一 Hysteria 实例的 HTTP 状态不再依赖旧转换器的 `_http` 文件名。
- URL 测试、自动切换探测会拒绝退休类型，并处理真实启动函数的失败；不再绕过启动器直接连接远端 SOCKS。Hysteria 的探测清理继续调用原运行管理器。
- 自动切换的手动后备列表也按现行有效节点过滤，避免持续选择旧核心或已不存在的节点；批量候选同样来自有效节点列表。

升级前备份配置、证书，并使用旧版本脚本停止 Client/Server，确认旧进程与规则释放后再升级。正常包升级应移除旧包的非 conffile；加载器额外跳过已知旧类型文件，避免不完整升级再次注册。不要无条件删除用户自定义文件或其他包文件，也不自动把旧节点改成 SS/Hysteria。原有 DNS helper、旧 Geo 数据路径和规则源命名保留；其中未进入现行节点链路的高级分流兼容解析分支不等于保留 Xray/sing-box 的配置生成或启动实现。

## 验证与边界

回归直接执行生产代码，系统命令、UCI、CBI 控件或核心进程边界使用替身：

- 真实 LuCI 页面与加载器：保留两种节点所需字段、三种 Hysteria 传输、CA、证书、本地 SOCKS/HTTP；旧文件残留不注册；远端 SOCKS 不出现在节点选择中。
- 真实生成器与服务端调度：SS 三种 AEAD、旧插件隔离；Hysteria Client/Server 三种传输、认证、标志、IPv4/IPv6及失败回滚；旧 Xray/sing-box/Hysteria2 服务端不生成配置、不启动、不开放端口。
- 真实 app/nftables 函数：失效节点/旧 DNS 与有效 ACL 混合；全局 DNS 失效时合法独立 SOCKS、有效 ACL 不被停止；显式停止保持公共进程和防火墙清理。
- 真实 dnsmasq `copy_instance()`：保留局域网域名、反向解析、hosts、KMS `_vlmcs._tcp` SRV；仅替换该实例的监听端口与默认上游。
- 真实探测函数及清理器：检查 curl 的实际本地 SOCKS 参数、启动失败、清理失败重试和退休类型阻断。

仍须在 VMware/实体 OpenWrt 验证 IPK 升级残留、完整 LuCI 保存/应用、实际 DNS 与 KMS 查询、TCP/UDP 数据面和 IPv6、三种 Hysteria 外层传输及服务端入站防火墙。自动化不代表这些设备测试已完成。

当前保留的 SS-Rust、SSR、NaiveProxy 和独立 SOCKS 服务端工具仍须在后续阶段单独退出；本轮结果不是最终双核心版本。

本轮验证结果：原生 Lua 5.1 全文件语法、37 个 Lua 文件的解析检查、12 个节点模板 JavaScript 变体、OpenWrt BusyBox ash、真实 UCI 清理/SS 启动、手动 Client/Server 管理、退休入口与升级残留、全局/混合 ACL 故障隔离、Hysteria v1 原生 Lua 5.1 全套回归、探测生命周期及 init 状态回归均通过。`git diff --check` 通过，GitHub Actions、SS/Hysteria 生成器、Hysteria 运行管理器、三个 DNS helper 和规则更新器均无改动。故障注入的拒绝及清理失败日志为预期结果，不代表测试失败。
