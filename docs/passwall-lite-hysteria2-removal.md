# Hysteria2 清理与升级注意事项

> 后续状态：2026-10-20 的 [核心精简阶段](passwall-lite-core-removal.md) 已删除 Xray/sing-box 及其生成器，因而下文先前暂留的内嵌 Hysteria2 实现也随之退出。以下范围说明保留为上一批清理的历史记录；升级时还需遵循新阶段的失效节点、旧 DNS 配置诊断说明。

目标仅保留独立 Hysteria v1.3.5。v1 的 Custom CA、认证、QUIC 窗口、UDP、FakeTCP、WeChat Video 不在删除范围内；端口跳跃仍未实现。本轮不修改 FakeTCP 运行管理器、其他协议实现及 GitHub Actions。

## 当前实施范围

- 已删除独立 Client/Server 的 `5_hysteria2.lua` 类型页和 `util_hysteria2.lua`。
- 已删除 `app.sh` 的独立 Hysteria2 SOCKS、全局透明代理启动分支及透明代理类型列表项。
- 新建节点只选择 Hysteria，不因二进制版本回退为 Hysteria2；v1 既有运行时版本校验保留。
- 旧 `type=Hysteria2` 节点不进入有效节点选择列表。客户端 SOCKS、全局及 ACL 启动前明确拒绝；服务端在配置生成、启动及防火墙放行前明确拒绝，包括独立 Hysteria2 的自定义 JSON 模式。
- 保留 Xray、sing-box 使用的 Hysteria2 端口跳跃防火墙绕行、展示和证书探测公共逻辑；它们不是独立类型的启动入口。本轮不修改 FakeTCP TTL/HL 规则及 nftables TPROXY 实现。
- **明确留待后续阶段**：经用户确认，本轮只删除独立 Hysteria2。Xray、sing-box 自身类型页和生成器的 `protocol=hysteria2` 分支保留，将随这两个核心整体移除；不应将本轮清理描述为所有核心内嵌 Hysteria2 的移除。公共拒绝逻辑仅针对 `type=Hysteria2`，不改变现存其他核心协议行为。
- `com.lua` 既有 Hysteria 下载入口已固定到官方 `v1.3.5`，版本命令为 `--version`，没有独立 Hysteria2 下载条目；保留这一 v1 更新入口，不改 Makefile 的共用二进制路径。

## IPK 升级与遗留文件

1. 升级前备份 `/etc/config/passwall`、`/etc/config/passwall_server` 及自定义证书；使用旧版本服务脚本停止客户端及服务端。先确认进程、透明代理和 FakeTCP 规则已清理，再升级包，避免热替换新旧管理器。
2. 用包管理器正常升级 IPK。上述被删除的三个 Lua 文件不是本包声明的 conffiles，正常升级应移除旧包拥有、而新包不再包含的文件。此行为仍需在实际 ImmortalWrt/opkg 环境验证。
3. 对于不完整升级留下的 `client/type/5_hysteria2.lua`、`server/type/5_hysteria2.lua` 及历史同名 `hysteria2.lua`，新类型加载器明确跳过，不执行旧页注册代码。不主动删除磁盘文件。
4. 若发现残留，先通过 `opkg search` 和 `opkg files luci-app-passwall` 核对所有权，再与旧 IPK 文件内容比较。仅对确认属于旧版 Passwall 且未被定制的文件进行人工清理；其他包所有或来源不明的文件保留并调查。本轮不提供无条件删除脚本。
5. 不删除、不自动转换旧节点、认证、证书或自定义 JSON。Hysteria2 与 v1 配置不兼容，需手动新建 v1 节点、重新选择全局/SOCKS/ACL 引用，并另行处理服务端实例。遗留节点有明确拒绝日志。
6. 正常升级后重启 rpcd/uhttpd 或整机重启以刷新 LuCI 缓存；确认只出现 v1 类型，分别验证客户端、服务端及三种传输。不要复用旧 Hysteria2 进程或配置文件测试 v1。

## 验证边界

`tests/passwall-hysteria2-removal.cjs` 执行真实 Client/Server 页面加载器、真实 `run_socks()`、`start_global()`、`acl_app()` 和 nftables ACL 规则生成函数；仅文件系统/UCI/命令边界使用测试替身。现有手动管理测试执行真实 `server_app.lua`，验证旧 Hysteria2 实例不生成配置、不启动、不开放端口，并保留邻近 SS 实例。

现有 Hysteria v1 自动化回归覆盖真实生成器、运行管理器、三种传输、认证、Custom CA、IPv4/IPv6、失败隔离和 FakeTCP 共享规则清理。自动化不能代替实际 IPK 升级、LuCI 保存、真实二进制联网及设备防火墙验证。

本轮已通过：独立 Hysteria2 删除回归、手动节点管理/SS/SSR/SS-Rust 回归、全局与混合 ACL 失败隔离回归、原生 Lua 5.1 的 Hysteria v1 回归、临时探测实例清理回归、真实 OpenWrt UCI 清理及 SS 启动回归，以及原生 Lua 5.1 / BusyBox ash 语法检查。故障注入中的拒绝、告警及清理失败日志是预期断言场景。
