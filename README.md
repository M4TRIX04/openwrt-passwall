## :mega:注意

本仓库是 PassWall 的私人精简分支，基于上游 `26.6.2` 做了大范围的裁剪，与上游功能集**不一致**，请勿直接套用上游文档：

- **客户端节点只保留 Shadowsocks 与 Hysteria（v1）**。Sing-box、Xray、NaiveProxy、ShadowsocksR、Shadowsocks-Rust 支持已全部移除，因此 vmess / vless / trojan / hysteria2 / tuic / anytls / naiveproxy / wireguard 节点无法使用，订阅里的这些节点会被跳过。
- **分流节点（`_shunt`）、URLTest 组（`_urltest`）、自定义接口节点（`_iface`）以及链式代理（Chain Proxy）已移除**，它们是 Sing-box 专属功能。ACL 与全局设置仍可通过「节点 + DNS 分流器」实现按设备/按域名分流。
- **DNS 过滤模式只剩 `udp` / `tcp` / `dns2socks`**（原 Sing-box / Xray DNS 模式已删除），DNS 分流器仍支持 Dnsmasq / ChinaDNS-NG / SmartDNS。
- **规则页只保留 URL 列表更新**（gfwlist / chnroute / chnroute6 / chnlist）。`geo2rule`、Geoview、geoip.dat / geosite.dat 相关功能已移除，不再需要 `v2ray-geodata` 与 `geoview` 包。
- 服务端支持 Shadowsocks / Socks / Hysteria。

## 版本号规则

沿用上游的日期制，目的是让每次装到设备上的包都能对上是哪一次构建：

- `PKG_VERSION` = **改动当天的日期**，格式 `YY.M.D`（不补零），例如 2026-11-08 记为 `26.11.8`
- `PKG_RELEASE` = **当天的修订号**，当天第一次改动为 `1`，同一天再改就 `2`、`3`……
- 跨天后 `PKG_VERSION` 换成新日期，`PKG_RELEASE` 回到 `1`

包内呈现为 `<版本>-r<修订>`，例如 `26.11.8-r1`；对应的 tag 是 `26.11.8-1`（与上游 tag 格式一致）。

因此**改代码必须同步改这两个数字**，否则连续几次构建的版本号相同，`opkg` 分不出新旧，设备上也查不到装的是哪一版。查当前装的版本：

```shell
opkg list-installed | grep luci-app-passwall
```

## 📌如何能编译到最新代码？


在 `./scripts/feeds install -a` 操作完成后，执行以下命令：

```shell
# 1) 只删真正撞名的 7 个和luci feed 自带一个 passwall
rm -rf feeds/packages/net/{chinadns-ng,dns2socks,hysteria,ipt2socks,microsocks,tcping,shadowsocks-libev}
rm -rf feeds/luci/applications/luci-app-passwall

# 2) 放packages和luci
git clone --depth 1 https://github.com/M4TRIX04/openwrt-passwall-packages package/passwall-packages
git clone --depth 1 https://github.com/M4TRIX04/openwrt-passwall package/passwall-luci
```
