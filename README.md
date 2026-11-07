## :mega:注意

本仓库是 PassWall 的私人精简分支，在 `26.6.2` 的基础上做了大范围的裁剪，与上游功能集**不一致**，请勿直接套用上游文档：

- **客户端节点只保留 Shadowsocks 与 Hysteria（v1）**。Sing-box、Xray、NaiveProxy、ShadowsocksR、Shadowsocks-Rust 支持已全部移除，因此 vmess / vless / trojan / hysteria2 / tuic / anytls / naiveproxy / wireguard 节点无法使用，订阅里的这些节点会被跳过。
- **分流节点（`_shunt`）、URLTest 组（`_urltest`）、自定义接口节点（`_iface`）以及链式代理（Chain Proxy）已移除**，它们是 Sing-box 专属功能。ACL 与全局设置仍可通过「节点 + DNS 分流器」实现按设备/按域名分流。
- **DNS 过滤模式只剩 `udp` / `tcp` / `dns2socks`**（原 Sing-box / Xray DNS 模式已删除），DNS 分流器仍支持 Dnsmasq / ChinaDNS-NG / SmartDNS。
- **规则页只保留 URL 列表更新**（gfwlist / chnroute / chnroute6 / chnlist）。`geo2rule`、Geoview、geoip.dat / geosite.dat 相关功能已移除，不再需要 `v2ray-geodata` 与 `geoview` 包。
- 服务端支持 Shadowsocks / Socks / Hysteria。

## 📌如何能编译到最新代码？

### 方法1：

执行 `./scripts/feeds update -a` 操作前，在 `feeds.conf.default` **顶部**插入如下代码：

```
src-git passwall_packages https://github.com/M4TRIX04/openwrt-passwall-packages.git;main
src-git passwall_luci https://github.com/M4TRIX04/openwrt-passwall.git;main
```

### 方法2：

在 `./scripts/feeds install -a` 操作完成后，执行以下命令：

```shell
# 移除 openwrt feeds 自带的核心库
rm -rf feeds/packages/net/{xray-core,v2ray-geodata,sing-box,chinadns-ng,dns2socks,hysteria,ipt2socks,microsocks,naiveproxy,shadowsocks-rust,shadowsocksr-libev,simple-obfs,tcping,v2ray-plugin,xray-plugin,geoview,shadow-tls}
git clone https://github.com/M4TRIX04/openwrt-passwall-packages package/passwall-packages

# 移除 openwrt feeds 过时的luci版本
rm -rf feeds/luci/applications/luci-app-passwall
git clone https://github.com/M4TRIX04/openwrt-passwall package/passwall-luci
```
