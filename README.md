## Versioning

This follows the upstream date-based scheme, so that every package installed on a device can be traced back to the build it came from:

- `PKG_VERSION` is the **date of the change**, in `YY.M.D` format without zero padding — 2026-11-08 becomes `26.11.8`
- `PKG_RELEASE` is the **revision for that day**: `1` for the first change, then `2`, `3`, ... for further changes on the same day
- When the day changes, `PKG_VERSION` moves to the new date and `PKG_RELEASE` resets to `1`

Inside the package this reads as `<version>-r<revision>`, e.g. `26.11.8-r1`; the matching tag is `26.11.8-1` (same format as upstream tags).

**Bump both numbers whenever the code changes.** Otherwise consecutive builds end up with the same version, `opkg` cannot tell them apart, and there is no way to check which build a device is running. To check the installed version:

```shell
opkg list-installed | grep luci-app-passwall
```

## 📌 How do I build against the latest code?

After `./scripts/feeds install -a` has finished, run:

```shell
# 1) Remove only the 7 packages that really clash, plus the passwall shipped by the luci feed
rm -rf feeds/packages/net/{chinadns-ng,dns2socks,hysteria,ipt2socks,microsocks,tcping,shadowsocks-libev}
rm -rf feeds/luci/applications/luci-app-passwall

# 2) Add packages and luci; pull if already present, safe to re-run
if [ -d package/passwall-packages ]; then
	git -C package/passwall-packages pull --ff-only
else
	git clone --depth 1 https://github.com/M4TRIX04/openwrt-passwall-packages package/passwall-packages
fi

if [ -d package/passwall-luci ]; then
	git -C package/passwall-luci pull --ff-only
else
	git clone --depth 1 https://github.com/M4TRIX04/openwrt-passwall package/passwall-luci
fi
```
