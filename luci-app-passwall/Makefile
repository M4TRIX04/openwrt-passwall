# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall
PKG_VERSION:=26.10.16
PKG_RELEASE:=2
PKG_PO_VERSION:=$(PKG_VERSION)

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Geoview \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Geodata

LUCI_TITLE:=LuCI support for PassWall
LUCI_PKGARCH:=all
# Shadowsocks-libev client cores are mandatory: the Global path starts a
# private ss-local for its SOCKS listener and ss-redir for transparent TCP+UDP
# (ss-redir relays UDP itself via mode=tcp_and_udp, so no extra helper package
# is involved). ss-server stays out of this list because server mode is
# optional. These package names are not provided by the default OpenWrt feeds
# or by the passwall packages feed; they come from the separate
# openwrt-legacy-proxy-packages build.
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +coreutils-timeout +curl \
	+chinadns-ng +dns2socks +dnsmasq-full +ip-full \
	+libuci-lua +lua +luci-compat +luci-lib-jsonc \
	+microsocks +resolveip +shadowsocks-libev-ss-local \
	+shadowsocks-libev-ss-redir +tcping +tcpdump-mini

define Package/$(PKG_NAME)/config
menu "Configuration"
	depends on PACKAGE_$(PKG_NAME)

config PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy
	bool "Iptables Transparent Proxy"
	select PACKAGE_ipset
	select PACKAGE_ipt2socks
	select PACKAGE_iptables
	select PACKAGE_iptables-zz-legacy
	select PACKAGE_iptables-mod-conntrack-extra
	select PACKAGE_iptables-mod-extra
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
	select PACKAGE_kmod-ipt-nat
	default y if ! PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy
	bool "Nftables Transparent Proxy"
	select PACKAGE_ipt2socks
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
	select PACKAGE_kmod-nf-reject
	select PACKAGE_kmod-nf-reject6
	default y if PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_INCLUDE_Geoview
	bool "Include Geoview"
	select PACKAGE_geoview
	default y if aarch64||arm||i386||x86_64

# Hysteria is deliberately not bundled here. The configured feeds only provide
# hysteria 2.x, which Passwall Lite does not support; Hysteria v1.3.5 is built by
# the separate openwrt-legacy-proxy-packages repository and installed on the
# device as an optional component.
config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Geodata
	bool "Include V2ray_Geodata"
	select PACKAGE_v2ray-geoip
	select PACKAGE_v2ray-geosite
	default n

endmenu
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall
/etc/config/passwall_server
/etc/passwall/
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
rm -f $${IPKG_INSTROOT}/usr/share/passwall/rules/*.nft
rm -rf $${IPKG_INSTROOT}/tmp/etc/passwall_tmp
exit 0
endef

define Package/$(PKG_NAME)/postrm
#!/bin/sh
rm -f $${IPKG_INSTROOT}/usr/share/passwall/rules/*.nft
rm -rf $${IPKG_INSTROOT}/tmp/etc/passwall_tmp
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
