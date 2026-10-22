#!/bin/sh
set -e
apk add --no-cache curl lua5.1 lua5.1-dev lua5.1-cjson python3 iproute2-ss nftables iptables ip6tables openssl build-base linux-headers >/dev/null
sha=580b6b1d9ec3a79edb8e2a5a9c4700b9c320ff6a
curl -fsSL "https://codeload.github.com/openwrt/luci/tar.gz/$sha" | tar -xz -C /tmp
cd "/tmp/luci-$sha/libs/luci-lib-nixio/src"
make compile LUA_CFLAGS=-I/usr/include/lua5.1 FPIC=-fPIC NIXIO_LDFLAGS='-lm -ldl -shared' >/tmp/nixio-build.log 2>&1 || { cat /tmp/nixio-build.log; exit 1; }
cp nixio.so /usr/lib/lua/5.1/
mkdir -p /usr/share/lua/5.1/nixio
cp ../root/usr/lib/lua/nixio/*.lua /usr/share/lua/5.1/nixio/
python3 /workspace/tests/prepare-bound-native.py
/tmp/hysteria --version
printf '\n127.0.0.1 multi.bound.test\n127.0.0.2 multi.bound.test\n::1 multi.bound.test\n' >> /etc/hosts
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/bound-key.pem -out /tmp/bound-cert.pem -days 1 -subj /CN=multi.bound.test -addext subjectAltName=DNS:multi.bound.test >/dev/null 2>&1
