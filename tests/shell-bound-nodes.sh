#!/bin/sh
set -e
work=$(mktemp -d)
export PW_BOUND_REPO=/workspace
export LD_LIBRARY_PATH=/tmp/native/lib:/tmp/native/usr/lib
export LUA_CPATH='/tmp/native/usr/lib/lua/?.so;;'
export PATH="/tmp/native/usr/bin:/tmp/native/sbin:$PATH"
cleanup() {
	passwall_stop_acl_nodes a 2>/dev/null || :
	passwall_stop_acl_nodes b 2>/dev/null || :
	passwall_stop_global_nodes 2>/dev/null || :
	[ -z "${backend:-}" ] || python3 "$PW_BOUND_REPO/tests/bound-traffic.py" identity-remove "$backend" 2>/dev/null || :
	[ -z "${web:-}" ] || kill "$web" 2>/dev/null || :
	pkill -f "$work" 2>/dev/null || :
}
trap cleanup EXIT
CONFIG=passwall; TMP_PATH="$work/runtime"; TMP_ACL_PATH="$TMP_PATH/acl"; GLOBAL_ACL_PATH="$TMP_ACL_PATH/default"
TMP_BIN_PATH="$TMP_PATH/bin";mkdir -p "$GLOBAL_ACL_PATH" "$TMP_BIN_PATH" "$work/live" "$work/state"
UTIL_SS="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/util_shadowsocks.lua"
UTIL_HYSTERIA="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/util_hysteria.lua"
HYSTERIA_RUNTIME="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/hysteria_runtime.lua"
PW_BOUND_HELPER="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/runtime_binding.lua"
TCP_PROXY_WAY=redirect; PROXY_IPV6=0
fail() { echo "FAIL bound: $*" >&2; find "$work" -name node.log -exec tail -n 10 '{}' \; >&2; exit 1; }
echolog() { echo "$*" >&2; }
status_is() { local expect=$1 rc=0;shift;"$@" || rc=$?;[ "$rc" = "$expect" ] || fail "$*: expected $expect got $rc"; }
lua() { if [ "$1" = - ]; then command lua5.1 "$@"; else command lua5.1 "$PW_BOUND_REPO/tests/bound-api.lua" "$@"; fi; }
uci() {
	local conf="$work/live" delta="$work/state" override= flags= option
	while [ "$#" -gt 0 ];do
		case "$1" in -q|-N|-X) flags="$flags $1";shift;; -c) conf=$2;shift 2;; -C) override=$2;shift 2;; -t) delta=$2;shift 2;; *) break;;esac
	done
	command /tmp/native/sbin/uci $flags -c "$conf" -C "${override:-$conf}" -t "$delta" "$@"
}
config_n_get() {
	case "$1:$2" in
		@global_app*:hysteria_file) echo /tmp/hysteria;;
		@global*:loglevel) echo warn;;
		@global*:log_node) echo 1;;
		*) uci -q get "passwall.$1.$2";;
	esac
}
config_get_type() { uci -q get "passwall.$1"; }
first_type() { case "$1" in /*) echo "$1";;*) command -v "$1";;esac; }
json_init() { request=; }
json_add_string() { [ -z "$request" ] || request="$request,"; request="$request\"$1\":\"$2\""; }
json_dump() { printf '{%s}' "$request"; }
# PRODUCTION_HELPERS
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/node_config.sh"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/runtime_snapshot.sh"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/global_nodes.sh"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/acl_nodes.sh"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/bound_nodes.sh"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/split_firewall.sh"
PW_FW_ENDPOINT_HELPER="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/firewall_endpoint.lua"
cat > "$work/live/passwall" <<'UCI'
config global 'settings'
 option enabled '1'
 option acl_enable '1'
 option tcp_node 'ss'
 option udp_node 'tcp'
config global_app 'application'
 option hysteria_file '/tmp/hysteria'
config nodes 'ss'
 option type 'SS'
 option address 'multi.bound.test'
 option port '38388'
 option method 'aes-128-gcm'
 option password 'secret'
config nodes 'hy'
 option type 'Hysteria'
 option address 'multi.bound.test'
 option port '34443'
 option protocol 'udp'
 option hysteria_auth_type 'string'
 option hysteria_auth_password 'secret'
 option hysteria_up_mbps '10'
 option hysteria_down_mbps '20'
 option hysteria_ca '/tmp/bound-cert.pem'
 option tls_allowInsecure '0'
 option hysteria_obfs 'test-obfs'
config acl_rule 'a'
 option enabled '1'
 option mode '1'
 option tcp_node 'ss'
 option udp_node 'tcp'
config acl_rule 'b'
 option enabled '1'
 option mode '1'
 option tcp_node 'ss'
 option udp_node 'tcp'
UCI
capture() { passwall_snapshot_capture || fail capture; snapshot=$PW_SNAPSHOT_DIR; }
global_config() { get_cache_var "ACL_GLOBAL_${1}_instance"; }
acl_config() { get_cache_var "ACL_${1}_${2}_instance"; }
check_config() {
	command lua5.1 - "$1" "$2" <<'LUA'
local json=require'cjson';local function read(p)local f=assert(io.open(p));local s=f:read('*a');f:close();return json.decode(s) end
local c=read(arg[1]);local b=read(arg[1]:gsub('/config.json$','/binding.json'))
assert(b.endpoint.original_node.address=='multi.bound.test' and b.endpoint.generator_node.address==b.endpoint.address)
assert(c.server==(c.method and b.endpoint.address or ((b.endpoint.family==6 and '['..b.endpoint.address..']' or b.endpoint.address)..':'..b.endpoint.port)))
if not c.method then assert(c.server_name=='multi.bound.test' and c.ca=='/tmp/bound-cert.pem' and not c.insecure and c.auth_str=='secret') end
assert(read(arg[1]:gsub('/config.json$','/bound.identity')).generation==b.endpoint.generation)
print('BOUND_CONFIG '..b.endpoint.original_node.type..' '..arg[2]..' '..b.endpoint.address..' '..b.family)
LUA
	local proto=tcp expected
	[ -n "$(sed -n '3p' "${1%/*}/meta")" ] || proto=udp
	expected=$(python3 - "$1" "$proto" <<'PY'
import json,sys
b=json.load(open(sys.argv[1].replace('config.json','binding.json')))['endpoint']
stream=sys.argv[2] if b['original_node']['type']=='SS' else ('tcp' if b['original_node']['protocol']=='faketcp' else 'udp')
print(b['address'],b['port'],stream)
PY
)
	[ "$(lua "$PW_FW_ENDPOINT_HELPER" "$1" "$proto")" = "$expected" ] || fail firewall-endpoint-not-pinned
}
# Real servers; no production service/server path is activated or changed.
cat > "$work/ss-server.json" <<'JSON'
{"server":["::","0.0.0.0"],"server_port":38388,"password":"secret","method":"aes-128-gcm","timeout":60}
JSON
# Separate the test server's backend connections from the local test client in
# the same namespace. This GID is test-only and never changes server_app.lua.
python3 -c 'import os,sys;os.setgid(9922);os.execv(sys.argv[1],sys.argv[1:])' "$(command -v ss-server)" -c "$work/ss-server.json" -u > "$work/ss-server.log" 2>&1 &
for transport in udp wechat-video faketcp;do
	case "$transport" in udp) port=34443;;wechat-video) port=34445;;faketcp) port=34444;;esac
	printf '{"listen":":%s","protocol":"%s","obfs":"test-obfs","cert":"/tmp/bound-cert.pem","key":"/tmp/bound-key.pem","auth":{"mode":"password","config":{"password":"secret"}}}' "$port" "$transport" > "$work/hy-$transport.json"
	python3 -c 'import os,sys;os.setgid(9922);os.execv(sys.argv[1],sys.argv[1:])' /tmp/hysteria --no-check -c "$work/hy-$transport.json" server > "$work/hy-$transport.log" 2>&1 &
done
sleep 1
# v1.3.5 TCPRedirect intentionally rejects loopback original destinations.
# An isolated benchmark address exercises actual SO_ORIGINAL_DST forwarding.
ip address replace 198.18.0.10/32 dev lo
python3 "$PW_BOUND_REPO/tests/bound-traffic.py" serve & web=$!
sleep .2
for core in ss hy;do
	for role in tcp udp both;do
		uci -q delete passwall.settings.tcp_node || :;uci -q delete passwall.settings.udp_node || :
		[ "$role" = udp ] || uci set "passwall.settings.tcp_node=$core"
		[ "$role" = tcp ] || uci set "passwall.settings.udp_node=$core"
		capture
		status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
		if [ "$role" != udp ];then passwall_global_node_ready TCP || fail tcp-ready;check_config "$(global_config TCP)" "$role";fi
		if [ "$role" != tcp ];then passwall_global_node_ready UDP || fail udp-ready;check_config "$(global_config UDP)" "$role";fi
		status_is 0 passwall_stop_global_nodes
	done
done
echo 'PASS real binaries: frozen configs, GID/socket ownership, IPv4 TCP-only/UDP-only/combined global publication and cleanup'
for transport in udp wechat-video faketcp;do
	case "$transport" in udp) port=34443;;wechat-video) port=34445;;faketcp) port=34444;;esac
	uci set "passwall.hy.protocol=$transport";uci set "passwall.hy.port=$port"
	uci set passwall.settings.tcp_node=hy;uci set passwall.settings.udp_node=tcp
	uci set passwall.a.tcp_node=hy;uci set passwall.b.tcp_node=hy
	capture
	status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
	shared=$(acl_config a tcp)
	[ "$shared" = "$(acl_config b tcp)" ] || fail 'bound ACL sharing failed'
	status_is 0 passwall_stop_acl_nodes a
	passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail 'creator exit killed shared Hysteria'
	check_config "$shared" "$transport"
	status_is 0 passwall_stop_acl_nodes b
	status_is 0 passwall_stop_global_nodes
done
uci set passwall.a.tcp_node=ss;uci set passwall.b.tcp_node=ss
capture
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
shared=$(acl_config a tcp)
[ "$shared" = "$(acl_config b tcp)" ] || fail 'bound SS ACL sharing failed'
status_is 0 passwall_stop_acl_nodes a
passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail 'creator exit killed SS relay'
check_config "$shared" ss-acl
status_is 0 passwall_stop_acl_nodes b
echo 'PASS native Hysteria all transports, merged ACL sharing/last release; SS-local + real ipt2socks GID and transparent sockets'

TCP_PROXY_WAY=tproxy
for transport in udp wechat-video faketcp;do
	case "$transport" in udp) port=34443;;wechat-video) port=34445;;faketcp) port=34444;;esac
	uci set "passwall.hy.protocol=$transport";uci set "passwall.hy.port=$port"
	for family in 6 dual;do
		for core in ss hy;do
			for role in tcp udp both;do
				uci -q delete passwall.settings.tcp_node || :;uci -q delete passwall.settings.udp_node || :
				[ "$role" = udp ] || uci set "passwall.settings.tcp_node=$core"
				[ "$role" = tcp ] || uci set "passwall.settings.udp_node=$core"
				capture
				# This exact SS build has IPv6 UDP V6ONLY=1: never advertise dual
				# UDP from one ss-redir instance. This is an explicit refusal test.
				if [ "$core:$family" = ss:dual ] && [ "$role" != tcp ];then
					status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv6 "$family"
					[ -z "$(global_config TCP)$(global_config UDP)" ] || fail false-dual-SS
				else
					status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv6 "$family"
					[ "$role" = udp ] || _pw_bound_helper verify "$(dirname "$(global_config TCP)")" 6 tcp || fail IPv6-TCP
					[ "$role" = tcp ] || _pw_bound_helper verify "$(dirname "$(global_config UDP)")" 6 udp || fail IPv6-UDP
				fi
				status_is 0 passwall_stop_global_nodes
			done
		done
	done
done
echo 'PASS native IPv6/dual matrix: all Hysteria transports/roles; SS IPv6 all roles and dual TCP; unsupported single-ss-redir dual UDP rejected without cache'

for backend in nft iptables;do
	python3 "$PW_BOUND_REPO/tests/bound-traffic.py" identity-add "$backend"
	for family in 4 6;do
		TCP_PROXY_WAY=tproxy;preference=ipv6
		if [ "$family" = 4 ];then TCP_PROXY_WAY=redirect;preference=ipv4;fi
		for core in ss hy;do
			for transport in udp wechat-video faketcp;do
				[ "$core:$transport" != ss:wechat-video ] && [ "$core:$transport" != ss:faketcp ] || continue
				case "$core:$transport" in ss:*) remote=38388;stream=tcp;;hy:udp) remote=34443;stream=udp;;hy:wechat-video) remote=34445;stream=udp;;hy:faketcp) remote=34444;stream=tcp;;esac
				uci set "passwall.hy.protocol=$transport";uci set "passwall.hy.port=$remote"
				uci set "passwall.a.tcp_node=$core";uci set passwall.a.udp_node=tcp
				capture
				status_is 0 passwall_start_bound_acl_nodes "$snapshot" a "$preference" "$family" 0 warn
				config=$(acl_config a tcp);socks=$(cat "${config%/*}/socks_port")
				python3 "$PW_BOUND_REPO/tests/bound-traffic.py" "$backend" socks "$socks" "$family" "$stream" "$remote"
				[ "$core" != ss ] || stream=udp
				python3 "$PW_BOUND_REPO/tests/bound-traffic.py" "$backend" socks-udp "$socks" "$family" "$stream" "$remote"
				if [ "$core:$transport" = hy:faketcp ];then
					python3 - "$config" <<'PY'
import glob, hashlib, json, os, sys
record=json.load(open('/tmp/etc/passwall_hysteria1/'+hashlib.md5(sys.argv[1].encode()).hexdigest()+'.json'))
inodes=set()
for path in ('/proc/net/raw','/proc/net/raw6'):
 for row in open(path).read().splitlines()[1:]: inodes.add(row.split()[9])
count=0
for fd in glob.glob('/proc/'+str(record['pid'])+'/fd/*'):
 try: link=os.readlink(fd)
 except FileNotFoundError: continue
 if link.startswith('socket:[') and link[8:-1] in inodes:
  assert os.stat(fd).st_gid==9911;count+=1
assert count>0,'actual Hysteria raw socket not observed'
print('PASS actual Hysteria FakeTCP raw socket ownership/GID; not a socket-class substitute')
PY
					# The route exemption above must leave the actual manager/core
					# filter rules installed. IPv4/IPv6 are checked separately.
					python3 "$PW_BOUND_REPO/tests/bound-traffic.py" ttl "$family"
				fi
				status_is 0 passwall_stop_acl_nodes a
			done
		done
	done
	# Actual ss-redir and Hysteria TCP REDIRECT traffic, with ordinary OUTPUT
	# still denied access to the same upstream endpoint.
	TCP_PROXY_WAY=redirect
	for core in ss hy;do
		uci set passwall.hy.protocol=udp;uci set passwall.hy.port=34443
		uci set "passwall.settings.tcp_node=$core";uci -q delete passwall.settings.udp_node || :
		capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
		port=$(get_cache_var ACL_GLOBAL_TCP_redir_port)
		if [ "$core" = ss ];then stream=tcp;remote=38388;else stream=udp;remote=34443;fi
		python3 "$PW_BOUND_REPO/tests/bound-traffic.py" "$backend" redir "$port" 4 "$stream" "$remote"
		status_is 0 passwall_stop_global_nodes
	done
	python3 "$PW_BOUND_REPO/tests/bound-traffic.py" identity-remove "$backend"
	backend=
done
echo 'PASS actual SS-redir/SS-local and Hysteria x3: nft/iptables-nft core-only OUTPUT, TCP and SOCKS UDP echo over IPv4/IPv6'
. "$PW_BOUND_REPO/tests/shell-bound-lifecycle.sh"
