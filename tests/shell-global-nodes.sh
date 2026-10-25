#!/bin/sh
set -e
work=$(mktemp -d)
trap 'pkill -f "$work" 2>/dev/null || :; rm -rf "$work" /tmp/etc/passwall_hysteria1' EXIT
CONFIG=passwall;TMP_PATH="$work/runtime";TMP_ACL_PATH="$TMP_PATH/acl";GLOBAL_ACL_PATH="$TMP_ACL_PATH/default"
TMP_BIN_PATH="$TMP_PATH/bin";mkdir -p "$GLOBAL_ACL_PATH" "$TMP_BIN_PATH" "$work/bin"
UTIL_SS=/tmp/util_shadowsocks.lua;UTIL_HYSTERIA=/tmp/util_hysteria.lua;HYSTERIA_RUNTIME=/tmp/hysteria_runtime.lua
export PW_TEST_NODES="$work/nodes.json" PW_RULES="$work/rules" PW_EVENTS="$work/events"
export PATH="$work/bin:$PATH"
TCP_PROXY_WAY=redirect;PROXY_IPV6=0
fail() { echo "FAIL: $*" >&2;cat "$PW_EVENTS" >&2;exit 1; }
echolog() {
	echo "$*" >> "$PW_EVENTS"
	case "$*" in *'reclaiming only'*) find "$GLOBAL_ACL_PATH" -name node.log -exec cat '{}' \; >> "$PW_EVENTS" ;; esac
}
lua() { if [ "$1" = - ]; then command lua5.1 "$@"; else command lua5.1 /tmp/b2-api.lua "$@"; fi; }
json_init() { request=''; }
json_add_string() { [ -z "$request" ] || request="$request,";request="$request\"$1\":\"$2\""; }
json_dump() { printf '{%s}' "$request"; }
config_get_type() { [ "$(config_n_get "$1" type)" = missing ] || echo nodes; }
config_n_get() {
	case "$1:$2" in
		@global*:hysteria_file) echo "$work/bin/hysteria" ;;
		@global*:log_node) echo 1 ;;
		@global*:loglevel) echo warn ;;
		*) command lua5.1 - "$1" "$2" "${3-}" <<'LUA'
local f=assert(io.open(os.getenv('PW_TEST_NODES')))
local n=require('cjson').decode(f:read('*a'))
print((n[arg[1]] or {})[arg[2]] or arg[3] or '')
LUA
		;;
	esac
}
first_type() { case "$1" in /*) echo "$1";;*) echo "$work/bin/$1";;esac; }
# Accelerate waiting at the OS boundary; production checks/loop counts stay real.
sleep() { command sleep 0.01; }
# PRODUCTION_HELPERS
. /tmp/node_config.sh
. /tmp/global_nodes.sh
cat > "$PW_TEST_NODES" <<'JSON'
{
 "ss1":{"type":"SS","address":"192.0.2.1","port":"8388","password":"secret","method":"aes-128-gcm"},
 "ss2":{"type":"SS","address":"192.0.2.2","port":"8388","password":"secret","method":"chacha20-ietf-poly1305"},
 "ssbad":{"type":"SS","address":"192.0.2.1","port":"8388","password":"secret","method":"bad"},
 "ssexit":{"type":"SS","address":"exit.invalid","port":"8388","password":"secret","method":"aes-128-gcm"},
 "ssstall":{"type":"SS","address":"stall.invalid","port":"8388","password":"secret","method":"aes-128-gcm"},
 "sstcpmissing":{"type":"SS","address":"tcp-missing.invalid","port":"8388","password":"secret","method":"aes-128-gcm"},
 "ssudpmissing":{"type":"SS","address":"udp-missing.invalid","port":"8388","password":"secret","method":"aes-128-gcm"},
 "hy1":{"type":"Hysteria","address":"192.0.2.3","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hy2":{"type":"Hysteria","address":"192.0.2.4","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hyfake":{"type":"Hysteria","protocol":"faketcp","address":"192.0.2.3","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hyfake2":{"type":"Hysteria","protocol":"faketcp","address":"192.0.2.3","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hyvideo":{"type":"Hysteria","protocol":"wechat-video","address":"192.0.2.3","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hybad":{"type":"Hysteria","address":"192.0.2.3","port":"443","hysteria_up_mbps":"0","hysteria_down_mbps":"20"},
 "hyexit":{"type":"Hysteria","address":"exit.invalid","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hystall":{"type":"Hysteria","address":"stall.invalid","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hytcpmissing":{"type":"Hysteria","address":"tcp-missing.invalid","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"},
 "hyudpmissing":{"type":"Hysteria","address":"udp-missing.invalid","port":"443","hysteria_up_mbps":"10","hysteria_down_mbps":"20"}
}
JSON
cat > "$work/bin/core" <<'SH'
#!/bin/sh
[ "$1" != --version ] || { echo 'hysteria version v1.3.5';exit 0; }
while [ "$#" -gt 0 ]; do case "$1" in -c) config=$2;shift;;esac;shift;done
eval "$(lua5.1 - "$config" <<'LUA'
local f=assert(io.open(arg[1]));local c=require('cjson').decode(f:read('*a'))
local l=c.redirect_tcp or c.tproxy_tcp or c.tproxy_udp or c.socks5
print('port='..(c.local_port or l.listen:match(':(%d+)$')))
print('remote='..c.server)
LUA
)"
case "$remote" in
 exit.invalid*) exit 3;;stall.invalid*) exec sleep 30;;
 tcp-missing.invalid*) exec busybox nc -u -l -p "$port" -s 127.0.0.1;;
 udp-missing.invalid*) exec busybox nc -l -p "$port" -s 127.0.0.1;;
esac
set -- --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --user=root --port="$port" --listen-address=127.0.0.1 --bind-interfaces --cache-size=0
exec dnsmasq "$@"
SH
chmod +x "$work/bin/core";ln -s core "$work/bin/ss-redir";ln -s core "$work/bin/hysteria"
cat > "$work/bin/iptables" <<'SH'
#!/bin/sh
line=$(printf '%s\n' "$*" | sed 's/ -[CD] / -A /')
case " $* " in
 *' -C '*) grep -Fxq -- "$line" "$PW_RULES" 2>/dev/null;exit $?;;
 *' -A '*) printf '%s\n' "$line" >> "$PW_RULES";;
 *' -D '*) [ ! -e "$PW_RULES.delete-error" ] || exit 2;grep -Fxv -- "$line" "$PW_RULES" > "$PW_RULES.new" || :;mv "$PW_RULES.new" "$PW_RULES";;
esac
SH
chmod +x "$work/bin/iptables";ln -s iptables "$work/bin/ip6tables"
: > "$PW_EVENTS";: > "$PW_RULES"
status_is() { local expected=$1 code=0;shift;"$@" || code=$?;[ "$code" = "$expected" ] || fail "$*: expected $expected got $code"; }
ready() { passwall_global_node_ready "$1" || fail "$1 not ready"; }
closed() { local p;for p in TCP UDP;do [ -z "$(get_cache_var "ACL_GLOBAL_${p}_instance")" ] || fail 'closed capability published';done; }
instance_pid() {
	if [ "$(sed -n '1p' "${1%/config.json}/meta")" = SS ];then
		sed -n '1p' "${1%/config.json}/process"
	else
		command lua5.1 - "$1" <<'LUA'
local f=assert(io.open('/tmp/etc/passwall_hysteria1/'..arg[1]:gsub('[^%w]','_')..'.json'))
print(require('cjson').decode(f:read('*a')).pid)
LUA
	fi
}
config_is() {
	command lua5.1 - "$1" "$2" "$TCP_PROXY_WAY" <<'LUA'
local f=assert(io.open(arg[1]));local c=require('cjson').decode(f:read('*a'))
local tcp=arg[2]=='both' or arg[2]=='tcp';local udp=arg[2]=='both' or arg[2]=='udp'
if c.method then
 assert(c.mode==({both='tcp_and_udp',tcp='tcp_only',udp='udp_only'})[arg[2]])
 assert(c.plugin==nil and c.plugin_opts==nil)
 assert((c.tcp_tproxy or false)==(tcp and arg[3]=='tproxy'))
else
 assert(((c.redirect_tcp or c.tproxy_tcp)~=nil)==tcp)
 assert((c.tproxy_udp~=nil)==udp)
 assert(c.tls==nil and c.quic==nil and c.transport==nil)
 if tcp then assert(c[arg[3]=='redirect' and 'redirect_tcp' or 'tproxy_tcp']) end
end
LUA
}
[ -z "${PW_B2_TRACE:-}" ] || set -x
gen_hysteria_config '{"node":"hy1","local_socks_port":"1070"}' "$work/native-socks.json"
start_hysteria "$work/native-socks.json" "$work/native-socks.log" warn
set_cache_vars s1 hy1
# The new read-only query must reject a live, identity-matching process which
# does not own the socket, even while the original listener still exists.
record=$(find /tmp/etc/passwall_hysteria1 -name '*.json')
cp "$record" "$work/record.backup"
command sleep 30 & unrelated=$!
unrelated_birth=$(get_process_start_time "$unrelated")
command lua5.1 - "$record" "$unrelated" "$unrelated_birth" <<'LUA'
local json=require('cjson');local f=assert(io.open(arg[1]));local r=json.decode(f:read('*a'));f:close()
r.pid=tonumber(arg[2]);r.birth=arg[3]
f=assert(io.open(arg[1],'w'));f:write(json.encode(r));f:close()
LUA
status_is 1 lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json"
cp "$work/record.backup" "$record"
kill "$unrelated";wait "$unrelated" || :
lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json" || fail 'query altered original instance'
for pair in 'ss1 tcp' 'hy1 tcp' 'ss1 ss1' 'hy1 hy1' 'ss1 ss2' 'hy1 hy2' 'ss1 hy1' 'hy1 ss1'; do
	set -- $pair
	status_is 0 passwall_start_global_nodes "$1" "$2"
	ready TCP;ready UDP
	t=$(get_cache_var ACL_GLOBAL_TCP_instance);u=$(get_cache_var ACL_GLOBAL_UDP_instance)
	if [ "$2" = tcp ] || [ "$1" = "$2" ];then
		[ "$t" = "$u" ] || fail 'same node not combined';config_is "$t" both
	else
		[ "$t" != "$u" ] || fail 'independent instances shared a config';config_is "$t" tcp;config_is "$u" udp
	fi
	status_is 0 passwall_stop_global_nodes;closed
done
for core in ss1 hy1 hyfake hyvideo;do
	status_is 0 passwall_start_global_nodes "$core" '';ready TCP
	config_is "$(get_cache_var ACL_GLOBAL_TCP_instance)" tcp
	[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'TCP-only is UDP-ready'
	status_is 0 passwall_start_global_nodes '' "$core";ready UDP
	config_is "$(get_cache_var ACL_GLOBAL_UDP_instance)" udp
	[ -z "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] || fail 'UDP-only is TCP-ready'
	status_is 0 passwall_start_global_nodes "$core" tcp;ready TCP;ready UDP
	status_is 0 passwall_stop_global_nodes;closed
done
TCP_PROXY_WAY=tproxy
status_is 0 passwall_start_global_nodes ss1 hy1
config_is "$(get_cache_var ACL_GLOBAL_TCP_instance)" tcp
config_is "$(get_cache_var ACL_GLOBAL_UDP_instance)" udp
status_is 0 passwall_start_global_nodes hy1 ss1
config_is "$(get_cache_var ACL_GLOBAL_TCP_instance)" tcp
config_is "$(get_cache_var ACL_GLOBAL_UDP_instance)" udp
TCP_PROXY_WAY=redirect
status_is 0 passwall_start_global_nodes '' '';closed
[ -z "$(find "$GLOBAL_ACL_PATH/split" -name meta)" ] || fail 'off state left an owned instance'
status_is 0 passwall_start_global_nodes '' tcp;closed
echo 'PASS real split startup: both cores/roles, follow/explicit, combined/split paths, UDP-only/TCP-only/off and all Hysteria transports'

# One failure must not stop the other protocol or publish the failed listener.
for bad in ssbad hybad ssexit hyexit ssstall hystall;do
	status_is 2 passwall_start_global_nodes "$bad" ss2
	[ -z "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] || fail 'failed TCP published';ready UDP
	status_is 2 passwall_start_global_nodes hy1 "$bad"
	ready TCP;[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'failed UDP published'
	status_is 0 passwall_stop_global_nodes
done
echo 'PASS real split startup: config errors, immediate exits, missing listeners and single-protocol isolation'

# Each protocol is mandatory for combined publication: these live nc fixtures
# own only the other protocol. No PID or TCP socket can stand in for UDP readiness.
for bad in sstcpmissing ssudpmissing hytcpmissing hyudpmissing;do
	status_is 2 passwall_start_global_nodes "$bad" tcp;closed
	[ -z "$(find "$GLOBAL_ACL_PATH/split" -name meta)" ] || fail 'partly listening instance retained'
done
echo 'PASS TCP and UDP listeners independently required before combined publication'

# Readiness is a current query, not a historical startup flag. A PID with a
# mismatching birth must neither be accepted nor killed, even if still alive.
command sleep 30 & unrelated=$!
unrelated_birth=$(get_process_start_time "$unrelated")
status_is 1 _pw_global_ss_alive "$unrelated" "$((unrelated_birth + 1))"
status_is 0 _pw_global_ss_kill "$unrelated" "$((unrelated_birth + 1))"
kill -0 "$unrelated" || fail 'PID reuse guard killed foreign process'
kill "$unrelated";wait "$unrelated" || :
for core in ss1 hy1;do
	status_is 0 passwall_start_global_nodes "$core" tcp
	config=$(get_cache_var ACL_GLOBAL_TCP_instance);pid=$(instance_pid "$config")
	kill -KILL "$pid"
	status_is 1 passwall_global_node_ready TCP;status_is 1 passwall_global_node_ready UDP
	[ "$(get_cache_var ACL_GLOBAL_TCP_instance)" = "$config" ] || fail 'readiness query mutated ownership'
	status_is 0 passwall_stop_global_nodes;closed
done
# Changing a config must not let a SOCKS/TCP-only JSON validate cached UDP.
status_is 0 passwall_start_global_nodes hy1 tcp
config=$(get_cache_var ACL_GLOBAL_TCP_instance);cp "$config" "$work/config.backup"
command lua5.1 - "$config" <<'LUA'
local json=require('cjson');local f=assert(io.open(arg[1]));local c=json.decode(f:read('*a'));f:close()
c.tproxy_udp=nil;f=assert(io.open(arg[1],'w'));f:write(json.encode(c));f:close()
LUA
status_is 1 passwall_global_node_ready UDP
command lua5.1 - "$config" "$work/config.backup" <<'LUA'
local json=require('cjson');local f=assert(io.open(arg[2]));local c=json.decode(f:read('*a'));f:close()
c.tproxy_udp.listen='127.0.0.1:1';f=assert(io.open(arg[1],'w'));f:write(json.encode(c));f:close()
LUA
status_is 1 passwall_global_node_ready UDP
cp "$work/config.backup" "$config";ready TCP;ready UDP
status_is 0 passwall_stop_global_nodes
echo 'PASS post-publication crash detection, PID birth guard and expected Hysteria protocol/port validation'

# Real conflict and inode ownership: an unrelated listener must stay alive and
# cannot make the test shell (or another core PID) count as a ready endpoint.
dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --user=root --port=1041 --listen-address=127.0.0.1 --bind-interfaces > "$work/holder.log" 2>&1 &
holder=$!
for n in $(seq 1 100);do [ "$(check_port_exists 1041 tcp,udp)" != 0 ] && break;sleep 0.1;done
if _pw_global_ss_socket "$$" tcp 1041;then fail 'unrelated socket accepted';fi
status_is 0 passwall_start_global_nodes ss1 tcp
ready TCP;ready UDP
[ "$(get_cache_var ACL_GLOBAL_TCP_redir_port)" != 1041 ] || fail 'occupied port reused'
status_is 0 passwall_stop_global_nodes
kill -0 "$holder" || fail 'unrelated holder killed';kill "$holder";wait "$holder" || :
echo 'PASS real port conflict and wrong-PID socket rejection; unrelated listener preserved'

set_cache_vars ACL_GLOBAL_node legacy ACL_GLOBAL_redir_port 19999 ACL_keep_tcp_instance "$work/foreign.json" s1 hy1
# Stale protocol tuple points outside B2 ownership. It must be invalidated,
# without stopping that independently running native SOCKS instance.
set_cache_vars ACL_GLOBAL_TCP_node hy1 ACL_GLOBAL_TCP_redir_port 1070 ACL_GLOBAL_TCP_instance "$work/native-socks.json"
status_is 2 passwall_start_global_nodes ssbad ss2
[ -z "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] || fail 'stale successful TCP tuple reused'
ready UDP
lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json" || fail 'foreign stale instance killed'
status_is 0 passwall_stop_global_nodes
fault_key=;partial=0
printf() {
	if [ "$1" = '%s=%s\n' ] && [ "$2" = "$fault_key" ];then [ "$partial" != 1 ] || command printf "%s='broken" "$2";return 1;fi
	command printf "$@"
}
for fault_key in ACL_GLOBAL_UDP_node ACL_GLOBAL_UDP_redir_port ACL_GLOBAL_UDP_instance;do
	for partial in 0 1;do
		status_is 2 passwall_start_global_nodes ss1 hy1
		ready TCP;[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'failed publication visible'
		[ "$(get_cache_var ACL_GLOBAL_node)" = legacy ] && [ "$(get_cache_var ACL_keep_tcp_instance)" = "$work/foreign.json" ] && [ "$(get_cache_var s1)" = hy1 ] || fail 'unrelated state changed'
	done
done
fault_key=;partial=0
status_is 0 passwall_stop_global_nodes
for fault_key in ACL_GLOBAL_TCP_node ACL_GLOBAL_TCP_redir_port ACL_GLOBAL_TCP_instance;do
	status_is 2 passwall_start_global_nodes ss1 hy1
	[ -z "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] || fail 'failed TCP publication visible';ready UDP
done
for fault_key in ACL_GLOBAL_TCP_node ACL_GLOBAL_UDP_instance;do
	status_is 2 passwall_start_global_nodes hy1 tcp;closed
done
fault_key=
status_is 0 passwall_stop_global_nodes
echo 'PASS real cache publication faults: TCP/UDP fields, combined atomicity, partial writes, other protocol and legacy/ACL/SOCKS boundaries'

# Inject an actual process death after the real atomic rename, before returning
# from the real setter. Post-publication revalidation must withdraw that tuple.
mv() {
	case "$*" in
		*" $TMP_PATH/var")
			[ ! -e "$work/publish-fired" ] || [ "$rollback_error" != 1 ] || return 1
			command mv "$@" || return 1
			[ ! -e "$work/publish-fired" ] || return 0
			local config pid
			config=$(get_cache_var "ACL_GLOBAL_${crash_proto}_instance") || return 0
			[ -n "$config" ] || return 0
			touch "$work/publish-fired"
			pid=$(instance_pid "$config") || return 1
			kill -KILL "$pid" || return 1
			command sleep 0.03
			;;
		*) command mv "$@" ;;
	esac
}
for core in ss1 hyfake;do
	for crash_proto in TCP UDP;do
		rollback_error=0;rm -f "$work/publish-fired"
		if [ "$crash_proto" = TCP ];then
			status_is 2 passwall_start_global_nodes "$core" ss2
			status_is 1 passwall_global_node_ready TCP;ready UDP
			[ -z "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] || fail 'dead TCP tuple remained published'
		else
			status_is 2 passwall_start_global_nodes ss2 "$core"
			ready TCP;status_is 1 passwall_global_node_ready UDP
			[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'dead UDP tuple remained published'
		fi
		[ -e "$work/publish-fired" ] || fail 'death injection not exercised'
	done
	crash_proto=UDP;rm -f "$work/publish-fired"
	status_is 2 passwall_start_global_nodes "$core" tcp;closed
done
# A failed withdrawal is hard failure and must retain the exact owned instance
# and cache record for retry. Public readiness must still reject the dead PID.
rollback_error=1;crash_proto=UDP;rm -f "$work/publish-fired"
status_is 1 passwall_start_global_nodes ss1 hyfake
ready TCP;status_is 1 passwall_global_node_ready UDP
pending=$(get_cache_var ACL_GLOBAL_UDP_instance)
[ -n "$pending" ] && [ -f "${pending%/config.json}/meta" ] || fail 'unpublish retry ownership lost'
[ -s "$PW_RULES" ] || fail 'hard failure silently discarded FakeTCP cleanup record'
unset -f mv
status_is 0 passwall_stop_global_nodes;closed
[ ! -s "$PW_RULES" ] || fail 'post-publication cleanup retry leaked rule'
[ "$(get_cache_var ACL_keep_tcp_instance)" = "$work/foreign.json" ] || fail 'publication rollback damaged ACL'
lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json" || fail 'publication rollback damaged SOCKS'
echo 'PASS real death during publication: per-protocol/combined withdrawal, hard rollback failure, retry and independent instance boundaries'

# Stop unpublishes atomically before killing. Failed unpublication keeps listeners.
status_is 0 passwall_start_global_nodes ss1 hy1
mv() { return 1; }
status_is 1 passwall_stop_global_nodes
ready TCP;ready UDP
unset -f mv
status_is 0 passwall_stop_global_nodes;closed

# The same binding ownership rule protects SS instances, not just Hysteria.
status_is 0 passwall_start_global_nodes ss1 tcp
shared=$(get_cache_var ACL_GLOBAL_TCP_instance);shared_port=$(get_cache_var ACL_GLOBAL_TCP_redir_port)
set_cache_vars ACL_a_tcp_instance "$shared" ACL_a_tcp_node ss1 ACL_a_tcp_redir_port "$shared_port"
set_cache_vars ACL_b_udp_instance "$shared" ACL_b_udp_node ss1 ACL_b_udp_redir_port "$shared_port"
status_is 0 passwall_stop_global_nodes;closed
_pw_global_instance_ready "${shared%/config.json}" || fail 'shared SS killed'
set_cache_vars ACL_a_tcp_instance '' ACL_a_tcp_node '' ACL_a_tcp_redir_port ''
status_is 0 passwall_stop_global_nodes
_pw_global_instance_ready "${shared%/config.json}" || fail 'one ACL release killed another ACL owner'
set_cache_vars ACL_b_udp_instance '' ACL_b_udp_node '' ACL_b_udp_redir_port ''
status_is 0 passwall_stop_global_nodes
[ ! -d "${shared%/config.json}" ] && [ "$(check_port_exists "$shared_port" tcp,udp)" = 0 ] || fail 'last SS owner not released'

# Cannot inspect references: retain the live instance and propagate unsafe state.
status_is 0 passwall_start_global_nodes ss1 ''
held=$(get_cache_var ACL_GLOBAL_TCP_instance)
sed() {
	if [ "$1" = -n ] && [ "$2" = 's/^\([A-Za-z0-9_]*_instance\)=.*/\1/p' ];then return 1;fi
	command sed "$@"
}
status_is 1 passwall_stop_global_nodes;closed
_pw_global_instance_ready "${held%/config.json}" || fail 'ownership query failure killed instance'
unset -f sed
status_is 0 passwall_stop_global_nodes

# SS cleanup failure keeps the process record for retry, and cannot advertise UDP.
fault_key=ACL_GLOBAL_UDP_node
kill() { return 1; }
status_is 1 passwall_start_global_nodes hy1 ss1
ready TCP;[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'unsafe SS published'
[ -n "$(find "$GLOBAL_ACL_PATH/split" -name process)" ] || fail 'SS retry record lost'
unset -f kill
fault_key=
status_is 0 passwall_stop_global_nodes;closed

# Shared ACL owner survives global release and a subsequent global start.
status_is 0 passwall_start_global_nodes hyfake tcp
shared=$(get_cache_var ACL_GLOBAL_TCP_instance)
set_cache_vars ACL_a_tcp_instance "$shared" ACL_a_tcp_node hyfake ACL_a_tcp_redir_port "$(get_cache_var ACL_GLOBAL_TCP_redir_port)"
set_cache_vars ACL_b_udp_instance "$shared" ACL_b_udp_node hyfake ACL_b_udp_redir_port "$(get_cache_var ACL_GLOBAL_UDP_redir_port)"
status_is 0 passwall_stop_global_nodes;closed
lua "$HYSTERIA_RUNTIME" ready client "$shared" || fail 'shared Hysteria killed'
status_is 0 passwall_start_global_nodes hyfake tcp
[ "$(get_cache_var ACL_GLOBAL_TCP_instance)" != "$shared" ] || fail 'previous-cycle instance reused'
lua "$HYSTERIA_RUNTIME" ready client "$shared" || fail 'new start killed shared instance'
status_is 0 passwall_stop_global_nodes
[ -s "$PW_RULES" ] || fail 'shared FakeTCP rule prematurely deleted'
set_cache_vars ACL_a_tcp_instance '' ACL_a_tcp_node '' ACL_a_tcp_redir_port ''
status_is 0 passwall_stop_global_nodes
lua "$HYSTERIA_RUNTIME" ready client "$shared" || fail 'one Hysteria ACL release killed another owner'
[ -s "$PW_RULES" ] || fail 'one ACL release removed shared FakeTCP rule'
set_cache_vars ACL_b_udp_instance '' ACL_b_udp_node '' ACL_b_udp_redir_port ''
status_is 0 passwall_stop_global_nodes
[ ! -s "$PW_RULES" ] || fail 'last FakeTCP rule leaked'

status_is 0 passwall_start_global_nodes hyfake hyfake2
t=$(get_cache_var ACL_GLOBAL_TCP_instance);u=$(get_cache_var ACL_GLOBAL_UDP_instance)
[ "$t" != "$u" ] && [ "$(wc -l < "$PW_RULES")" = 1 ] || fail 'FakeTCP instances/rule ownership conflated'
set_cache_vars ACL_GLOBAL_UDP_node '' ACL_GLOBAL_UDP_redir_port '' ACL_GLOBAL_UDP_instance ''
_pw_global_instance_stop "${u%/config.json}" || fail 'one FakeTCP instance failed stop'
ready TCP
[ -s "$PW_RULES" ] || fail 'one instance removed shared rule'
status_is 0 passwall_stop_global_nodes
[ ! -s "$PW_RULES" ] || fail 'last independent FakeTCP rule leaked'

# Cleanup failure is unsafe, records stay retryable; no successful UDP tuple.
fault_key=ACL_GLOBAL_UDP_node
touch "$PW_RULES.delete-error"
status_is 1 passwall_start_global_nodes ss1 hyfake
ready TCP;[ -z "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'unsafe UDP advertised'
[ -n "$(find "$GLOBAL_ACL_PATH/split" -name meta)" ] || fail 'retry records lost'
fault_key=;rm "$PW_RULES.delete-error"
status_is 0 passwall_stop_global_nodes;closed
[ ! -s "$PW_RULES" ] || fail 'cleanup retry leaked rule'
lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json" || fail 'independent native SOCKS instance stopped'
lua "$HYSTERIA_RUNTIME" stop client "$work/native-socks.json"
echo 'PASS real lifecycle: failed unpublish, ACL sharing, new-cycle paths, FakeTCP ownership and failed cleanup/retry'
