# Runs after the shared B2 test setup, before any B2 test cases.
. /tmp/acl_nodes.sh
export PW_CORE_EVENTS="$work/core-events" PW_RELAY_FAIL="$work/relay-fail"
: > "$PW_CORE_EVENTS"
cat > "$work/bin/core" <<'SH'
#!/bin/sh
exec lua5.1 /tmp/acl-listener.lua "$@"
SH
chmod +x "$work/bin/core";ln -s core "$work/bin/ss-local";ln -s core "$work/bin/ipt2socks"
uci() {
	[ "$1" != -q ] || shift
	[ "$1" = show ] || return 1
	command lua5.1 - "${2#passwall.}" <<'LUA'
local f=assert(io.open(os.getenv('PW_TEST_NODES')));local n=require('cjson').decode(f:read('*a'))[arg[1]]
if not n then os.exit(1) end
local keys={};for k in pairs(n) do keys[#keys+1]=k end;table.sort(keys)
for _,k in ipairs(keys) do print(k..'='..tostring(n[k])) end
LUA
}
acl_start() { passwall_start_acl_nodes "$1" 1 0 "$2" "$3" "${4:-0}" "${5:-warn}"; }
acl_ready() { passwall_acl_node_ready "$1" "$2" || fail "$1/$2 not ready"; }
acl_closed() {
	local proto
	for proto in tcp udp;do
		[ -z "$(get_cache_var "ACL_${1}_${proto}_instance")" ] || fail "$1/$proto remains published"
		if passwall_acl_node_ready "$1" "$proto";then fail "$1/$proto falsely ready";fi
	done
}
acl_stop() { passwall_stop_acl_nodes "$1" || fail "$1 cleanup failed";acl_closed "$1"; }
state_is() {
	local expected="$1" value
	shift
	value=$(passwall_acl_protocol_state "$@") || fail "protocol state query failed: $*"
	[ "$value" = "$expected" ] || fail "$*: expected state $expected got $value"
}
config() { get_cache_var "ACL_${1}_${2}_instance"; }
pid_for() {
	if [ "$(sed -n '1p' "${1%/config.json}/meta")" = SS ];then sed -n '1p' "${1%/config.json}/process"
	else instance_pid "$1";fi
}
[ -z "${PW_B3_TRACE:-}" ] || set -x

# Independent native SOCKS and old single-node caches are outside B3 ownership.
gen_hysteria_config '{"node":"hy1","local_socks_port":"1070"}' "$work/native-socks.json"
start_hysteria "$work/native-socks.json" "$work/native-socks.log" warn
set_cache_vars ACL_GLOBAL_node legacy ACL_GLOBAL_redir_port 19999 ACL_legacy_node untouched \
	ACL_legacy_redir_port 19998 acl_node_ss1_socks_port 19997 s1 hy1

for pair in 'ss1 tcp' 'hy1 tcp' 'ss1 ss1' 'hy1 hy1' 'ss1 ss2' 'hy1 hy2' 'ss1 hy1' 'hy1 ss1';do
	set -- $pair
	status_is 0 acl_start a "$1" "$2"
	[ "$PW_NODE_UDP_SELECTOR" = "$2" ] || fail 'follow/explicit selection semantics lost'
	acl_ready a tcp;acl_ready a udp
	state_is ready a tcp "$1"
	state_is ready a udp "$( [ "$2" = tcp ] && echo "$1" || echo "$2" )"
	t=$(config a tcp);u=$(config a udp)
	if [ "$2" = tcp ] || [ "$1" = "$2" ];then [ "$t" = "$u" ] || fail 'same-node ACL not combined'
	else [ "$t" != "$u" ] || fail 'different nodes share configuration';fi
	[ -z "$(get_cache_var ACL_a_tcp_default)" ] && [ -z "$(get_cache_var ACL_a_udp_default)" ] || fail 'independent ACL inherits DNS/default'
	acl_stop a
done
for core in ss1 hy1 hyfake hyvideo;do
	for pair in tcp udp both closed;do
		case "$pair" in tcp) t=$core;u=;;udp) t=;u=$core;;both) t=$core;u=tcp;;closed) t=;u=;;esac
		status_is 0 acl_start a "$t" "$u"
		if [ -n "$t" ];then acl_ready a tcp;else status_is 1 passwall_acl_node_ready a tcp;fi
		if [ "$pair" = both ] || [ "$pair" = udp ];then acl_ready a udp;else status_is 1 passwall_acl_node_ready a udp;fi
		# Protocol role is an ipt2socks flag, not the SS SOCKS UDP control channel.
		if [ "$core" = ss1 ] && [ "$pair" != closed ];then
			cfg=$(config a "$( [ "$pair" = udp ] && echo udp || echo tcp )")
			command lua5.1 - "$cfg" "$pair" "$PW_CORE_EVENTS" <<'LUA'
local json=require('cjson');local f=assert(io.open(arg[1]));local c=json.decode(f:read('*a'));f:close()
assert(c.mode==(arg[2]=='tcp' and 'tcp_only' or 'tcp_and_udp'))
local last
for line in io.lines(arg[3]) do local e=json.decode(line);if e.relay and e.socks==c.local_port then last=e end end
assert(last,'relay command not exercised')
assert(last.tcp==(arg[2]~='udp') and last.udp==(arg[2]~='tcp'));assert(last.v6 and last.redirect)
LUA
		fi
		acl_stop a
	done
done
status_is 0 acl_start a '' tcp;acl_closed a
state_is closed a tcp '';state_is closed a udp ''
status_is 0 passwall_start_acl_nodes a 0 invalid retired invalid invalid invalid;acl_closed a
echo 'PASS ACL two cores/all roles, combined/split, follow/explicit, off/mode=0 and correct SS backend/relay flags'

# Real IPv4 and IPv6 listeners, and both TCP transparent modes for SS relay.
for way in redirect tproxy;do
	TCP_PROXY_WAY=$way;PROXY_IPV6=1
	status_is 0 acl_start a ss1 tcp;acl_ready a tcp;acl_ready a udp
	cfg=$(config a tcp);pid=$(sed -n '1p' "${cfg%/config.json}/relay/process")
	port=$(get_cache_var ACL_a_tcp_redir_port)
	_pw_global_ss_socket "$pid" tcp "$port" 6 || fail 'IPv6 TCP relay not owned'
	_pw_global_ss_socket "$pid" udp "$port" 6 || fail 'IPv6 UDP relay not owned'
	command lua5.1 - "$PW_CORE_EVENTS" "$way" <<'LUA'
local json=require('cjson');local last;for line in io.lines(arg[1]) do local e=json.decode(line);if e.relay then last=e end end
assert(last.redirect==(arg[2]=='redirect'))
LUA
	acl_stop a
	if [ "$way" = tproxy ];then status_is 0 acl_start a hy1 tcp;acl_ready a tcp;acl_ready a udp
	else status_is 2 acl_start a hy1 tcp;acl_closed a;fi
	acl_stop a
done
TCP_PROXY_WAY=redirect;PROXY_IPV6=0
echo 'PASS native IPv4/IPv6 socket ownership and TCP REDIRECT/TPROXY dispatch'

# A business role/IPv6 difference must not rewrite the original listener set.
status_is 0 acl_start a ss1 tcp;a=$(config a tcp)
TCP_PROXY_WAY=tproxy
status_is 0 acl_start b ss1 tcp
[ "$(config b tcp)" != "$a" ] || fail 'incompatible TCP listener reused'
acl_ready a tcp;acl_stop b
TCP_PROXY_WAY=redirect;PROXY_IPV6=1
status_is 0 acl_start b ss1 tcp
[ "$(config b tcp)" != "$a" ] || fail 'incompatible IPv6 listener reused'
acl_ready a tcp;acl_stop b;acl_stop a
TCP_PROXY_WAY=redirect;PROXY_IPV6=0

# Closed is determined by the effective request, never by absence of a port.
for pair in 'ss1 hybad' 'hybad ss1';do
	set -- $pair;status_is 2 acl_start a "$1" "$2"
	if [ "$1" = ss1 ];then state_is ready a tcp ss1;state_is failed a udp hybad
	else state_is failed a tcp hybad;state_is ready a udp ss1;fi
	acl_stop a
done
status_is 0 acl_start a '' ss1
state_is closed a tcp '';state_is ready a udp ss1
status_is 1 passwall_acl_protocol_state a tcp ss1 extra
status_is 1 passwall_acl_protocol_state a udp ''
set_cache_vars ACL_a_udp_redir_port ''
status_is 1 passwall_acl_protocol_state a udp ss1
a=$(config a udp)
set_cache_vars ACL_a_udp_redir_port "$(sed -n '4p' "${a%/config.json}/meta")"
state_is ready a udp ss1
acl_stop a
(
	TMP_PATH="$work/empty-cache";TMP_ACL_PATH="$TMP_PATH/acl";GLOBAL_ACL_PATH="$TMP_ACL_PATH/default"
	state_is closed a tcp '';state_is failed a udp ss1
	mkdir -p "$TMP_PATH";: > "$TMP_PATH/var"
	state_is closed a tcp '';state_is failed a udp ss1
)
echo 'PASS explicit closed/failed/ready contract, partial TCP/UDP success, contradictory records and context isolation'

# Same node ID does not grant missing protocol capability or permit replacement.
for core in ss1 hy1;do
	status_is 0 acl_start a "$core" ''
	a=$(config a tcp);pid=$(pid_for "$a")
	status_is 0 acl_start b "$core" tcp
	[ "$(config b tcp)" = "$a" ] || fail 'existing compatible TCP not reused'
	[ "$(config b udp)" != "$a" ] || fail 'TCP-only mistaken for UDP-ready'
	acl_ready a tcp;acl_ready b tcp;acl_ready b udp
	acl_stop b;acl_ready a tcp;kill -0 "$pid" || fail 'unbind B killed A'
	acl_stop a
	status_is 0 acl_start a "$core" tcp
	a=$(config a tcp);pid=$(pid_for "$a")
	status_is 0 acl_start b "$core" tcp
	[ "$(config b tcp)" = "$a" ] && [ "$(config b udp)" = "$a" ] || fail 'combined instance not shared'
	acl_stop a;acl_ready b tcp;acl_ready b udp;kill -0 "$pid" || fail 'first owner stopped shared process'
	acl_stop b
	[ ! -d "${a%/config.json}" ] || fail 'last reference leaked instance'
done
status_is 0 acl_start a ss1 '';a=$(config a tcp)
status_is 0 acl_start c '' ss1;c=$(config c udp)
status_is 0 acl_start b ss1 tcp
[ "$(config b tcp)" = "$a" ] && [ "$(config b udp)" = "$c" ] || fail 'two existing single-protocol instances not reused'
acl_stop a;acl_ready b tcp;acl_stop c;acl_ready b udp;acl_stop b
status_is 0 acl_start a hyfake tcp
a=$(config a tcp)
status_is 0 acl_start b hyfake tcp 1
[ "$(config b tcp)" != "$a" ] || fail 'logging incompatible instance reused'
acl_stop b;acl_ready a tcp
status_is 0 acl_start b hyfake tcp 0 debug
[ "$(config b tcp)" != "$a" ] || fail 'loglevel incompatible instance reused'
acl_stop b;acl_ready a tcp;acl_stop a
# Changed UCI contents require a new instance despite an identical node ID.
status_is 0 acl_start a ss1 tcp;a=$(config a tcp)
cp "$PW_TEST_NODES" "$work/nodes.backup"
command lua5.1 - "$PW_TEST_NODES" <<'LUA'
local json=require('cjson');local f=assert(io.open(arg[1]));local n=json.decode(f:read('*a'));f:close()
n.ss1.password='changed';f=assert(io.open(arg[1],'w'));f:write(json.encode(n));f:close()
LUA
status_is 0 acl_start b ss1 tcp
[ "$(config b tcp)" != "$a" ] || fail 'changed node reused old credentials'
acl_ready a tcp;acl_stop b;acl_stop a
cp "$work/nodes.backup" "$PW_TEST_NODES"
# A live process and instance path alone are not a successful binding.
status_is 0 acl_start a ss1 '';a=$(config a tcp)
set_cache_vars ACL_a_tcp_node ''
status_is 0 acl_start b ss1 ''
[ "$(config b tcp)" != "$a" ] || fail 'incomplete binding reused as success'
set_cache_vars ACL_a_tcp_node ss1
acl_ready a tcp;acl_stop b;acl_stop a
echo 'PASS capability-aware sharing, missing protocol separation, two owners and log/context isolation'

# Inherit only current, live global capabilities. No UCI selector reads/fallback.
status_is 0 passwall_start_global_nodes hy1 ss1
status_is 0 passwall_start_acl_nodes a 1 1 invalid invalid 0 warn
acl_ready a tcp;acl_ready a udp
[ "$(config a tcp)" = "$(get_cache_var ACL_GLOBAL_TCP_instance)" ] && [ "$(config a udp)" = "$(get_cache_var ACL_GLOBAL_UDP_instance)" ] || fail 'global instance not inherited'
[ "$(get_cache_var ACL_a_tcp_default)" = 1 ] && [ "$(get_cache_var ACL_a_udp_default)" = 1 ] || fail 'inheritance flag missing'
status_is 0 passwall_start_acl_nodes b 1 1 invalid invalid 0 warn
old_tcp=$(config a tcp);old_udp=$(config a udp)
status_is 0 passwall_start_global_nodes ss2 hy2
acl_ready a tcp;acl_ready a udp;acl_ready b tcp;acl_ready b udp
[ "$(config a tcp)" = "$old_tcp" ] && [ "$(config b udp)" = "$old_udp" ] || fail 'new global replaced old ACL instance'
state_is ready a tcp hy1
status_is 1 passwall_acl_protocol_state a tcp ss2
acl_stop b;acl_ready a tcp;acl_ready a udp
status_is 0 passwall_stop_global_nodes;acl_ready a tcp;acl_ready a udp
acl_stop a
for pair in 'ssbad hy1' 'hy1 ssbad';do
	set -- $pair;status_is 2 passwall_start_global_nodes "$1" "$2"
	status_is 0 passwall_start_acl_nodes a 1 1 retired retired 0 warn
	if [ "$1" = ssbad ];then status_is 1 passwall_acl_node_ready a tcp;acl_ready a udp
	else acl_ready a tcp;status_is 1 passwall_acl_node_ready a udp;fi
	state_is "$( [ "$1" = ssbad ] && echo failed || echo ready )" a tcp "$1"
	state_is "$( [ "$2" = ssbad ] && echo failed || echo ready )" a udp "$2"
	acl_stop a;status_is 0 passwall_stop_global_nodes
done
status_is 0 passwall_start_global_nodes hy1 tcp
status_is 0 passwall_start_acl_nodes a 1 1 '' '' 0 warn
status_is 0 passwall_start_acl_nodes b 1 1 '' '' 0 warn
g=$(get_cache_var ACL_GLOBAL_TCP_instance);kill -KILL "$(instance_pid "$g")"
status_is 1 passwall_acl_node_ready a tcp;status_is 1 passwall_acl_node_ready b udp
state_is failed a tcp hy1;state_is failed b udp hy1
acl_stop a;acl_stop b
status_is 0 passwall_start_acl_nodes a 1 1 '' '' 0 warn;acl_closed a
acl_stop a;status_is 0 passwall_stop_global_nodes
echo 'PASS live/partial/failed global inheritance, defaults, global stop and no invented protocol capabilities'

for bad in ssbad hybad ssexit hyexit ssstall hystall sstcpmissing ssudpmissing hytcpmissing hyudpmissing;do
	status_is 0 acl_start a hyfake tcp;a=$(config a tcp)
	status_is 2 acl_start b "$bad" tcp;acl_closed b
	[ "$(get_cache_var ACL_b_split_failed)" = 1 ] || fail 'failed ACL diagnosis missing'
	acl_ready a tcp;acl_ready a udp;[ "$(config a tcp)" = "$a" ] || fail 'B rollback changed A'
	acl_stop b;acl_stop a
done
# Same-node B must create a new instance when log differs; failure cannot find
# its ownership through A's node cache or stop A's FakeTCP rule.
status_is 0 acl_start a hyfake tcp;a=$(config a tcp)
touch "$PW_RELAY_FAIL"
# Relay fixture failure exercises the SS second-process failure path.
status_is 2 acl_start b ss1 tcp;acl_closed b
rm "$PW_RELAY_FAIL";acl_ready a tcp;acl_stop b
# Fail a same-node Hysteria start at the actual version-command boundary.
mv "$work/bin/hysteria" "$work/bin/hysteria.good"
cat > "$work/bin/hysteria" <<'SH'
#!/bin/sh
[ "$1" != --version ] || { echo 'hysteria version v2.0.0';exit 0; }
exit 3
SH
chmod +x "$work/bin/hysteria"
status_is 2 acl_start b hyfake tcp 1;acl_closed b
mv "$work/bin/hysteria.good" "$work/bin/hysteria"
acl_ready a tcp;acl_ready a udp;[ "$(config a tcp)" = "$a" ] || fail 'same-node B damaged A'
[ -s "$PW_RULES" ] || fail 'B removed A FakeTCP rule'
acl_stop b;acl_stop a;[ ! -s "$PW_RULES" ] || fail 'last FakeTCP cleanup leaked'
echo 'PASS config/exit/listener failures, SS relay failure and same-node Hysteria A-success B-failure isolation'
status_is 2 acl_start b missing tcp;acl_closed b;acl_stop b

# Native occupied ports are not accepted as our listeners and are not killed.
dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --user=root --port=11200 --listen-address=127.0.0.1 --bind-interfaces > "$work/holder.log" 2>&1 &
holder=$!
for n in $(seq 1 100);do [ "$(check_port_exists 11200 tcp,udp)" != 0 ] && break;sleep 0.1;done
status_is 0 acl_start a ss1 tcp;acl_ready a tcp
[ "$(get_cache_var ACL_a_tcp_redir_port)" != 11200 ] || fail 'occupied port reused'
acl_stop a;kill -0 "$holder" || fail 'foreign port owner killed';kill "$holder";wait "$holder" || :

fault_key=;partial=0;record_fail_at=0;record_count=0;release_write_fail=0
printf() {
	if [ "$release_write_fail" = 1 ] && [ "$1" = '%s\n' ] && [ "$#" = 2 ];then
		case "$2" in "$TMP_ACL_PATH"/split-acl/instance.*) command printf 'partial';return 1 ;; esac
	fi
	if [ "$1" = '%s\n' ] && [ "$#" = 3 ] && [ "$record_fail_at" != 0 ];then
		record_count=$((record_count + 1))
		if [ "$record_count" = "$record_fail_at" ];then command printf '%s\n' "$2";return 1;fi
	fi
	if [ "$1" = '%s=%s\n' ] && [ "$2" = "$fault_key" ];then [ "$partial" != 1 ] || command printf "%s='broken" "$2";return 1;fi
	command printf "$@"
}
status_is 0 acl_start a hyfake tcp;a=$(config a tcp)
for record_fail_at in 1 2;do
	record_count=0
	status_is 2 acl_start b ss1 tcp;acl_closed b;acl_ready a tcp
	[ "$record_count" -ge "$record_fail_at" ] || fail 'process-record injection not exercised'
	[ -z "$(find "$TMP_ACL_PATH/split-acl" -name process)" ] || fail 'failed SS process record/instance leaked'
	acl_stop b
done
record_fail_at=0
for proto in tcp udp;do
	for field in node redir_port instance default;do
		fault_key="ACL_b_${proto}_${field}"
		for partial in 0 1;do
			# inherited default=1 must be in the same atomic publication group.
			if [ "$field" = default ];then
				status_is 0 passwall_start_global_nodes ss1 tcp
				status_is 2 passwall_start_acl_nodes b 1 1 '' '' 0 warn
			else status_is 2 acl_start b ss1 tcp;fi
			status_is 1 passwall_acl_node_ready b "$proto"
			acl_ready a tcp;acl_ready a udp;[ "$(config a tcp)" = "$a" ] || fail 'cache fault damaged A'
			passwall_stop_acl_nodes b || fail 'failed binding not retryable'
		done
	done
done
fault_key=;partial=0
status_is 0 passwall_stop_global_nodes
for proto in tcp udp;do
	fault_key="ACL_b_${proto}_instance"
	status_is 2 acl_start b ss1 hy1
	if [ "$proto" = tcp ];then state_is failed b tcp ss1;state_is ready b udp hy1
	else state_is ready b tcp ss1;state_is failed b udp hy1;fi
	acl_ready a tcp;acl_stop b
done
fault_key=ACL_b_split_failed
status_is 1 acl_start b ssbad tcp;acl_closed b;acl_ready a tcp
fault_key=
# A failed publication into an already shared instance must not kill that owner.
fault_key=ACL_b_tcp_node
status_is 2 acl_start b hyfake tcp;acl_ready a tcp;acl_closed b
fault_key=
# Withdrawal failure keeps the live binding and ownership for retry.
mv() { return 1; }
status_is 1 passwall_stop_acl_nodes a
acl_ready a tcp;acl_ready a udp
unset -f mv
# Distinguish release-list publication failure from cache withdrawal failure.
release_write_fail=1
status_is 1 passwall_stop_acl_nodes a;acl_ready a tcp;acl_ready a udp
release_write_fail=0
mktemp() {
	case "$1" in */release.a.XXXXXX) return 1 ;; *) command mktemp "$@" ;; esac
}
status_is 1 passwall_stop_acl_nodes a;acl_ready a tcp;acl_ready a udp
unset -f mktemp
mv() {
	case "$*" in *" $TMP_PATH/var") return 1 ;; *) command mv "$@" ;; esac
}
status_is 1 passwall_stop_acl_nodes a;acl_ready a tcp;acl_ready a udp
[ -s "$TMP_ACL_PATH/split-acl/release.a" ] || fail 'failed unpublish lost saved release paths'
unset -f mv
acl_stop b;acl_stop a
echo 'PASS atomic protocol/default publication, partial writes, shared-owner preservation and failed-unpublish retry'

# Kill the actual newly launched process during the real cache rename. A later
# live query cannot trust the tuple; failed withdrawal must preserve retry state.
mv() {
	case "$*" in
		*" $TMP_PATH/var")
			[ ! -e "$work/acl-fired" ] || [ "$withdraw_error" != 1 ] || return 1
			command mv "$@" || return 1
			[ ! -e "$work/acl-fired" ] || return 0
			local cfg target
			cfg=$(config b tcp) || return 0
			[ -n "$cfg" ] || return 0
			touch "$work/acl-fired"
			target=$(pid_for "$cfg");kill -KILL "$target" || return 1
			command sleep 0.03
			;;
		*) command mv "$@" ;;
	esac
}
for core in ss1 hyfake;do
	withdraw_error=0;rm -f "$work/acl-fired"
	status_is 2 acl_start b "$core" tcp;acl_closed b
	[ -e "$work/acl-fired" ] || fail 'cache publication death not injected'
	acl_stop b
done
withdraw_error=1;rm -f "$work/acl-fired"
status_is 1 acl_start b hyfake tcp
status_is 1 passwall_acl_node_ready b tcp
pending=$(config b tcp)
[ -n "$pending" ] && [ -e "${pending%/config.json}/meta" ] || fail 'failed withdrawal lost retry state'
unset -f mv
acl_stop b
[ ! -s "$PW_RULES" ] || fail 'failed withdrawal leaked FakeTCP rule'
echo 'PASS death during publication, no stale-ready result, failed withdrawal and exact-instance retry'

# Unknown reference state is hard failure; preserve the live resource for retry.
status_is 0 acl_start b ss1 ''
pending=$(config b tcp)
sed() {
	if [ "$1" = -n ] && [ "$2" = 's/^\([A-Za-z0-9_]*_instance\)=.*/\1/p' ];then return 1;fi
	command sed "$@"
}
status_is 1 passwall_stop_acl_nodes b;acl_closed b
_pw_acl_instance_ready "${pending%/config.json}" || fail 'reference-read error killed instance'
unset -f sed
acl_stop b

# Hard process cleanup failure: preserve exact records, then successfully retry.
# The last reference can belong to someone other than the original creator.
retry_stop() { ( unset PW_ACL_NEW_DIR PW_ACL_NEW_PID PW_ACL_NEW_BIRTH; passwall_stop_acl_nodes "$1" ); }
status_is 0 acl_start a ss1 tcp
shared=$(config a tcp)
shared_port=$(get_cache_var ACL_a_tcp_redir_port)
shared_socks=$(cat "${shared%/config.json}/socks_port")
shared_pid=$(pid_for "$shared");shared_birth=$(get_process_start_time "$shared_pid")
status_is 0 acl_start b ss1 tcp
acl_stop a;acl_ready b tcp
kill() { return 1; }
status_is 1 passwall_stop_acl_nodes b;acl_closed b
unset -f kill
status_is 0 retry_stop b
[ ! -d "${shared%/config.json}" ] || fail 'last non-creator cleanup retry lost its instance'
status_is 1 _pw_global_ss_alive "$shared_pid" "$shared_birth"
[ "$(check_port_exists "$shared_port" tcp,udp)" = 0 ] && [ "$(check_port_exists "$shared_socks" tcp,udp)" = 0 ] || fail 'last consumer retry left SS listeners'
for source in acl global;do
	if [ "$source" = acl ];then status_is 0 acl_start a hyfake tcp
	else status_is 0 passwall_start_global_nodes hyfake tcp;status_is 0 passwall_start_acl_nodes a 1 1 '' '' 0 warn;fi
	shared=$(config a tcp)
	shared_port=$(get_cache_var ACL_a_tcp_redir_port)
	if [ "$source" = acl ];then status_is 0 acl_start b hyfake tcp
	else status_is 0 passwall_start_acl_nodes b 1 1 '' '' 0 warn;status_is 0 passwall_start_global_nodes ss2 tcp;fi
	acl_stop a;acl_ready b tcp
	touch "$PW_RULES.delete-error"
	status_is 1 passwall_stop_acl_nodes b;acl_closed b
	[ -s "$TMP_ACL_PATH/split-acl/release.b" ] || fail 'last releaser lost retry responsibility'
	[ "$(wc -l < "$TMP_ACL_PATH/split-acl/release.b")" = 1 ] || fail 'combined release path recorded more than once'
	rm "$PW_RULES.delete-error"
	status_is 0 retry_stop b
	[ ! -d "${shared%/config.json}" ] && [ ! -e "$TMP_ACL_PATH/split-acl/release.b" ] || fail 'last releaser cleanup did not finish'
	[ "$(check_port_exists "$shared_port" tcp,udp)" = 0 ] || fail 'last releaser left transparent listener'
	if [ "$source" = global ];then ready TCP;status_is 0 passwall_stop_global_nodes;fi
done
status_is 0 passwall_start_global_nodes ss1 tcp
status_is 0 passwall_start_acl_nodes a 1 1 '' '' 0 warn
shared=$(config a tcp)
status_is 0 passwall_start_global_nodes ss2 tcp
kill() { return 1; }
status_is 1 passwall_stop_acl_nodes a;acl_closed a
unset -f kill
status_is 0 retry_stop a
[ ! -d "${shared%/config.json}" ] || fail 'global SS last-consumer retry leaked instance'
ready TCP;status_is 0 passwall_stop_global_nodes
# Removing the release list itself may fail after the instance is gone.
status_is 0 acl_start b ss1 tcp
shared=$(config b tcp)
rm() {
	case "$*" in *" $TMP_ACL_PATH/split-acl/release.b") return 1 ;; *) command rm "$@" ;; esac
}
status_is 1 passwall_stop_acl_nodes b;acl_closed b
[ ! -d "${shared%/config.json}" ] && [ -e "$TMP_ACL_PATH/split-acl/release.b" ] || fail 'release-list cleanup error hidden'
unset -f rm
status_is 0 retry_stop b
[ ! -e "$TMP_ACL_PATH/split-acl/release.b" ] || fail 'completed release-list retry failed'
echo 'PASS last non-creator/global consumer cleanup failure, persisted responsibility and retry without original creator'
status_is 0 acl_start a hyfake tcp;a=$(config a tcp)
fault_key=ACL_b_udp_node
kill() { return 1; }
status_is 1 acl_start b ss1 tcp
acl_closed b;acl_ready a tcp
[ -n "$(find "$TMP_ACL_PATH/split-acl" -name process)" ] || fail 'failed SS cleanup lost records'
unset -f kill
fault_key=
acl_stop b;acl_ready a tcp;acl_stop a
# FakeTCP cleanup errors retain rule ownership and do not affect a different ACL.
status_is 0 acl_start a ss1 tcp
fault_key=ACL_b_udp_node;touch "$PW_RULES.delete-error"
status_is 1 acl_start b hyfake tcp;acl_closed b;acl_ready a tcp
[ -s "$PW_RULES" ] || fail 'retry rule ownership lost'
fault_key=;rm "$PW_RULES.delete-error"
acl_stop b;acl_ready a tcp;acl_stop a
[ ! -s "$PW_RULES" ] || fail 'FakeTCP retry leaked rule'
for core in ss1 hy1;do
	status_is 0 acl_start a "$core" tcp;old=$(config a tcp)
	status_is 0 acl_start a "$core" tcp;new=$(config a tcp)
	[ "$old" != "$new" ] && [ ! -d "${old%/config.json}" ] || fail 'restart reused stale instance'
	acl_stop a
done
[ "$(get_cache_var ACL_GLOBAL_node)" = legacy ] && [ "$(get_cache_var acl_node_ss1_socks_port)" = 19997 ] && [ "$(get_cache_var ACL_legacy_node)" = untouched ] && [ "$(get_cache_var s1)" = hy1 ] || fail 'legacy/independent cache modified'
lua "$HYSTERIA_RUNTIME" ready client "$work/native-socks.json" || fail 'independent SOCKS killed'
lua "$HYSTERIA_RUNTIME" stop client "$work/native-socks.json"
[ -z "$(find "$TMP_ACL_PATH/split-acl" -name meta)" ] || fail 'owned ACL instances leaked'
echo 'PASS exact-instance cleanup failures/retry, FakeTCP ownership, continuous restart and legacy/SOCKS isolation'
