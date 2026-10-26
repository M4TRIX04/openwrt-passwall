#!/bin/sh
# Sourced by the existing immutability runner. Retain the explicit ACL socket
# fixtures and cover F1's real frozen Global listeners in the same container.
/bin/ash -n "$PW_BOUND_REPO/tests/shell-bound-socket.sh"
cat > "$work/socket-prepare.lua" <<'LUA'
local api = require "luci.passwall.api"
local params = assert(api.jsonc.parse(arg[6]))
params.socks_tcp_socket = {address="127.0.0.1", protocol="tcp", family="4",
	port=assert(tonumber(params.local_socks_port or params.local_port))}
require("luci.passwall.runtime_binding").prepare(arg[1], arg[2], arg[3], arg[4], arg[5], api.jsonc.stringify(params))
LUA

for core in ss hy; do
	uci set passwall.a.use_global_config=0; uci set passwall.b.use_global_config=0
	uci set "passwall.a.tcp_node=$core"; uci set passwall.a.udp_node=tcp
	uci set "passwall.b.tcp_node=$core"; uci set passwall.b.udp_node=tcp
	capture
	PW_SOCKET_FIXTURE=1
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
	PW_SOCKET_FIXTURE=0
	config=$(acl_config a tcp); instance=${config%/*}
	python3 - "$instance" <<'PY'
import json,sys
d=sys.argv[1]
b=json.load(open(d+'/binding.json')); c=json.load(open(d+'/bound.capabilities'))
assert b['socks_tcp_socket']=={'address':'127.0.0.1','protocol':'tcp','family':'4','port':int(open(d+'/socks_port').read())}
assert c['socks_tcp_socket']=={'4':True} and c['tcp']=={'4':True} and c['udp']=={'4':True}
assert 'dep_ready' not in c and 'dep_validated' not in c
PY
	files "$instance" > "$work/socket-published"
	count=$(seals)
	status_is 0 publish a "$instance" 1 1 ''
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
	[ "$(acl_config b tcp)" = "$config" ] && [ "$(seals)" = "$count" ] || fail socket-reference-not-shared
	unchanged "$instance" "$work/socket-published"
	status_is 1 _pw_bound_helper verify "$instance" 4 socks_tcp_socket
	echo "PASS fixture $core: explicit SOCKS TCP socket sealed/referenced with owned IPv4 loopback; shared without rewriting"
	cp -p "$instance/binding.json" "$work/socket-binding"
	cp -p "$instance/bound.capabilities" "$work/socket-caps"
	for fault in missing_cap extra_family false_cap malformed_cap wildcard_decl wrong_port wrong_protocol wrong_family unknown_field missing_port; do
		python3 - "$instance" "$fault" <<'PY'
import json,os,sys
d,fault=sys.argv[1:]
if fault=='missing_port': os.remove(d+'/socks_port')
else:
 name='bound.capabilities' if fault in ('missing_cap','extra_family','false_cap','malformed_cap') else 'binding.json'
 p=d+'/'+name; c=json.load(open(p)); s=c['socks_tcp_socket']
 if fault=='missing_cap': del c['socks_tcp_socket']
 elif fault=='extra_family': s['6']=True
 elif fault=='false_cap': s['4']=False
 elif fault=='malformed_cap': c['socks_tcp_socket']='not a capability table'
 elif fault=='wildcard_decl': s['address']='0.0.0.0'
 elif fault=='wrong_port': s['port']+=1
 elif fault=='wrong_protocol': s['protocol']='udp'
 elif fault=='wrong_family': s['family']='6'
 else: s['pid']=1
 open(p,'w').write(json.dumps(c))
PY
		files "$instance" > "$work/rejected"
		status_is 1 _pw_bound_helper reference "$instance" "$snapshot" ipv4 4
		unchanged "$instance" "$work/rejected"
		cp -p "$work/socket-binding" "$instance/binding.json"
		cp -p "$work/socket-caps" "$instance/bound.capabilities"
		python3 - "$instance" <<'PY'
import json,sys
d=sys.argv[1];p=json.load(open(d+'/binding.json'))['socks_tcp_socket']['port']
open(d+'/socks_port','w').write(str(p)+'\n')
PY
		echo "REJECT fixture $core: $fault; reference rc=1, no repair"
	done
	if [ "$core" = ss ]; then
		# A separate real ss-local supplies controlled socket evidence. Its
		# frozen JSON is kept intact; a test-only launch JSON intentionally
		# opens a different socket. No Global instance or reference is created.
		for fault in wildcard endian_alias foreign wrong_port udp; do
			probe_dir=$(mktemp -d "$work/socket-probe.XXXXXX")
			probe_port=$(get_new_port 14000 tcp,udp)
			expected_port=$probe_port
			[ "$fault" != foreign ] || expected_port=$(cat "$instance/socks_port")
			printf 'SS\nss\n\n\n' > "$probe_dir/meta"
			printf '%s\n' "$expected_port" > "$probe_dir/socks_port"
			PW_SOCKET_FIXTURE=1
			status_is 0 _pw_bound_helper prepare "$snapshot" ss ipv4 4 "$probe_dir" "{\"local_addr\":\"127.0.0.1\",\"local_port\":$expected_port,\"mode\":\"tcp_only\"}"
			PW_SOCKET_FIXTURE=0
			actual_port=$probe_port; actual_proto=tcp
			[ "$fault" != wrong_port ] || actual_port=$(get_new_port 15000 tcp,udp)
			[ "$fault" != udp ] || actual_proto=udp
			python3 - "$probe_dir" "$fault" "$actual_port" <<'PY'
import json,sys
d,fault,p=sys.argv[1:]; c=json.load(open(d+'/config.json'));c['local_port']=int(p)
if fault=='wildcard': c['local_address']='0.0.0.0'
if fault=='endian_alias': c['local_address']='1.0.0.127'
if fault=='udp': c['mode']='udp_only'
json.dump(c,open(d+'/launch-fixture.json','w'))
PY
			ln -s "$(first_type ss-local)" "$probe_dir/core"
			[ "$fault" != endian_alias ] || ip address add 1.0.0.127/32 dev lo
			probe_pid=$(_pw_bound_helper spawn "$probe_dir/log" "$probe_dir/core" -c "$probe_dir/launch-fixture.json" -v)
			probe_birth=$(get_process_start_time "$probe_pid")
			printf '%s\n%s\nfixture\n' "$probe_pid" "$probe_birth" > "$probe_dir/process"
			for i in $(seq 1 100); do
				_pw_global_ss_socket "$probe_pid" "$actual_proto" "$actual_port" && break
				sleep .02
			done
			_pw_global_ss_socket "$probe_pid" "$actual_proto" "$actual_port" || fail socket-fixture-not-listening
			files "$probe_dir" > "$work/socket-probe-before"
			status_is 1 _pw_bound_helper verify "$probe_dir" 2> "$work/socket-error"
			grep -q 'SOCKS TCP socket unavailable at exact loopback' "$work/socket-error" || fail wrong-socket-rejection-path
			status_is 1 _pw_bound_helper seal "$probe_dir" 2> "$work/socket-error"
			grep -q 'SOCKS TCP socket unavailable at exact loopback' "$work/socket-error" || fail wrong-socket-seal-path
			unchanged "$probe_dir" "$work/socket-probe-before"
			_pw_global_ss_kill "$probe_pid" "$probe_birth" || fail socket-fixture-stop
			[ "$fault" != endian_alias ] || ip address del 1.0.0.127/32 dev lo
			echo "REJECT real socket fixture: $fault; correct process/GID cannot substitute wrong address/protocol/port or foreign inode"
		done
	fi
	status_is 0 passwall_stop_acl_nodes a
	passwall_acl_node_ready b tcp || fail socket-shared-instance-stopped
	status_is 0 passwall_stop_acl_nodes b
	[ ! -d "$instance" ] || fail socket-last-reference-kept-instance
	# Internal SOCKS stays IPv4 even when transparent capability is IPv6/dual.
	TCP_PROXY_WAY=tproxy
	for family in 6 dual; do
		capture; PW_SOCKET_FIXTURE=1
		status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv6 "$family" 0 warn
		PW_SOCKET_FIXTURE=0
		config=$(acl_config a tcp); instance=${config%/*}
		status_is 0 _pw_bound_helper reference "$instance" "$snapshot" ipv6 "$family"
		python3 - "$instance" "$family" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]+'/bound.capabilities'))
assert c['socks_tcp_socket']=={'4':True}
assert set(c['tcp'])==set(c['udp'])==({'6'} if sys.argv[2]=='6' else {'4','6'})
PY
		status_is 0 passwall_stop_acl_nodes a
		echo "PASS fixture $core: transparent family=$family remains independent of IPv4 SOCKS socket"
	done
	TCP_PROXY_WAY=redirect
done

# An existing undeclared instance cannot acquire the new capability by adding
# a record. Rejection must not rewrite the record into either format.
uci set passwall.a.tcp_node=ss; uci set passwall.a.udp_node=tcp
capture
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
config=$(acl_config a tcp); instance=${config%/*}
cp -p "$instance/bound.capabilities" "$work/legacy-caps"
python3 - "$instance/bound.capabilities" <<'PY'
import json,sys
p=sys.argv[1];c=json.load(open(p));assert 'socks_tcp_socket' not in c
c['socks_tcp_socket']={'4':True};json.dump(c,open(p,'w'))
PY
files "$instance" > "$work/rejected"
status_is 1 _pw_bound_helper reference "$instance" "$snapshot" ipv4 4
unchanged "$instance" "$work/rejected"
mv "$work/legacy-caps" "$instance/bound.capabilities"
status_is 0 _pw_bound_helper reference "$instance" "$snapshot" ipv4 4
status_is 0 passwall_stop_acl_nodes a
echo 'REJECT undeclared legacy instance with injected SOCKS capability; original format still references after test restore'

# Reject malformed declarations at prepare, before writing instance records.
cat > "$work/socket-invalid.lua" <<'LUA'
local api = require "luci.passwall.api"
local bound = require "luci.passwall.runtime_binding"
local cases = {
	{address="0.0.0.0"}, {address="::1"}, {protocol="udp"}, {family="6"},
	{port=0}, {port=65536}, {port=123.5}, {port="12345"}, {pid=1}, false
}
for i, patch in ipairs(cases) do
	local declaration = {address="127.0.0.1",protocol="tcp",family="4",port=12345}
	if type(patch)=="table" then for k,v in pairs(patch) do declaration[k]=v end else declaration=patch end
	local dir=arg[2].."/invalid-declaration."..i; assert(api.fs.mkdir(dir))
	local params={local_addr="127.0.0.1",local_port=12345,mode="tcp_only",socks_tcp_socket=declaration}
	local ok, err=pcall(bound.prepare,arg[1],"ss","ipv4","4",dir,api.jsonc.stringify(params))
	assert(not ok and tostring(err):find("SOCKS",1,true),tostring(err))
	assert(not api.fs.access(dir.."/binding.json") and not api.fs.access(dir.."/config.json"))
end
print("REJECT malformed SOCKS declarations: address/protocol/family/port/type/unknown PID; no instance records written")
LUA
status_is 0 lua "$work/socket-invalid.lua" "$snapshot" "$work"

# F1 Global TCP-only: exact socket evidence and SS subordinate identity belong
# to one frozen instance. The combined/shared path is covered by the caller.
uci set passwall.a.use_global_config=0; uci set passwall.b.use_global_config=0
uci -q delete passwall.settings.udp_node || :
for core in ss hy; do
	uci set "passwall.settings.tcp_node=$core"
	capture
	status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	config=$(global_config TCP); instance=${config%/*}
	[ -z "$(global_config UDP)$(get_cache_var GLOBAL_SOCKS_server)" ] || fail f1-published-unrequested-role
	status_is 0 _pw_bound_helper reference "$instance" "$snapshot" ipv4 4
	status_is 1 _pw_bound_helper verify "$instance" 4 socks_tcp_socket
	python3 - "$instance" "$core" <<'PY'
import hashlib,json,sys
d,core=sys.argv[1:];load=lambda name:json.load(open(d+'/'+name))
b=load('binding.json');c=load('bound.capabilities');main=load('bound.identity')
assert c=={'tcp':{'4':True},'socks_tcp_socket':{'4':True}}
s=b['ss_socks']['socket'] if core=='ss' else b['socks_tcp_socket']
assert s=={'address':'127.0.0.1','protocol':'tcp','family':'4','port':int(open(d+'/socks_port').read())}
if core=='ss':
 aux=load('socks/bound.identity');cfg=load('socks/config.json');primary=load('config.json')
 assert str(aux['pid'])!=str(main['pid']) and cfg['mode']=='tcp_only' and not cfg.get('tcp_tproxy')
 assert cfg['local_address']=='127.0.0.1' and cfg['local_port']==s['port']
 assert cfg['server']==primary['server']==b['endpoint']['address'] and cfg['server_port']==primary['server_port']==b['endpoint']['port']
 assert aux['generation']==main['generation']==b['endpoint']['generation']
 assert b['ss_socks']['config_md5']==hashlib.md5(open(d+'/socks/config.json','rb').read()).hexdigest()
 for sub,record in [('',main),('socks/',aux)]:
  lines=open(d+'/'+sub+'process').read().splitlines()
  assert lines[:2]==[str(record['pid']),str(record['birth'])]
  stat=open('/proc/'+lines[0]+'/stat').read().rsplit(') ',1)[1].split()
  assert stat[0]!='Z' and stat[19]==lines[1]
else:
 assert load('config.json')['socks5']['listen']=='127.0.0.1:'+str(s['port'])
PY
	# Missing or forged subordinate identity cannot be repaired by reference.
	if [ "$core" = ss ]; then
		cp -p "$instance/socks/bound.identity" "$work/f1-identity"
		for fault in missing wrong_birth; do
			if [ "$fault" = missing ]; then rm "$instance/socks/bound.identity"
			else
				python3 - "$instance/socks/bound.identity" <<'PY'
import json,sys
p=sys.argv[1];r=json.load(open(p));r['birth']=str(int(r['birth'])+1);json.dump(r,open(p,'w'))
PY
			fi
			files "$instance" > "$work/rejected"
			status_is 1 _pw_bound_helper reference "$instance" "$snapshot" ipv4 4
			status_is 1 _pw_global_instance_stop "$instance"
			unchanged "$instance" "$work/rejected"
			_pw_global_ss_ready "$instance" && _pw_global_ss_socks_ready "$instance" || fail f1-rejection-killed-process
			cp -p "$work/f1-identity" "$instance/socks/bound.identity"
		done
	fi
	status_is 0 passwall_stop_global_nodes
	[ ! -d "$instance" ] || fail f1-tcp-only-stop
	echo "PASS F1 Global $core TCP-only: frozen loopback socket/identity; no UDP or production SOCKS cache"
	# UDP-only must never obtain an auxiliary or native SOCKS declaration.
	uci -q delete passwall.settings.tcp_node || :
	uci set "passwall.settings.udp_node=$core"
	capture; status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	config=$(global_config UDP); instance=${config%/*}
	python3 - "$instance" <<'PY'
import json,os,sys
d=sys.argv[1];b=json.load(open(d+'/binding.json'));c=json.load(open(d+'/bound.capabilities'))
assert 'ss_socks' not in b and 'socks_tcp_socket' not in b
assert c=={'udp':{'4':True}} and not os.path.exists(d+'/socks_port') and not os.path.exists(d+'/socks')
PY
	status_is 0 passwall_stop_global_nodes
	uci -q delete passwall.settings.udp_node || :
done

# Real ss-local launch, then a partial process-receipt write (e.g. ENOSPC).
# Keep an unrelated live ACL to detect accidental cross-instance cleanup.
uci set passwall.settings.tcp_node=ss; uci set passwall.settings.udp_node=tcp
uci set passwall.a.tcp_node=ss; uci set passwall.a.udp_node=tcp
capture; status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
keep_config=$(acl_config a tcp); keep_instance=${keep_config%/*}
files "$keep_instance" > "$work/f1-keep"
printf() {
	if [ "$#" = 2 ] && [ "$1" = '%s' ] && [ -n "${PW_GLOBAL_NEW_SOCKS_PROCESS:-}" ] &&
		[ "$2" = "$PW_GLOBAL_NEW_SOCKS_PROCESS" ]; then
		command printf '%s\n' "$PW_GLOBAL_NEW_SOCKS_PID"
		command printf '%s\n' "$PW_GLOBAL_NEW_PID" "$PW_GLOBAL_NEW_BIRTH" \
			"$PW_GLOBAL_NEW_SOCKS_PID" "$PW_GLOBAL_NEW_SOCKS_BIRTH" > "$work/f1-write-hit"
		return 1
	fi
	command printf "$@"
}
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
unset -f printf
[ -s "$work/f1-write-hit" ] || fail f1-write-fault-not-hit
python3 - "$work/f1-write-hit" > "$work/f1-processes" <<'PY'
import json,sys
v=open(sys.argv[1]).read().splitlines();assert len(v)==4 and all(x.isdigit() for x in v)
json.dump([v[:2],v[2:]],sys.stdout)
PY
processes_gone "$work/f1-processes"
[ -z "$(global_config TCP)$(global_config UDP)" ] &&
	[ -z "$(find "$GLOBAL_ACL_PATH/split" -maxdepth 1 -name 'instance.*' -print)" ] || fail f1-failed-write-leaked
passwall_acl_node_ready a tcp && passwall_acl_node_ready a udp || fail f1-rollback-killed-unrelated-ACL
unchanged "$keep_instance" "$work/f1-keep"
echo 'REJECT F1 SS auxiliary partial process write: rc=2, both owned PIDs reclaimed; unrelated ACL preserved'

# A spawn may have launched a child before its PID reply is lost. The creating
# caller must retain responsibility, never infer no-launch from an empty reply.
# Restore the helper after this scenario; only the test observer knows the PID.
eval "$(sed -n '/^_pw_bound_helper() {/,/^}/p' "$PW_BOUND_REPO/tests/shell-bound-immutability.sh" | sed '1s/_pw_bound_helper/f1_real_helper/')"
_pw_bound_helper() {
	if [ "$1" = spawn ]; then
		case "$3" in */socks/core)
			local observed_pid observed_birth
			observed_pid=$(f1_real_helper "$@") || return 1
			observed_birth=$(get_process_start_time "$observed_pid")
			printf '%s\n' "$PW_GLOBAL_NEW_PID" "$PW_GLOBAL_NEW_BIRTH" "$observed_pid" "$observed_birth" > "$work/f1-lost-hit"
			return 1 ;;
		esac
	fi
	f1_real_helper "$@"
}
status_is 1 passwall_start_bound_global_nodes "$snapshot" ipv4 4
instance=$PW_GLOBAL_NEW_INSTANCE
eval "$(sed -n '/^_pw_bound_helper() {/,/^}/p' "$PW_BOUND_REPO/tests/shell-bound-immutability.sh")"
[ -d "$instance" ] && [ -s "$instance/process" ] && [ ! -e "$instance/socks/process" ] &&
	[ ! -e "$instance/bound.capabilities" ] && [ -z "$(global_config TCP)$(global_config UDP)" ] || fail f1-lost-reply-claimed-clean
{ IFS= read -r main_pid; IFS= read -r main_birth; IFS= read -r socks_pid; IFS= read -r socks_birth; } < "$work/f1-lost-hit"
_pw_global_ss_alive "$main_pid" "$main_birth" && _pw_global_ss_alive "$socks_pid" "$socks_birth" || fail f1-lost-reply-guessed-identity
passwall_acl_node_ready a tcp && passwall_acl_node_ready a udp || fail f1-lost-reply-killed-unrelated-ACL
unchanged "$keep_instance" "$work/f1-keep"
# Test observer cleanup only, using the exact identities captured above.
status_is 0 _pw_global_ss_kill "$socks_pid" "$socks_birth"
status_is 0 _pw_global_ss_kill "$main_pid" "$main_birth"
case "$instance" in "$GLOBAL_ACL_PATH"/split/instance.*) rm -rf "$instance" ;; *) fail f1-observer-cleanup-path ;; esac
status_is 0 passwall_stop_acl_nodes a
echo 'REJECT F1 SS auxiliary lost spawn reply: rc=1, responsibility retained; observer cleanup only, automatic recovery NOT claimed'
echo 'SKIP F1 outer connection/data forwarding/DNS helper/dnsmasq L1-L3/dep_ready and production/device integration'
