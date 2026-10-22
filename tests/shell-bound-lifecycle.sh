#!/bin/sh
# Sourced by the real native test after network counter validation.
pid_for() {
	if [ "$(head -n 1 "${1%/config.json}/meta")" = SS ];then head -n 1 "${1%/config.json}/process"
	else python3 - "$1" <<'PY'
import hashlib,json,sys
print(json.load(open('/tmp/etc/passwall_hysteria1/'+hashlib.md5(sys.argv[1].encode()).hexdigest()+'.json'))['pid'])
PY
	fi
}
TCP_PROXY_WAY=redirect
uci set passwall.hy.protocol=udp;uci set passwall.hy.port=34443
# Missing manager metadata is not evidence of a dead process. In particular,
# deny /proc reading at the I/O boundary while keeping the real core alive.
uci set passwall.settings.tcp_node=hy;uci set passwall.settings.udp_node=tcp
capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
owned=$(global_config TCP);owned_pid=$(pid_for "$owned")
record=$(python3 - "$owned" <<'PY'
import hashlib,sys
print('/tmp/etc/passwall_hysteria1/'+hashlib.md5(sys.argv[1].encode()).hexdigest()+'.json')
PY
)
mv "$record" "$work/manager-backup"
status_is 1 _pw_bound_helper owner "${owned%/*}"
cat > "$work/owner-read-fault.lua" <<'LUA'
local fs=require('luci.passwall.api').fs
local real_read=fs.readfile
local real_stat=fs.stat
fs.readfile=function(p)
 if p=='/proc/'..arg[2]..'/stat' then return nil end
 return real_read(p)
end
if arg[3]=='stat' then
 fs.stat=function(p)
  if p=='/proc/'..arg[2] then return nil,13,'Permission denied' end
  return real_stat(p)
 end
end
local ok,err=pcall(require('luci.passwall.runtime_binding').owner,arg[1])
assert(not ok,'unreadable /proc was mistaken for a stopped owned core')
assert(tostring(err):find(arg[3]=='stat' and 'cannot establish process absence' or 'cannot read /proc/',1,true),err)
LUA
fault=0;lua "$work/owner-read-fault.lua" "${owned%/*}" "$owned_pid" || fault=$?
lua "$work/owner-read-fault.lua" "${owned%/*}" "$owned_pid" stat || fault=$?
mv "$work/manager-backup" "$record"
[ "$fault" = 0 ] || fail owner-read-failure-accepted
kill -0 "$owned_pid" && passwall_global_node_ready TCP || fail owner-fault-damaged-instance
cp "$record" "$work/manager-backup"
printf 'invalid JSON' > "$record"
kill -KILL "$owned_pid";sleep .1
status_is 1 passwall_stop_global_nodes
[ -f "${owned%/*}/bound.identity" ] && [ -z "$(global_config TCP)" ] || fail corrupt-owner-record-lost
mv "$work/manager-backup" "$record"
rm() {
	[ "$*" != "-rf ${owned%/*}" ] || return 1
	command rm "$@"
}
status_is 1 passwall_stop_global_nodes
[ -f "${owned%/*}/bound.identity" ] && [ ! -e "$record" ] || fail directory-retry-identity-lost
status_is 0 _pw_bound_helper owner "${owned%/*}"
unset -f rm
status_is 0 passwall_stop_global_nodes
[ ! -d "${owned%/*}" ] || fail directory-retry-not-reclaimed
echo 'PASS real live core + missing manager record: unreadable process state blocks cleanup, ownership retained and retry succeeds'
for pair in 'ss hy' 'hy ss';do
	set -- $pair;uci set "passwall.settings.tcp_node=$1";uci set "passwall.settings.udp_node=$2"
	capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	[ "$(global_config TCP)" != "$(global_config UDP)" ] || fail mixed-instance-collision
	passwall_global_node_ready TCP && passwall_global_node_ready UDP || fail mixed-roles
	status_is 0 passwall_stop_global_nodes
done
uci set passwall.a.tcp_node=ss;uci set passwall.a.udp_node=tcp
uci set passwall.b.use_global_config=1
uci set passwall.settings.tcp_node=ss;uci set passwall.settings.udp_node=tcp
capture
status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
inherited=$(acl_config b tcp)
[ "$inherited" = "$(global_config TCP)" ] || fail inherited-wrong-generation
status_is 0 passwall_stop_global_nodes
passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail global-release-stopped-ACL
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
survivor=$(acl_config a tcp);survivor_pid=$(pid_for "$survivor")
status_is 0 passwall_stop_acl_nodes b
uci set passwall.bad=nodes;uci set passwall.bad.type=SS;uci set passwall.bad.address=127.0.0.1
uci set passwall.bad.port=38388;uci set passwall.bad.method=invalid;uci set passwall.bad.password=secret
uci set passwall.settings.tcp_node=bad;uci set passwall.settings.udp_node=hy
capture
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ -z "$(global_config TCP)" ] && passwall_global_node_ready UDP || fail partial-global-isolation
status_is 2 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
[ -z "$(acl_config b tcp)" ] && passwall_acl_node_ready b udp || fail partial-inheritance
kill -0 "$survivor_pid" && passwall_acl_node_ready a tcp || fail other-ACL-stopped
status_is 0 passwall_stop_acl_nodes b;status_is 0 passwall_stop_global_nodes

# A stale snapshot must fail before clearing a healthy global binding.
uci set passwall.settings.tcp_node=ss;uci -q delete passwall.settings.udp_node || :
capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
old=$(global_config TCP)
status_is 1 passwall_start_bound_global_nodes "$snapshot" ipv4 invalid
[ "$(global_config TCP)" = "$old" ] && passwall_global_node_ready TCP || fail invalid-family-damaged-old
status_is 1 passwall_start_bound_global_nodes "$snapshot" invalid 4
[ "$(global_config TCP)" = "$old" ] && passwall_global_node_ready TCP || fail invalid-preference-damaged-old
status_is 1 passwall_start_bound_acl_nodes "$snapshot" a ipv4 invalid 0 warn
[ "$(acl_config a tcp)" = "$survivor" ] && passwall_acl_node_ready a tcp || fail invalid-ACL-family-damaged-old
status_is 1 passwall_start_bound_acl_nodes "$snapshot" a invalid 4 0 warn
[ "$(acl_config a tcp)" = "$survivor" ] && passwall_acl_node_ready a tcp || fail invalid-ACL-preference-damaged-old
uci set passwall.ss.password=changed
status_is 1 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ "$(global_config TCP)" = "$old" ] && passwall_global_node_ready TCP || fail stale-attempt-damaged-old
uci set passwall.ss.password=secret
status_is 0 passwall_stop_global_nodes
capture

# Fail the real atomic cache rename only when it contains a newly published tuple.
mv() {
	case "$*" in *" $TMP_PATH/var") if grep -q '^ACL_GLOBAL_TCP_instance=' "$2";then return 1;fi;;esac
	command mv "$@"
}
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ -z "$(global_config TCP)" ] && passwall_acl_node_ready a tcp || fail cache-failure-leaked-or-cross-cleaned
unset -f mv

# Death after real publication + failed withdrawal must retain exact retry data.
mv() {
	case "$*" in *" $TMP_PATH/var")
		[ ! -e "$work/fired" ] || return 1
		command mv "$@" || return 1
		local c
		c=$(global_config TCP) || return 0
		[ -n "$c" ] || return 0
		touch "$work/fired";kill -KILL "$(pid_for "$c")";sleep .05
		;;
	*) command mv "$@";;esac
}
status_is 1 passwall_start_bound_global_nodes "$snapshot" ipv4 4
pending=$(global_config TCP)
[ -n "$pending" ] && [ -f "${pending%/*}/bound.identity" ] || fail rollback-record-lost
status_is 1 passwall_global_node_ready TCP
kill -0 "$survivor_pid" || fail rollback-cross-instance-kill
unset -f mv
status_is 0 passwall_stop_global_nodes
[ ! -d "${pending%/*}" ] || fail rollback-retry-failed
echo 'PASS native cache publication/withdrawal faults: false-ready blocked, records retained and exact-instance retry; other ACL preserved'

# Fault only the GID launcher: the real ss-redir opens its actual sockets as
# GID 0. Real verification must reject it, not trust a requested GID or PID.
_pw_bound_helper() {
	if [ "$1" = spawn ];then
		shift;local log=$1;shift
		"$@" > "$log" 2>&1 & echo $!
	else lua "$PW_BOUND_HELPER" "$@";fi
}
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ -z "$(global_config TCP)" ] && passwall_acl_node_ready a tcp || fail wrong-GID-accepted
_pw_bound_helper() { lua "$PW_BOUND_HELPER" "$@"; }
echo 'PASS real wrong-GID core/socket rejected and reclaimed; unrelated ACL remains ready'

# Diagnostic failure must not be replaced by process-only readiness.
mkdir -p "$work/bin";real_ss=$(command -v ss)
printf '#!/bin/sh\n[ -z "$PW_BOUND_DIAG_FAULT" ] || exit 2\nexec %s "$@"\n' "$(shell_quote "$real_ss")" > "$work/bin/ss"
chmod +x "$work/bin/ss";export PATH="$work/bin:$PATH" PW_BOUND_DIAG_FAULT=1
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ -z "$(global_config TCP)" ] && kill -0 "$survivor_pid" || fail diagnostics-false-capability
unset PW_BOUND_DIAG_FAULT
passwall_acl_node_ready a udp || fail diagnostics-damaged-survivor

# Real failed FakeTCP deletion/query keeps ownership, and retry clears it.
real_iptables=$(command -v iptables)
printf '#!/bin/sh\ncase " $* " in *" -D OUTPUT "*|*" -C OUTPUT "*) [ -z "$PW_BOUND_RULE_FAULT" ] || exit 2;;esac\nexec %s "$@"\n' "$(shell_quote "$real_iptables")" > "$work/bin/iptables"
chmod +x "$work/bin/iptables"
uci set passwall.hy.protocol=faketcp;uci set passwall.hy.port=34444;uci set passwall.settings.tcp_node=hy
capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
pending=$(global_config TCP);export PW_BOUND_RULE_FAULT=1
status_is 1 passwall_stop_global_nodes
[ -f "${pending%/*}/bound.identity" ] && [ -z "$(global_config TCP)" ] || fail cleanup-responsibility-lost
status_is 1 passwall_global_node_ready TCP
kill -0 "$survivor_pid" || fail FakeTCP-cleanup-crossed-ACL
unset PW_BOUND_RULE_FAULT
status_is 0 passwall_stop_global_nodes
[ ! -d "${pending%/*}" ] || fail FakeTCP-retry-kept-instance
echo 'PASS actual FakeTCP delete/query failure, owner record retention, failed-ready state and retry without losing other instances'
status_is 0 passwall_stop_acl_nodes a

# Same source text, new resolution/generation: do not share/relabel the old process.
uci set passwall.b.use_global_config=0;uci set passwall.b.tcp_node=ss;uci set passwall.b.udp_node=tcp
capture;old_snapshot=$snapshot
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
old=$(acl_config a tcp)
python3 - <<'PY'
p='/etc/hosts';lines=open(p).readlines()
with open(p,'w') as f:f.writelines(line for line in lines if not (line.startswith('127.0.0.1 ') and 'multi.bound.test' in line))
PY
status_is 0 passwall_start_bound_acl_nodes "$old_snapshot" b ipv4 4 0 warn
[ "$(acl_config b tcp)" = "$old" ] || fail same-generation-reresolved
status_is 0 passwall_stop_acl_nodes b
capture
[ "$(cat "$snapshot/source.md5")" = "$(cat "$old_snapshot/source.md5")" ] || fail fixture-source-changed
status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
new=$(acl_config b tcp)
[ "$old" != "$new" ] || fail cross-generation-shared
python3 - "$old" "$new" <<'PY'
import json,sys
a=json.load(open(sys.argv[1].replace('config.json','binding.json')))
b=json.load(open(sys.argv[2].replace('config.json','binding.json')))
assert a['endpoint']['address']=='127.0.0.1' and b['endpoint']['address']=='127.0.0.2'
assert a['endpoint']['original_node']['address']==b['endpoint']['original_node']['address']=='multi.bound.test'
assert a['endpoint']['generation']!=b['endpoint']['generation']
PY
# An old generation's identity cannot authorize cleanup of a new process even
# if a stale identity file is presented at the new directory's exact path.
cp "${new%/*}/bound.identity" "$work/new-identity-backup"
cp "${old%/*}/bound.identity" "${new%/*}/bound.identity"
status_is 1 _pw_acl_instance_stop "${new%/*}"
kill -0 "$(pid_for "$new")" || fail stale-identity-killed-new
mv "$work/new-identity-backup" "${new%/*}/bound.identity"
status_is 0 passwall_stop_acl_nodes a
passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail old-generation-cleaned-new
status_is 1 _pw_bound_helper compatible "${new%/*}" "$old_snapshot" ipv4 4
status_is 0 passwall_stop_acl_nodes b
printf '127.0.0.1 multi.bound.test\n' >> /etc/hosts
echo 'PASS real UCI unchanged, immutable per-generation multi-A/AAAA binding, endpoint rotation/new process and old-generation cleanup isolation'

# Literal endpoint needs no DNS. IPv6-only is deliberately narrower than a
# kernel dual-stack listener; callers cannot consume an unpublished family.
uci set passwall.ss.address=127.0.0.1
uci set passwall.settings.tcp_node=ss;uci -q delete passwall.settings.udp_node || :
capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
[ "$(uci get passwall.ss.address)" = 127.0.0.1 ] || fail literal-UCI-mutated
status_is 1 lua "$PW_FW_ENDPOINT_HELPER" "$(global_config TCP)" udp
status_is 0 passwall_stop_global_nodes
uci set passwall.settings.tcp_node=hy;uci set passwall.settings.udp_node=tcp
uci set passwall.hy.protocol=udp;uci set passwall.hy.port=34443
TCP_PROXY_WAY=tproxy;capture
status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv6 6
config=$(global_config TCP)
status_is 0 _pw_bound_helper verify "${config%/*}" 6 tcp
status_is 1 _pw_bound_helper verify "${config%/*}" 4 tcp
port=$(get_cache_var ACL_GLOBAL_TCP_redir_port)
status_is 0 _pw_fw_family_ready "$config" tcp "$port" 6
status_is 1 _pw_fw_family_ready "$config" tcp "$port" 4
status_is 1 _pw_fw_family_ready "$config" tcp "$((port+1))" 6
python3 - "$config" <<'PY'
import json,sys
c=json.load(open(sys.argv[1].replace('config.json','bound.capabilities')))
assert set(c['tcp'])==set(c['udp'])=={'6'}
PY
status_is 0 passwall_stop_global_nodes
capture;status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv6 dual
config=$(global_config TCP);port=$(get_cache_var ACL_GLOBAL_TCP_redir_port)
status_is 0 _pw_fw_family_ready "$config" tcp "$port" 4
status_is 0 _pw_fw_family_ready "$config" tcp "$port" 6
status_is 0 passwall_stop_global_nodes
echo 'PASS literal endpoint and explicit family limits: dual socket never widens IPv6-only published capability'

# The mature SS ACL relay provides two address-family sockets. This is a
# different verified implementation of dual-stack from one V6ONLY=0 socket.
uci set passwall.a.tcp_node=ss;uci set passwall.a.udp_node=tcp;capture
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv6 dual 0 warn
config=$(acl_config a tcp);port=$(get_cache_var ACL_a_tcp_redir_port)
for proto in tcp udp;do
	status_is 0 _pw_fw_family_ready "$config" "$proto" "$port" 4
	status_is 0 _pw_fw_family_ready "$config" "$proto" "$port" 6
done
python3 - "$config" "$port" <<'PY'
import glob,os,sys
pid=open(sys.argv[1].replace('config.json','relay/process')).readline().strip()
owned={os.readlink(fd) for fd in glob.glob('/proc/'+pid+'/fd/*')}
for proto in ('tcp','udp'):
 for suffix in ('','6'):
  rows=[r.split() for r in open('/proc/net/'+proto+suffix).read().splitlines()[1:]]
  assert any(int(r[1].split(':')[1],16)==int(sys.argv[2]) and
             'socket:['+r[9]+']' in owned and r[3]==('0A' if proto=='tcp' else '07') for r in rows)
print('PASS actual SS ACL: distinct owned IPv4/IPv6 TCP/UDP relay sockets, strict dual capability checks')
PY
status_is 0 passwall_stop_acl_nodes a
