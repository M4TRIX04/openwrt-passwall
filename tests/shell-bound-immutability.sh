#!/bin/sh
# Appended to the unchanged native bound fixture; all resources are disposable.
/bin/ash -n "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/acl_nodes.sh"
/bin/ash -n "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/bound_nodes.sh"
/bin/ash -n "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/global_nodes.sh"
/bin/ash -n "$PW_BOUND_REPO/tests/shell-bound-immutability.sh"
luac5.1 -p "$PW_BOUND_HELPER"
uci set passwall.hy.hysteria_lazy_start=1

cat > "$work/seal-fault.lua" <<'LUA'
local nixio = require "nixio"
local open = nixio.open
nixio.open = function(path, ...)
	if path:match("/bound%.capabilities%.new$") then return nil end
	return open(path, ...)
end
require("luci.passwall.runtime_binding").verify(arg[1], true)
LUA
# Trace the real adapter; inject only the requested first-seal failure.
_pw_bound_helper() {
	printf '%s\n' "$*" >> "$work/bound-actions"
	if [ "$1:${PW_SOCKET_FIXTURE:-0}" = prepare:1 ]; then
		shift
		lua "$work/socket-prepare.lua" "$@"
		return
	fi
	case "$1:${PW_IMMUTABLE_FAIL_SEAL:-0}" in seal:1|seal:partial)
		python3 - "$2" "$work/failed-processes" <<'PY'
import hashlib,json,os,sys
d=sys.argv[1]
records=[]
for sub in ('','relay/'):
 p=d+'/'+sub+'process'
 if os.path.exists(p): records.append(open(p).read().splitlines()[:2])
if not records:
 p='/tmp/etc/passwall_hysteria1/'+hashlib.md5((d+'/config.json').encode()).hexdigest()+'.json'
 r=json.load(open(p)); records.append([str(r['pid']),str(r['birth'])])
json.dump(records,open(sys.argv[2],'w'))
PY
		;;
	esac
	[ "$1:${PW_IMMUTABLE_FAIL_SEAL:-0}" != seal:1 ] || return 1
	if [ "$1:${PW_IMMUTABLE_FAIL_SEAL:-0}" = seal:partial ]; then
		lua "$work/seal-fault.lua" "$2"
		return
	fi
	lua "$PW_BOUND_HELPER" "$@"
}
seals() { grep -c '^seal ' "$work/bound-actions" || :; }
publish() {
	local PW_BOUND_SNAPSHOT="$snapshot" PW_BOUND_PREFERENCE=ipv4 PW_BOUND_FAMILY=4
	_pw_acl_publish "$@"
}
publish_global() {
	local PW_BOUND_SNAPSHOT="$snapshot" PW_BOUND_PREFERENCE=ipv4 PW_BOUND_FAMILY=4
	_pw_global_publish "$(sed -n '2p' "$1/meta")" "$(sed -n '3p' "$1/meta")" "$(sed -n '4p' "$1/meta")" "$1"
}
files() {
	python3 - "$1" <<'PY'
import hashlib,json,os,stat,sys
result={}
for name in ('config.json','binding.json','bound.identity','bound.capabilities','socks_port'):
 p=os.path.join(sys.argv[1],name)
 try:
  s=os.lstat(p)
 except FileNotFoundError:
  result[name]=None
  continue
 assert stat.S_ISREG(s.st_mode),p
 result[name]=[hashlib.sha256(open(p,'rb').read()).hexdigest(),s.st_mtime_ns,s.st_ctime_ns,s.st_ino,s.st_dev,s.st_mode,s.st_size]
print(json.dumps(result,sort_keys=True))
PY
}
unchanged() { files "$1" > "$work/after"; cmp "$2" "$work/after" || fail immutable-files-rewritten; }

for core in ss hy; do
	uci set "passwall.a.tcp_node=$core"; uci set passwall.a.udp_node=tcp
	uci set "passwall.b.tcp_node=$core"; uci set passwall.b.udp_node=tcp
	uci set passwall.b.use_global_config=0
	capture
	: > "$work/bound-actions"
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
	config=$(acl_config a tcp); instance=${config%/*}
	[ "$(seals)" = 1 ] && [ -s "$instance/bound.identity" ] && [ -s "$instance/bound.capabilities" ] || fail first-seal-missing
	python3 - "$instance" <<'PY'
import json,sys
for name in ('binding.json','bound.capabilities'):
 assert 'socks_tcp_socket' not in json.load(open(sys.argv[1]+'/'+name))
PY
	files "$instance" > "$work/published"
	status_is 0 publish a "$instance" 1 1 ''
	status_is 0 publish a "$instance" 1 1 ''
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
	[ "$(acl_config b tcp)" = "$config" ] && [ "$(acl_config b udp)" = "$config" ] || fail same-generation-not-shared
	[ "$(seals)" = 1 ] || fail reference-called-seal
	unchanged "$instance" "$work/published"
	# Even an explicit accidental seal is rejected without rewriting records.
	status_is 1 _pw_bound_helper seal "$instance"
	unchanged "$instance" "$work/published"
	echo "PASS $core: first seal once; repeated publish and second ACL preserve SHA256/mtime/ctime/inode"
	count=$(seals)
	for file in config.json binding.json bound.identity bound.capabilities socks_port; do
		cp -p "$instance/$file" "$work/backup"
		for fault in missing changed; do
			if [ "$fault" = missing ]; then
				rm "$instance/$file"
			else
				python3 - "$instance/$file" "$file" <<'PY'
import json,sys
p,name=sys.argv[1:]
if name=='socks_port':
 value=int(open(p).read())+1
 open(p,'w').write(str(value)+'\n')
else:
 c=json.load(open(p))
 if name=='config.json': c['timeout']=12345
 elif name=='binding.json': c['config_md5']='0'*32
 elif name=='bound.identity': c['generation']='generation.tampered'
 else: c={'tcp':{'4':True,'6':True},'udp':{'4':True}}
 open(p,'w').write(json.dumps(c))
PY
			fi
			files "$instance" > "$work/rejected"
			cache_before=$(md5sum "$TMP_PATH/var")
			status_is 1 publish c "$instance" 1 1 ''
			[ -z "$(acl_config c tcp)" ] && [ "$(md5sum "$TMP_PATH/var")" = "$cache_before" ] || fail rejection-published-reference
			[ "$(seals)" = "$count" ] || fail rejection-tried-reseal
			unchanged "$instance" "$work/rejected"
			cp -p "$work/backup" "$instance/$file"
			echo "REJECT $core: $fault $file; rc=1, no publication or file repair"
		done
	done
	# Missing both records must not turn a published instance into a new one.
	mv "$instance/bound.identity" "$work/identity-backup"
	mv "$instance/bound.capabilities" "$work/capabilities-backup"
	files "$instance" > "$work/rejected"
	status_is 1 publish c "$instance" 1 1 ''
	unchanged "$instance" "$work/rejected"
	[ "$(seals)" = "$count" ] || fail missing-seal-recreated
	mv "$work/identity-backup" "$instance/bound.identity"
	mv "$work/capabilities-backup" "$instance/bound.capabilities"
	echo "REJECT $core: both seal records missing; no recreation"
	# A seal changed during the real cache rename must fail the post-publish
	# read-only check and withdraw this attempt, without repairing the record.
	cp -p "$instance/bound.capabilities" "$work/capabilities-backup"
	rm -f "$work/publish-fired"
	mv() {
		command mv "$@" || return 1
		case "$*" in *" $TMP_PATH/var")
			if [ ! -e "$work/publish-fired" ]; then
				touch "$work/publish-fired"
				printf '{}' > "$instance/bound.capabilities"
				files "$instance" > "$work/rejected"
			fi
			;;
		esac
	}
	status_is 1 publish c "$instance" 1 1 ''
	unset -f mv
	[ -e "$work/publish-fired" ] && [ -z "$(acl_config c tcp)$(acl_config c udp)" ] || fail post-check-left-reference
	[ "$(acl_config a tcp)" = "$config" ] && [ "$(acl_config b tcp)" = "$config" ] || fail post-check-removed-other-reference
	unchanged "$instance" "$work/rejected"
	mv "$work/capabilities-backup" "$instance/bound.capabilities"
	echo "REJECT $core: seal changed during publication; rc=1, attempt withdrawn without repair"
	# Compatibility must be checked even with a complete, valid seal.
	files "$instance" > "$work/published"
	PW_BOUND_PREFERENCE=ipv6 PW_BOUND_FAMILY=4 PW_BOUND_SNAPSHOT=$snapshot
	status_is 1 _pw_acl_publish c "$instance" 1 1 ''
	PW_BOUND_PREFERENCE=ipv4 PW_BOUND_FAMILY=6
	status_is 1 _pw_acl_publish c "$instance" 1 1 ''
	PW_BOUND_PREFERENCE= PW_BOUND_FAMILY= PW_BOUND_SNAPSHOT=
	old_snapshot=$snapshot; capture
	status_is 1 publish c "$instance" 1 1 ''
	snapshot=$old_snapshot
	unchanged "$instance" "$work/published"
	[ "$(seals)" = "$count" ] && [ -z "$(acl_config c tcp)" ] || fail incompatible-reference-published
	echo "REJECT $core: preference/family/generation mismatch; rc=1, no reseal"
	status_is 0 passwall_stop_acl_nodes a
	[ -d "$instance" ] && passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail first-release-stopped-shared
	status_is 0 passwall_stop_acl_nodes b
	[ ! -d "$instance" ] || fail last-release-kept-instance
	echo "PASS $core: shared instance survives first release and is reclaimed after last release"
	for fault in 1 partial; do
		PW_IMMUTABLE_FAIL_SEAL=$fault
		status_is 2 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
		PW_IMMUTABLE_FAIL_SEAL=0
		[ -z "$(acl_config a tcp)$(acl_config a udp)" ] || fail failed-seal-published
		[ -z "$(find "$TMP_ACL_PATH/split-acl" -maxdepth 1 -name 'instance.*' -print)" ] || fail failed-seal-leaked-instance
		python3 - "$work/failed-processes" <<'PY'
import json,sys
for pid,birth in json.load(open(sys.argv[1])):
 try: fields=open('/proc/'+pid+'/stat').read().rsplit(') ',1)[1].split()
 except FileNotFoundError: continue
 assert fields[0]=='Z' or fields[19]!=birth,('owned process survived failed seal',pid,birth)
PY
		echo "REJECT $core: first seal failure ($fault); public rc=2, no reference or instance left"
	done
done

for core in ss hy; do
	uci set "passwall.settings.tcp_node=$core"; uci set passwall.settings.udp_node=tcp
	uci set passwall.a.use_global_config=1; uci set passwall.b.use_global_config=1
	capture
	: > "$work/bound-actions"
	status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	config=$(global_config TCP); instance=${config%/*}
	[ "$(seals)" = 1 ] || fail global-first-seal-missing
	files "$instance" > "$work/global-published"
	status_is 0 publish_global "$instance"
	status_is 0 publish_global "$instance"
	[ "$(seals)" = 1 ] || fail global-republish-called-seal
	unchanged "$instance" "$work/global-published"
	python3 - "$instance" <<'PY'
import json,sys
for name in ('binding.json','bound.capabilities'):
 assert 'socks_tcp_socket' not in json.load(open(sys.argv[1]+'/'+name))
PY
	for file in config.json binding.json bound.identity bound.capabilities; do
		cp -p "$instance/$file" "$work/global-backup"
		for fault in missing changed; do
			if [ "$fault" = missing ]; then rm "$instance/$file"
			else printf '{}' > "$instance/$file"; fi
			files "$instance" > "$work/rejected"
			cache_before=$(md5sum "$TMP_PATH/var")
			status_is 1 publish_global "$instance"
			[ "$(md5sum "$TMP_PATH/var")" = "$cache_before" ] && [ "$(seals)" = 1 ] || fail global-rejection-resealed-or-published
			unchanged "$instance" "$work/rejected"
			cp -p "$work/global-backup" "$instance/$file"
			echo "REJECT Global $core: $fault $file before publication; no repair or cache change"
		done
	done
	files "$instance" > "$work/global-published"
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
	status_is 0 passwall_start_bound_acl_nodes "$snapshot" b ipv4 4 0 warn
	[ "$(acl_config a tcp)" = "$config" ] && [ "$(acl_config b udp)" = "$config" ] || fail inherited-wrong-instance
	status_is 0 publish a "$instance" 1 1 1
	[ "$(seals)" = 1 ] || fail inheritance-called-seal
	unchanged "$instance" "$work/global-published"
	cp -p "$instance/bound.capabilities" "$work/capabilities-backup"
	rm -f "$work/publish-fired"
	mv() {
		command mv "$@" || return 1
		case "$*" in *" $TMP_PATH/var")
			if [ ! -e "$work/publish-fired" ]; then
				touch "$work/publish-fired"; printf '{}' > "$instance/bound.capabilities"
				files "$instance" > "$work/rejected"
			fi;;
		esac
	}
	status_is 1 publish_global "$instance"
	unset -f mv
	[ -e "$work/publish-fired" ] && [ -z "$(global_config TCP)$(global_config UDP)" ] || fail global-post-check-left-publication
	[ "$(acl_config a tcp)" = "$config" ] && [ "$(acl_config b udp)" = "$config" ] || fail global-post-check-removed-ACL
	unchanged "$instance" "$work/rejected"
	mv "$work/capabilities-backup" "$instance/bound.capabilities"
	status_is 0 publish_global "$instance"
	[ "$(seals)" = 1 ] || fail global-post-check-resealed
	files "$instance" > "$work/global-published"
	echo "REJECT Global $core: post-publication seal change; exact attempt withdrawn, inherited references retained"
	status_is 0 passwall_stop_acl_nodes a
	status_is 0 passwall_stop_global_nodes
	passwall_acl_node_ready b tcp && passwall_acl_node_ready b udp || fail global-release-stopped-inherited
	unchanged "$instance" "$work/global-published"
	status_is 0 passwall_stop_acl_nodes b
	[ ! -d "$instance" ] || fail inherited-last-release-kept-instance
	echo "PASS $core: Global inherited by two ACLs, no reseal or immutable file changes; last-reference cleanup preserved"
	for fault in 1 partial; do
		PW_IMMUTABLE_FAIL_SEAL=$fault
		status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
		PW_IMMUTABLE_FAIL_SEAL=0
		[ -z "$(global_config TCP)$(global_config UDP)" ] || fail global-failed-seal-published
		[ -z "$(find "$GLOBAL_ACL_PATH/split" -maxdepth 1 -name 'instance.*' -print)" ] || fail global-failed-seal-leaked
		python3 - "$work/failed-processes" <<'PY'
import json,sys
for pid,birth in json.load(open(sys.argv[1])):
 try: fields=open('/proc/'+pid+'/stat').read().rsplit(') ',1)[1].split()
 except FileNotFoundError: continue
 assert fields[0]=='Z' or fields[19]!=birth,('Global process survived failed seal',pid,birth)
PY
		echo "REJECT Global $core: first/partial seal failure ($fault), rc=2; owned process reclaimed"
	done
done
. "$PW_BOUND_REPO/tests/shell-bound-socket.sh"
echo 'SKIP production/device data plane and DNS: outside this isolated immutability regression'
