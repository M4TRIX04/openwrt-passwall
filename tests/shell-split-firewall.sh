# Production B1/B2/B3.1 helpers and native listener fixtures already loaded.
. /tmp/split_firewall.sh
fail() { echo "FAIL: $*" >&2;cat "$PW_EVENTS" >&2;ps -o pid,ppid,stat,args >&2;exit 1; }
PW_FW_ENDPOINT_HELPER=/tmp/firewall_endpoint.lua
export PW_FW_KERNEL="$work/firewall.json"
cp "$work/bin/iptables" "$work/bin/faketcp-iptables"
for command_name in nft iptables ip6tables iptables-restore ip6tables-restore; do
	cat > "$work/bin/$command_name" <<'SH'
#!/bin/sh
case " $* " in *' -t filter '*) exec "$(dirname "$0")/faketcp-iptables" "$@" ;; esac
exec lua5.1 /tmp/firewall-fixture.lua "${0##*/}" "$@"
SH
	chmod +x "$work/bin/$command_name"
done
# ip6tables was a symlink in the fixture: make sure both names dispatch correctly.
rm -f "$work/bin/ip6tables"
cp "$work/bin/iptables" "$work/bin/ip6tables"
get_host_ip() { case "$1:$2" in ipv4:example.test) echo 192.0.2.10;; ipv6:example.test) echo 2001:db8::10;; *) return 1;; esac; }
acl_base=12001
get_new_port() { if [ "$1" = 11200 ];then shift;fixture_get_new_port "$acl_base" "$@";else fixture_get_new_port "$@";fi; }
policy() { passwall_fw_policy "$1" "$2" disable disable disable disable 1:65535 1:65535 0 0 0 0 0 proxy proxy psw_black psw_black6 psw_gfw; }
begin_fw() {
	passwall_fw_begin "$backend" "$TCP_PROXY_WAY" "$PROXY_IPV6" || fail 'begin'
	dir=$PW_FW_DIR
	policy "$dir" global || fail 'global policy'
}
finish_fw() { passwall_fw_seal "$dir" || fail 'seal';passwall_fw_apply "$dir" || fail 'apply'; }
dump_fw() { command lua5.1 /tmp/firewall-fixture.lua dump "$1" "$dir"; }
discard_fw() {
	passwall_fw_discard "$dir" || fail 'discard'
	passwall_fw_discard "$dir" || fail 'idempotent discard'
	command lua5.1 - "$PW_FW_KERNEL" "$dir/context" <<'LUA'
local f=assert(io.open(arg[1]));local c=require('cjson').decode(f:read('*a')).chains
f=assert(io.open(arg[2]));local ctx=f:read('*a');local token=ctx:match('[^\n]+\n[^\n]+\n[^\n]+\n([^\n]+)')
for k in pairs(c) do assert(not k:find('/'..token),'owned chains leaked: '..k) end
assert(c['4/mangle/PSW_DNS'][1]=='KEEP DNS SRV KMS')
assert(c['4/nat/PSW'][1]=='KEEP LEGACY')
LUA
}
for backend in nft iptables; do
	command lua5.1 /tmp/firewall-fixture.lua reset
	TCP_PROXY_WAY=tproxy;PROXY_IPV6=0
	# Every requested state runs real startup/cache/ready checks, not a synthetic
	# endpoint map. Failed nodes are real generator failures, safely reclaimed.
	for tcp_state in closed ready failed; do
		for udp_state in closed ready failed; do
			tcp=;udp=
			case "$tcp_state" in ready) tcp=ss1;;failed) tcp=ssbad;;esac
			case "$udp_state" in ready) udp=hy1;;failed) udp=hybad;;esac
			code=0;passwall_start_global_nodes "$tcp" "$udp" || code=$?
			[ "$code" != 1 ] || fail 'unexpected hard global failure'
			begin_fw
			passwall_fw_global "$dir" "$code" "$tcp" "$udp" 1 1 || fail 'global matrix'
			finish_fw;dump_fw "state-$tcp_state-$udp_state";discard_fw
		done
	done
	for pair in 'ss1 tcp' 'ss1 ss1' 'hy1 tcp' 'hy1 hy1' 'ss1 ss2' 'hy1 hy2' 'ss1 hy1' 'hy1 ss1'; do
		set -- $pair
		passwall_start_global_nodes "$1" "$2" || fail 'combo startup'
		gt=$PW_NODE_TCP;gu=$PW_NODE_UDP
		begin_fw;passwall_fw_global "$dir" 0 "$gt" "$gu" 1 1 || fail 'combo render'
		finish_fw;dump_fw "combo-$1-$2";discard_fw
	done
	for TCP_PROXY_WAY in redirect tproxy; do
		# Hysteria + IPv6 redirect is deliberately invalid; IPv4 global Hysteria
		# is native REDIRECT, whereas IPv6 runs in the separate TPROXY iteration.
		PROXY_IPV6=0
		passwall_start_global_nodes hyfake ss2 || fail 'mixed global'
		acl_base=12001;acl_start a ss1 '' || fail 'ACL A'
		acl_base=12002;status_is 2 acl_start b ssbad ss1
		acl_base=12003;acl_start c hy1 tcp || fail 'ACL C'
		status_is 0 passwall_start_acl_nodes d 0 0 retired missing 0 warn
		begin_fw
		for sid in a b c d;do policy "$dir" "$sid" || fail 'ACL policy';done
		passwall_fw_acl "$dir" a 1 1 0 ss1 '' ip:10.1.0.2 || fail 'A render'
		passwall_fw_acl "$dir" b 1 1 2 ssbad ss1 ip:10.1.0.3 || fail 'B isolation render'
		passwall_fw_acl "$dir" c 1 1 0 hy1 hy1 ip:10.1.0.4 || fail 'C render'
		passwall_fw_acl "$dir" d 1 0 0 retired missing ip:10.1.0.5 || fail 'mode0 render'
		passwall_fw_acl "$dir" disabled 0 invalid 1 retired missing ip:10.1.0.6 || fail 'disabled not skipped'
		passwall_fw_global "$dir" 0 hyfake ss2 1 1 || fail 'mixed default render'
		finish_fw;dump_fw mixed;discard_fw
		for sid in a b c d;do acl_stop "$sid";done
	done
	# Global inheritance is capability-based; missing global UDP stays failed.
	passwall_start_global_nodes ss1 '' || fail 'inherit global'
	status_is 0 passwall_start_acl_nodes a 1 1 ignored ignored 0 warn
	begin_fw;policy "$dir" a
	passwall_fw_acl "$dir" a 1 1 0 ss1 hybad ip:10.1.0.2 || fail 'inherit partial'
	passwall_fw_global "$dir" 0 ss1 '' 1 0 || fail 'inherit default'
	finish_fw;dump_fw inherit;discard_fw;acl_stop a
	# Router-only proxying must not accidentally enable the default LAN client.
	TCP_PROXY_WAY=tproxy;PROXY_IPV6=0
	passwall_start_global_nodes ss1 hy1 || fail 'router-only globals'
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 0 1 || fail 'router-only render'
	finish_fw;dump_fw router-only;discard_fw
	# Policy order is exercised in both TCP REDIRECT and TPROXY. Separate sets
	# are fixtures; actual emitted rules determine decisions in the host evaluator.
	for TCP_PROXY_WAY in redirect tproxy;do
		PROXY_IPV6=0;passwall_start_global_nodes ss1 hy1 || fail 'policy global'
		begin_fw
		passwall_fw_policy "$dir" global 22 22 443 443 80,443 80,443 1 1 1 1 direct disable disable psw_black psw_black6 psw_gfw || fail 'policy snapshot'
		passwall_fw_global "$dir" 0 ss1 hy1 1 1 || fail 'policy render'
		finish_fw;dump_fw policy;discard_fw
	done
	TCP_PROXY_WAY=tproxy;PROXY_IPV6=1
	passwall_start_global_nodes ss1 hy1 || fail 'source global'
	begin_fw
	for sid in mac set range v6;do policy "$dir" "$sid";done
	passwall_fw_acl "$dir" mac 1 0 0 old missing mac:00:11:22:33:44:55 br-lan || fail 'MAC/interface'
	passwall_fw_acl "$dir" set 1 0 0 old missing set:devices || fail 'source set'
	passwall_fw_acl "$dir" range 1 0 0 old missing iprange:10.2.0.1-10.2.0.9 || fail 'source range'
	passwall_fw_acl "$dir" v6 1 0 0 old missing ip:2001:db8:1::2 || fail 'IPv6 source'
	passwall_fw_global "$dir" 0 ss1 hy1 1 0 || fail 'source default'
	finish_fw;dump_fw sources;discard_fw
	# The fixture intentionally sets IPV6_V6ONLY on Hysteria's [::] sockets.
	# Exact family ownership must win over a generic ready result or a UCI flag.
	acl_base=12001;acl_start a ss1 tcp || fail 'dual-family SS ACL'
	acl_base=12002;acl_start b hy1 tcp || fail 'IPv6 Hysteria ACL'
	begin_fw;policy "$dir" a;policy "$dir" b
	passwall_fw_acl "$dir" a 1 1 0 ss1 ss1 ip:10.1.0.2 || fail 'family ACL4'
	passwall_fw_acl "$dir" a 1 1 0 ss1 ss1 ip:2001:db8:1::2 || fail 'family ACL6'
	passwall_fw_acl "$dir" b 1 1 0 hy1 hy1 ip:10.1.0.3 || fail 'Hysteria family ACL4'
	passwall_fw_acl "$dir" b 1 1 0 hy1 hy1 ip:2001:db8:1::3 || fail 'Hysteria family ACL6'
	passwall_fw_global "$dir" 0 ss1 hy1 1 0 || fail 'family globals'
	finish_fw;dump_fw families;discard_fw;acl_stop a;acl_stop b
	# Outer transport endpoints, including IPv6 with IPv4 business listeners,
	# come from instance JSON. No domain is passed to nft/xtables.
	command lua5.1 - "$PW_TEST_NODES" <<'LUA'
local p=arg[1];local f=assert(io.open(p));local j=require('cjson');local n=j.decode(f:read('*a'));f:close()
n.ss6=j.decode(j.encode(n.ss1));n.ss6.address='2001:db8::123'
n.ssdns=j.decode(j.encode(n.ss1));n.ssdns.address='example.test'
f=assert(io.open(p,'w'));f:write(j.encode(n));f:close()
LUA
	PROXY_IPV6=0
	for node in ss6 ssdns hyvideo;do
		passwall_start_global_nodes "$node" '' || fail 'outer endpoint global'
		begin_fw
		if [ "$node" = ssdns ]; then
			if passwall_fw_global "$dir" 0 "$node" '' 1 1;then fail 'unbound domain lookup accepted';fi
			if passwall_fw_seal "$dir";then fail 'unbound domain candidate sealed';fi
			continue
		fi
		passwall_fw_global "$dir" 0 "$node" '' 1 1 || fail 'outer endpoint rules'
		finish_fw;dump_fw "remote-$node";discard_fw
	done
	# An OUTPUT failed protocol can coincide with the valid core's *outer*
	# transport. Tuple-only exemptions cannot safely classify the local socket.
	for pair in 'hy1 ssbad' 'ssbad hyfake';do
		set -- $pair
		status_is 2 passwall_start_global_nodes "$1" "$2"
		gt=$PW_NODE_TCP;gu=$PW_NODE_UDP
		begin_fw;passwall_fw_global "$dir" 2 "$gt" "$gu" 1 1 || fail 'OUTPUT conflict preparation'
		if passwall_fw_seal "$dir";then fail 'OUTPUT conflict silently accepted';fi
		[ ! -e "$dir/pending" ] || fail 'OUTPUT conflict changed firewall'
		# LAN-only remains expressible; no local OUTPUT proxy is requested.
		begin_fw;passwall_fw_global "$dir" 2 "$gt" "$gu" 1 0 || fail 'LAN-only conflict case'
		finish_fw;dump_fw "outer-conflict-$1-$2";discard_fw
	done
	# DNS dependencies do not borrow the opposite transparent protocol or treat
	# ss-redir as a native SOCKS listener. Local DNS is outside this compiler.
	passwall_start_global_nodes ss1 '' || fail 'DNS dependency global'
	begin_fw;passwall_fw_check_dns "$dir" global GLOBAL tcp ss1 || fail 'TCP DNS capability'
	passwall_fw_check_dns "$dir" global GLOBAL local '' || fail 'local DNS'
	passwall_fw_global "$dir" 0 ss1 '' 1 0;finish_fw;discard_fw
	for via in udp socks;do
		begin_fw
		if passwall_fw_check_dns "$dir" global GLOBAL "$via" ss1;then fail 'missing DNS/SOCKS dependency accepted';fi
		if passwall_fw_global "$dir" 0 ss1 '' 1 1;then fail 'missing dependency candidate reused';fi
	done
	acl_start a '' ss1 || fail 'UDP-only ACL DNS fixture'
	begin_fw;passwall_fw_check_dns "$dir" acl a socks ss1 || fail 'native ACL SOCKS TCP control not recognized'
	acl_stop a
	# A complete but dead capability is never a stale forwarding endpoint.
	passwall_start_global_nodes ss1 '' || fail 'configuration snapshot fixture'
	for digest_fault in command output;do
		begin_fw
		if [ "$digest_fault" = command ];then md5sum() { return 1; }
		else md5sum() { echo invalid-digest; };fi
		status_is 1 passwall_fw_global "$dir" 0 ss1 '' 1 1
		unset -f md5sum
		status_is 1 passwall_fw_seal "$dir"
		[ ! -e "$dir/pending" ] || fail 'digest error touched firewall'
	done
	config_path=$(get_cache_var ACL_GLOBAL_TCP_instance)
	cp "$config_path" "$work/original-config.json"
	for timing in before_seal after_seal;do
		begin_fw;passwall_fw_global "$dir" 0 ss1 '' 1 1
		[ "$timing" != after_seal ] || passwall_fw_seal "$dir"
		command lua5.1 - "$config_path" <<'LUA'
local f=assert(io.open(arg[1]));local j=require('cjson');local c=j.decode(f:read('*a'));f:close()
c.server='192.0.2.99';f=assert(io.open(arg[1],'w'));f:write(j.encode(c));f:close()
LUA
		if [ "$timing" = before_seal ];then status_is 1 passwall_fw_seal "$dir"
		else status_is 1 passwall_fw_apply "$dir";fi
		[ ! -e "$dir/pending" ] || fail 'changed config touched firewall'
		cp "$work/original-config.json" "$config_path"
	done
	begin_fw;passwall_fw_global "$dir" 0 ss1 '' 1 1
	: > "$dir/checks"
	status_is 1 passwall_fw_seal "$dir"
	passwall_start_global_nodes ss1 hy1 || fail 'fresh global'
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1 || fail 'live render'
	kill "$(instance_pid "$(get_cache_var ACL_GLOBAL_TCP_instance)")"
	if passwall_fw_seal "$dir";then fail 'dead listener sealed';fi
	[ ! -e "$dir/installed" ] || fail 'dead listener installed'
	# Query error, partial tuple, or hard init error invalidates the candidate.
	for fault in partial query hard;do
		passwall_start_global_nodes ss1 '' || fail 'fresh error global'
		acl_base=12001;acl_start a ss1 '' || fail 'error ACL'
		begin_fw;policy "$dir" a
		case "$fault" in
			partial) set_cache_vars ACL_a_tcp_redir_port '';;
			query) get_cache_var() { return 1; };;
		esac
		status=0;[ "$fault" != hard ] || status=1
		if passwall_fw_acl "$dir" a 1 1 "$status" ss1 '' ip:10.1.0.2;then fail "$fault accepted";fi
		[ "$fault" != query ] || unset -f get_cache_var
		# Reload the actual helper after the injected command error.
		[ "$fault" != query ] || . /tmp/fw-cache-get.sh
		if passwall_fw_global "$dir" 0 ss1 '' 1 1;then fail 'poisoned candidate reused';fi
		if passwall_fw_apply "$dir";then fail 'unsealed candidate applied';fi
		acl_stop a
	done
	passwall_start_global_nodes ss1 '' || fail 'global partial fixture'
	begin_fw;set_cache_vars ACL_GLOBAL_TCP_redir_port ''
	if passwall_fw_global "$dir" 0 ss1 '' 1 1;then fail 'partial global tuple accepted';fi
	begin_fw
	if passwall_fw_global "$dir" 1 ss1 '' 1 1;then fail 'hard global init accepted';fi
	passwall_start_global_nodes ss1 '' || fail 'collision global'
	begin_fw;passwall_fw_global "$dir" 0 ss1 '' 1 1;passwall_fw_seal "$dir"
	# Even a randomly colliding name remains externally owned until this module
	# has checked absence and persisted pending; discard must leave it alone.
	command lua5.1 - "$PW_FW_KERNEL" "$dir/context" <<'LUA'
local j=require('cjson');local f=assert(io.open(arg[1]));local s=j.decode(f:read('*a'));f:close()
f=assert(io.open(arg[2]));local token=f:read('*a'):match('[^\n]+\n[^\n]+\n[^\n]+\n([^\n]+)');f:close()
s.chains['4/mangle/'..token..'P4']={'EXTERNAL COLLISION'}
f=assert(io.open(arg[1],'w'));f:write(j.encode(s));f:close()
LUA
	status_is 1 passwall_fw_apply "$dir"
	[ ! -e "$dir/pending" ] || fail 'external collision claimed'
	passwall_fw_discard "$dir" || fail 'unowned discard'
	command lua5.1 - "$PW_FW_KERNEL" "$dir/context" <<'LUA'
local j=require('cjson');local f=assert(io.open(arg[1]));local s=j.decode(f:read('*a'));f:close()
f=assert(io.open(arg[2]));local token=f:read('*a'):match('[^\n]+\n[^\n]+\n[^\n]+\n([^\n]+)');f:close()
local k='4/mangle/'..token..'P4';assert(s.chains[k][1]=='EXTERNAL COLLISION');s.chains[k]=nil
f=assert(io.open(arg[1],'w'));f:write(j.encode(s));f:close()
LUA
	# Stale old single-node ports never replace the requested failed capability.
	status_is 2 passwall_start_global_nodes ssbad ''
	set_cache_vars ACL_GLOBAL_redir_port 19999 ACL_GLOBAL_node legacy
	begin_fw;passwall_fw_global "$dir" 2 ssbad '' 1 1 || fail 'stale global'
	finish_fw;dump_fw state-failed-closed;discard_fw
	# Partial command application, rollback failure, retry, query uncertainty.
	passwall_start_global_nodes ss1 hy1 || fail 'failure global'
	PROXY_IPV6=1
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1;finish_fw
	other_generation=$dir
	# Normal atomic boundaries differ: nft rolls back this whole batch;
	# restore may have committed mangle when the next nat batch is rejected.
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1;passwall_fw_seal "$dir"
	if [ "$backend" = nft ];then echo 3 > "$PW_FW_KERNEL.apply"
	else echo $(( $(wc -l < "$dir/4.mangle.batch") + 3 )) > "$PW_FW_KERNEL.apply";fi
	: > "$PW_FW_KERNEL.audit"
	status_is 2 passwall_fw_apply "$dir"
	if [ "$backend" = nft ];then
		if grep -Eq 'flush chain| -F ' "$PW_FW_KERNEL.audit";then fail 'atomic nft rejection left chains';fi
	else grep -q ' -F ' "$PW_FW_KERNEL.audit" || fail 'earlier restore table was not rolled back';fi
	rm -f "$PW_FW_KERNEL.apply";discard_fw
	for rollback in success failure query;do
		begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1 || fail 'failure render'
		passwall_fw_seal "$dir" || fail 'failure seal'
		echo 4 > "$PW_FW_KERNEL.apply"
		touch "$PW_FW_KERNEL.partial"
		if [ "$rollback" = failure ];then echo 1 > "$PW_FW_KERNEL.delete";fi
		# Inject inventory failure only after first application has begun.
		if [ "$rollback" = query ];then echo 4 > "$PW_FW_KERNEL.query";fi
		code=0;passwall_fw_apply "$dir" || code=$?
		if [ "$rollback" = success ];then [ "$code" = 2 ] || fail 'safe rollback category'
		else [ "$code" = 1 ] && [ -e "$dir/pending" ] || fail 'hard rollback category';fi
		[ ! -e "$dir/installed" ] || fail 'partial generation marked installed'
		rm -f "$PW_FW_KERNEL.apply" "$PW_FW_KERNEL.delete" "$PW_FW_KERNEL.query" "$PW_FW_KERNEL.partial"
		discard_fw
		command lua5.1 /tmp/firewall-fixture.lua dump other "$other_generation"
	done
	dir=$other_generation
	rm() { case "$*" in *"$dir/installed"*) return 1;;*) command rm "$@";;esac; }
	status_is 1 passwall_fw_discard "$dir"
	[ -e "$dir/pending" ] && [ -e "$dir/installed" ] || fail 'receipt deletion failure lost ownership'
	unset -f rm
	discard_fw
	# Listener death after kernel-command success causes rollback, not publication.
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1;passwall_fw_seal "$dir"
	instance_pid "$(get_cache_var ACL_GLOBAL_TCP_instance)" > "$PW_FW_KERNEL.kill"
	status_is 2 passwall_fw_apply "$dir"
	[ ! -e "$dir/installed" ] || fail 'post-apply crash published'
	discard_fw
	PROXY_IPV6=0;passwall_start_global_nodes ss1 hy1 || fail 'recovered global'
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1;passwall_fw_seal "$dir"
	touch() { case "$*" in *"$dir/installed"*) command touch "$@";return 1;;*) command touch "$@";;esac; }
	status_is 2 passwall_fw_apply "$dir"
	unset -f touch
	[ ! -e "$dir/installed" ] && [ ! -e "$dir/pending" ] || fail 'failed receipt left success state'
	discard_fw
	# Build writes fail before a command can install any candidate rules.
	begin_fw;policy "$dir" a
	printf() { return 1; }
	if passwall_fw_acl "$dir" a 1 0 0 '' '' any;then fail 'write failure hidden';fi
	unset -f printf
	if passwall_fw_global "$dir" 0 ss1 hy1 1 1;then fail 'failed append reused';fi
	# A clean retry is a new private generation; old/other instances are untouched.
	begin_fw;passwall_fw_global "$dir" 0 ss1 hy1 1 1 || fail 'retry render'
	finish_fw;status_is 1 passwall_fw_apply "$dir";dump_fw retry
	# Simulate an external flush after installation: the receipt must not turn
	# a repeated apply into current-success evidence.
	command lua5.1 - "$PW_FW_KERNEL" "$dir/context" <<'LUA'
local j=require('cjson');local f=assert(io.open(arg[1]));local s=j.decode(f:read('*a'));f:close()
f=assert(io.open(arg[2]));local token=f:read('*a'):match('[^\n]+\n[^\n]+\n[^\n]+\n([^\n]+)');f:close()
s.chains['4/mangle/'..token..'P4']=nil
f=assert(io.open(arg[1],'w'));f:write(j.encode(s));f:close()
LUA
	status_is 1 passwall_fw_apply "$dir"
	rm() { case "$*" in *"$dir/pending"*) return 1;;*) command rm "$@";;esac; }
	status_is 1 passwall_fw_discard "$dir"
	[ ! -e "$dir/installed" ] && [ -e "$dir/pending" ] || fail 'pending cleanup failure hidden'
	status_is 1 passwall_fw_apply "$dir"
	unset -f rm
	discard_fw
	passwall_stop_global_nodes || fail 'global cleanup'
done
echo 'PASS B3.2 ash lifecycle: real startup/capabilities, mixed ACL isolation, partial rules, rollback failure/query failure/retry and untouched legacy DNS'
