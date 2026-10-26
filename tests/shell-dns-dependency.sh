#!/bin/sh
# Appended to the existing native bound fixture preamble by the Node runner.
# All writes/fixtures/processes are private to the disposable test container.
PW_DEPENDENCY_HELPER="$PW_BOUND_REPO/luci-app-passwall/luasrc/passwall/dependency_probe.lua"
. "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/dns_dependency.sh"
/bin/ash -n "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/dns_dependency.sh"
/bin/ash -n "$PW_BOUND_REPO/tests/shell-dns-dependency.sh"
luac5.1 -p "$PW_DEPENDENCY_HELPER"
uci set passwall.settings.dns_shunt=dnsmasq
uci set passwall.settings.dns_mode=dns2socks
uci set passwall.settings.remote_dns=1.1.1.1:5353
uci set passwall.settings.dns_cache=0
uci set passwall.a.dns_shunt=dnsmasq
uci set passwall.a.dns_mode=dns2socks
uci set passwall.a.remote_dns='[2001:db8::53]:5353'
uci set passwall.a.dns_cache=1
# Listener-only tests must not require or claim an outer connection. Use H1's
# existing lazy-start option instead of inventing a server/data-plane fixture.
uci set passwall.hy.hysteria_lazy_start=1

# Extend the preamble's fixed-value JSON fixture for F1's nested declaration.
json_init() { request=; json_separator=; }
json_add_string() { request="$request$json_separator\"$1\":\"$2\""; json_separator=,; }
json_add_int() { request="$request$json_separator\"$1\":$2"; json_separator=,; }
json_add_object() { request="$request$json_separator\"$1\":{"; json_separator=; }
json_close_object() { request="$request}"; json_separator=,; }

# Production adapters must not write persistent files or invoke lifecycle APIs.
# Snapshot freshness uses its existing transient check file and removes it.
# A live proxy appends its own connection log while a probe negotiates; that log
# is operational output, not a frozen record. Exclude exactly that file so the
# manifest still covers every config, binding, identity and capability record.
manifest() { find "$TMP_PATH" -type f ! -path '*/socks/node.log' -exec md5sum '{}' \; | sort; }
probe() {
	local expect=$1 reason=$2 before after; shift 2
	before=$(manifest)
	# Any config_n_get call during a dependency query is a live-input defect.
	PW_DEP_TEST_ACTIVE=1
	status_is "$expect" "$@"
	PW_DEP_TEST_ACTIVE=0
	[ ! -e "$work/live-read" ] || fail dependency-read-live-input
	[ "$PW_DNS_DEP_REASON" = "$reason" ] || fail "reason expected $reason got $PW_DNS_DEP_REASON"
	case "$PW_DNS_DEP_JSON" in *secret*|*changed-live*) fail dependency-leaked-credentials ;; esac
	case "$PW_DNS_DEP_STATE" in ''|dep_resolved|dep_validated) ;; *) fail invalid-dependency-state ;; esac
	if [ "$expect" != 0 ]; then
		[ -z "$PW_DNS_DEP_STATE" ] || fail failed-query-retained-public-state
		if [ -n "$PW_DNS_DEP_JSON" ]; then
			printf '%s' "$PW_DNS_DEP_JSON" | EXPECT_REASON="$reason" command lua5.1 -e '
local d=require"cjson".decode(io.read"*a");assert(d.state==nil and d.reason==os.getenv("EXPECT_REASON"))'
		fi
	fi
	after=$(manifest)
	[ "$before" = "$after" ] || fail dependency-mutated-runtime
}
validate() { passwall_validate_dns_dependency "$snapshot" "$@"; }
resolve() { passwall_resolve_dns_dependency "$snapshot" "$@"; }
assert_record() {
	printf '%s' "$PW_DNS_DEP_JSON" | EXPECT_STATE="$1" EXPECT_NODE="$2" EXPECT_SOURCE="${3:-acl}" command lua5.1 -e '
local j=require"cjson";local d=j.decode(io.read"*a")
assert(d.state==os.getenv("EXPECT_STATE") and d.node_id==os.getenv("EXPECT_NODE"));assert(not d.helper_port)
assert(not d.password and not d.original_node and not d.generator_node)
assert(d.reason==nil)
assert(d.socks_addr=="127.0.0.1" and d.socks_port>0)
if os.getenv("EXPECT_SOURCE")=="global" then
 assert(d.remote_dns=="1.1.1.1#5353" and d.dns_cache==0)
else assert(d.remote_dns=="[2001:db8:0:0:0:0:0:53]#5353" and d.dns_cache==1) end
assert(d.state~="dep_ready" and not d.helper_pid and not d.helper_identity)
'
}
# Independent SS ACL, real ss-local + ipt2socks, frozen no-auth negotiation.
capture
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
probe 0 '' resolve acl a ipv4 4
assert_record dep_resolved ss
probe 0 '' validate acl a ipv4 4
assert_record dep_validated ss
echo 'PASS ACL SS TCP: dep_resolved/dep_validated, real SOCKS5 greeting + exact owned listener/connection'

# B1-1: the live core and identity remain valid while ONLY the seal is damaged.
instance=$(acl_config a tcp); instance=${instance%/*}
cp -p "$instance/bound.capabilities" "$work/b1-caps"
for fault in missing invalid empty missing_family extra_field; do
	python3 - "$instance/bound.capabilities" "$fault" <<'PY'
import json,os,sys
p,fault=sys.argv[1:];c=json.load(open(p))
if fault=='missing': os.remove(p)
elif fault=='invalid': open(p,'w').write('invalid JSON')
else:
 if fault=='empty': c={}
 if fault=='missing_family': del c['tcp']['4']
 if fault=='extra_field': c['undeclared']={'4':True}
 json.dump(c,open(p,'w'))
PY
	probe 1 dns_dep_identity resolve acl a ipv4 4
	probe 1 dns_dep_identity validate acl a ipv4 4
	cp -p "$work/b1-caps" "$instance/bound.capabilities"
	probe 0 '' validate acl a ipv4 4
	echo "REJECT B1-1 seal=$fault: rc=1 dns_dep_identity, no public state/writes; restored seal validates"
done
cat > "$work/b1-negotiation-fault.lua" <<'LUA'
local api=require('luci.passwall.api')
local probe=dofile(os.getenv('PW_BOUND_REPO')..'/luci-app-passwall/luasrc/passwall/dependency_probe.lua')
local greeting=probe.probe_socks
probe.probe_socks=function(pid,p)
 greeting(pid,p)
 assert(api.fs.writefile(arg[4]..'/bound.capabilities','{}')==2)
end
local rc,reason,candidate=probe.check(unpack(arg))
assert(rc==1 and reason=='dns_dep_identity' and candidate and not candidate.state)
print(reason);print('');print(api.jsonc.stringify(candidate));os.exit(rc)
LUA
original_helper=$PW_DEPENDENCY_HELPER
PW_DEPENDENCY_HELPER="$work/b1-negotiation-fault.lua"
status_is 1 validate acl a ipv4 4
[ "$PW_DNS_DEP_REASON" = dns_dep_identity ] && [ -z "$PW_DNS_DEP_STATE" ] || fail b1-post-greeting-state
printf '%s' "$PW_DNS_DEP_JSON" | command lua5.1 -e 'local d=require"cjson".decode(io.read"*a");assert(d.state==nil and d.reason=="dns_dep_identity")'
PW_DEPENDENCY_HELPER=$original_helper
cp -p "$work/b1-caps" "$instance/bound.capabilities"
probe 0 '' validate acl a ipv4 4
echo 'REJECT B1-1 seal changed AFTER real greeting: strict post-check clears candidate state; retry succeeds'

# F1 supplies frozen Global SOCKS before a read-only dependency query.
status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
probe 0 '' resolve global GLOBAL ipv4 4
assert_record dep_resolved ss global
probe 0 '' validate global GLOBAL ipv4 4
assert_record dep_validated ss global
printf '%s' "$PW_DNS_DEP_JSON" | command lua5.1 -e '
local d=require"cjson".decode(io.read"*a")
assert(d.socks_config_md5 and #d.socks_config_md5==32 and d.socks_identity_md5 and #d.socks_identity_md5==32)'
echo 'PASS Global SS auxiliary SOCKS: frozen candidate + owned method negotiation; no DNS helper/dep_ready'

# Inherited ACL must not even read its ignored selectors (boundary probe).
status_is 0 passwall_stop_acl_nodes a
uci set passwall.a.use_global_config=1
uci set passwall.a.tcp_node=ignored
uci set passwall.a.udp_node=ignored
capture
status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
eval "$(sed -n '/^_pw_snapshot_option() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/runtime_snapshot.sh" | sed '1s/_pw_snapshot_option/_dep_original_option/')"
_pw_snapshot_option() {
	case "$2:$3" in a:tcp_node|a:udp_node) echo forbidden-selector-read >> "$work/forbidden"; return 1 ;; esac
	_dep_original_option "$@"
}
probe 0 '' validate acl a ipv4 4
assert_record dep_validated ss global
[ ! -e "$work/forbidden" ] || fail inherited-selector-read
eval "$(sed -n '/^_pw_snapshot_option() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/runtime_snapshot.sh")"
echo 'PASS inherited frozen Global SOCKS candidate; ignored ACL selectors never read; no helper/dep_ready'
status_is 0 passwall_stop_acl_nodes a
status_is 0 passwall_stop_global_nodes
# A real failed global TCP start leaves a ready UDP instance. Inheritance must
# report failed TCP intent, not an absent ACL instance, and never probe UDP.
uci set passwall.ss.method=invalid
uci set passwall.settings.udp_node=hy
capture
status_is 2 passwall_start_bound_global_nodes "$snapshot" ipv4 4
status_is 2 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
probe 2 dns_dep_no_tcp validate acl a ipv4 4
passwall_global_node_ready UDP || fail lost-ready-global-UDP
echo 'REJECT inherited global TCP failed with UDP ready: rc=2 dns_dep_no_tcp'
status_is 0 passwall_stop_acl_nodes a
status_is 0 passwall_stop_global_nodes
uci set passwall.ss.method=aes-128-gcm
uci set passwall.settings.udp_node=tcp
uci set passwall.a.use_global_config=0

# UDP-only owns a genuine SOCKS control listener but cannot supply TCP DNS.
uci delete passwall.a.tcp_node
uci set passwall.a.udp_node=ss
capture; status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
probe 2 dns_dep_no_tcp validate acl a ipv4 4
echo 'REJECT UDP-only despite actual native SOCKS: rc=2 dns_dep_no_tcp'
for reserved_mode in local direct; do
	uci set passwall.a.dns_mode="$reserved_mode"
	capture
	probe 2 dns_dep_backend_unsupported validate acl a ipv4 4
done
# Explicit interface reservation is independent of dns_mode and deliberately
# has no candidate state. This does NOT validate a Lite product DNS mode.
probe 0 '' validate acl a ipv4 4 not_applicable
[ -z "$PW_DNS_DEP_STATE" ] || fail reserved-interface-state
printf '%s' "$PW_DNS_DEP_JSON" | command lua5.1 -e '
local d=require"cjson".decode(io.read"*a");assert(d.proxy_required==false and d.applicability=="reserved" and d.state==nil and d.reason==nil)'
echo 'RESERVED not_applicable interface logic verified; SKIP local/direct product mode (B4 decision, no production support claim)'
uci set passwall.a.dns_mode=dns2socks
status_is 0 passwall_stop_acl_nodes a

for selectors in 'ss tcp' 'ss ss' 'ss hy' 'ss close' 'close close' 'close tcp'; do
	set -- $selectors
	if [ "$1" = close ]; then uci -q delete passwall.a.tcp_node || :; else uci set passwall.a.tcp_node="$1"; fi
	if [ "$2" = close ]; then uci -q delete passwall.a.udp_node || :; else uci set passwall.a.udp_node="$2"; fi
	capture
	if [ "$1" = close ]; then probe 2 dns_dep_no_tcp resolve acl a ipv4 4
	else
		status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
		probe 0 '' validate acl a ipv4 4
		assert_record dep_validated ss
		status_is 0 passwall_stop_acl_nodes a
	fi
done
echo 'PASS combined/explicit same/follow/split/TCP-only; REJECT closed and follow-without-TCP'

# Keep one real valid instance for mutation/rejection checks.
uci set passwall.a.tcp_node=ss; uci set passwall.a.udp_node=tcp
capture; status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
config=$(acl_config a tcp); instance=${config%/*}
uci set passwall.ss.password=changed-live-secret
probe 1 dns_dep_stale_generation validate acl a ipv4 4
uci set passwall.ss.password=secret
probe 0 '' validate acl a ipv4 4

# Known-good IPv4 instance cannot satisfy an IPv6/dual request. Keep rc=1
# while identifying capability incompatibility instead of identity spoofing.
probe 1 dns_dep_capability validate acl a ipv4 6
probe 1 dns_dep_capability validate acl a ipv4 dual
echo 'REJECT family mismatch: rc=1 dns_dep_capability, public state cleared'

# Low-level argument probes isolate malformed input from generation changes.
# They call the same CLI, never create helpers, and publish no candidate state.
argument_probe() {
	local output rc=0
	output=$(lua "$PW_DEPENDENCY_HELPER" validate "$snapshot" ss "$instance" "$1" ipv4 4 acl:a dnsmasq dns2socks "$2" "$3" 2>/dev/null) || rc=$?
	PW_DNS_DEP_REASON=$(printf '%s\n' "$output" | sed -n '1p')
	PW_DNS_DEP_STATE=$(printf '%s\n' "$output" | sed -n '2p')
	PW_DNS_DEP_JSON=$(printf '%s\n' "$output" | sed -n '3p')
	return "$rc"
}
actual_port=$(get_cache_var ACL_a_tcp_redir_port)
for invalid_dns in '' 'bad name' 999.999.999.999 '1.1.1.1:0' '1.1.1.1#65536' '[::1' 'http://example.com'; do
	probe 2 dns_dep_argument argument_probe "$actual_port" "$invalid_dns" 1
done
for invalid_port in 0 65536 -1 abc; do
	probe 2 dns_dep_argument argument_probe "$invalid_port" 1.1.1.1 1
done
for invalid_cache in '' 2 true; do
	probe 2 dns_dep_argument argument_probe "$actual_port" 1.1.1.1 "$invalid_cache"
done
probe 1 dns_dep_argument validate acl a invalid 4
echo 'REJECT invalid remote_dns/transparent_port/cache: rc=2 dns_dep_argument; invalid API preference: rc=1 dns_dep_argument'

# Force a failure after the candidate has been assembled, at the existing
# SOCKS probe boundary. Diagnostics must survive, candidate state must not.
cat > "$work/fault-probe.lua" <<'LUA'
local probe=dofile(os.getenv('PW_BOUND_REPO')..'/luci-app-passwall/luasrc/passwall/dependency_probe.lua')
probe.probe_socks=function() error({rc=tonumber(os.getenv('DEP_FAULT_RC')),reason=os.getenv('DEP_FAULT_REASON')},0) end
local rc,reason,candidate=probe.check(unpack(arg))
assert(candidate and not candidate.state and candidate.node_id=='ss' and candidate.instance_dir)
print(reason);print('');print(require'cjson'.encode(candidate));os.exit(rc)
LUA
original_helper=$PW_DEPENDENCY_HELPER
PW_DEPENDENCY_HELPER="$work/fault-probe.lua"
export DEP_FAULT_RC=2 DEP_FAULT_REASON=dns_dep_socks
probe 2 dns_dep_socks validate acl a ipv4 4
export DEP_FAULT_RC=1 DEP_FAULT_REASON=dns_dep_identity
probe 1 dns_dep_identity validate acl a ipv4 4
PW_DEPENDENCY_HELPER=$original_helper
unset DEP_FAULT_RC DEP_FAULT_REASON
probe 0 '' validate acl a ipv4 4
echo 'PASS rc=1/2 clears post-resolution state and preserves diagnostic node/path/reason; subsequent success has no error reason'

# Same configuration, new generation: old instance must not be relabelled.
old_snapshot=$snapshot; capture
probe 1 dns_dep_stale_generation validate acl a ipv4 4
snapshot=$old_snapshot

cp "$instance/bound.identity" "$work/identity.saved"
python3 - "$instance/bound.identity" <<'PY'
import json,sys
p=sys.argv[1];d=json.load(open(p));d['birth']='1';json.dump(d,open(p,'w'))
PY
probe 1 dns_dep_identity validate acl a ipv4 4
cp "$work/identity.saved" "$instance/bound.identity"
cp "$instance/socks_port" "$work/socks.saved"
echo 1 > "$instance/socks_port"
probe 2 dns_dep_socks validate acl a ipv4 4
rm "$instance/socks_port"
probe 2 dns_dep_socks validate acl a ipv4 4
printf 'invalid\n' > "$instance/socks_port"
probe 2 dns_dep_socks validate acl a ipv4 4
cp "$work/socks.saved" "$instance/socks_port"
mv "$instance/bound.identity" "$work/identity.absent"
probe 1 dns_dep_unbound_instance validate acl a ipv4 4
mv "$work/identity.absent" "$instance/bound.identity"
echo 'REJECT stale live input/new generation/wrong birth/tampered/missing/malformed SOCKS port; runtime unchanged by probes'

# Malformed cache and absent cache differ. UDP cache is never a fallback.
saved_port=$(get_cache_var ACL_a_tcp_redir_port)
set_cache_vars ACL_a_tcp_redir_port ''
probe 1 dns_dep_cache_untrusted validate acl a ipv4 4
set_cache_vars ACL_a_tcp_redir_port "$saved_port"
saved_node=$(get_cache_var ACL_a_tcp_node)
set_cache_vars ACL_a_tcp_node '' ACL_a_tcp_redir_port '' ACL_a_tcp_instance ''
probe 2 dns_dep_no_instance validate acl a ipv4 4
set_cache_vars ACL_a_tcp_node "$saved_node" ACL_a_tcp_redir_port "$saved_port" ACL_a_tcp_instance "$config"
set_cache_vars ACL_a_tcp_instance "$TMP_ACL_PATH/split-acl/instance.missing/config.json"
probe 1 dns_dep_no_instance validate acl a ipv4 4
set_cache_vars ACL_a_tcp_instance "$config"
mv "$TMP_PATH/var" "$work/cache.saved"
mkdir "$TMP_PATH/var"
probe 1 dns_dep_cache_untrusted validate acl a ipv4 4
rmdir "$TMP_PATH/var"
: > "$TMP_PATH/var"
probe 1 dns_dep_cache_untrusted validate acl a ipv4 4
rm "$TMP_PATH/var"
probe 2 dns_dep_no_instance validate acl a ipv4 4
mv "$work/cache.saved" "$TMP_PATH/var"
echo 'REJECT missing pointer rc=1/no_instance; missing publication rc=2/no_instance; unreadable-shaped/partial cache rc=1/cache_untrusted; unbound instance rc=1/unbound_instance'

# Unsupported backends rejected before any probe/lifecycle activity.
for combination in dnsmasq:tcp dnsmasq:udp chinadns-ng:dns2socks smartdns:socks; do
	uci set passwall.a.dns_shunt="${combination%:*}"
	uci set passwall.a.dns_mode="${combination#*:}"
	capture
	probe 2 dns_dep_backend_unsupported validate acl a ipv4 4
done
uci set passwall.a.dns_shunt=dnsmasq; uci set passwall.a.dns_mode=dns2socks
status_is 0 passwall_stop_acl_nodes a

# Native protocol-boundary tests use a real owned TCP server. These fixtures
# prove method/ownership rejection, NOT a bound core or proxy data plane.
cat > "$work/method-server.py" <<'PY'
import os,socket,sys,time
os.setgid(9911)
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
open(sys.argv[1],'w').write(str(s.getsockname()[1]))
while True:
 c,_=s.accept()
 with c:
  data=b''
  while len(data)<3:
   part=c.recv(3-len(data))
   if not part: break
   data+=part
  assert data==b'\x05\x01\x00',data
  if sys.argv[2]=='bad': c.sendall(b'\x05\xff')
  elif sys.argv[2]=='http': c.sendall(b'HTTP')
  elif sys.argv[2]=='timeout': time.sleep(3)
  elif sys.argv[2]=='fragment':
   c.sendall(b'\x05');time.sleep(.02);c.sendall(b'\x00')
  else: c.sendall(b'\x05\x00')
  c.settimeout(4)
  try: assert c.recv(1)==b'', 'unexpected SOCKS CONNECT/request'
  except (TimeoutError,ConnectionResetError): pass
PY
cat > "$work/method-probe.lua" <<'LUA'
local probe=dofile(os.getenv('PW_BOUND_REPO')..'/luci-app-passwall/luasrc/passwall/dependency_probe.lua')
local ok,err=pcall(probe.probe_socks,arg[1],tonumber(arg[2]))
if arg[3]=='pass' then assert(ok,tostring(err))
else assert(not ok and type(err)=='table' and err.rc==2 and err.reason=='dns_dep_socks') end
LUA
for response in good fragment bad http timeout; do
	rm -f "$work/method.port"
	python3 "$work/method-server.py" "$work/method.port" "$response" > "$work/method.log" 2>&1 & method_pid=$!
	for attempt in $(seq 1 100); do [ ! -s "$work/method.port" ] || break; sleep .01; done
	method_port=$(cat "$work/method.port")
	case "$response" in good|fragment) expected=pass ;; *) expected=reject ;; esac
	lua "$work/method-probe.lua" "$method_pid" "$method_port" "$expected" || fail "method-$response"
	# Correct greeting from a foreign PID cannot claim this listener.
	lua "$work/method-probe.lua" "$$" "$method_port" reject || fail foreign-listener
	kill "$method_pid"; wait "$method_pid" 2>/dev/null || :
	echo "PASS native SOCKS method=$response expected=$expected; foreign owner rejected"
done

# Hysteria has genuine SOCKS even with unreachable upstream (method only).
# This is NOT a successful outer connection or DNS query.
for transport in udp wechat-video faketcp; do
	uci set passwall.hy.protocol="$transport"
	uci set passwall.a.tcp_node=hy; uci -q delete passwall.a.udp_node || :
	capture; status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
	probe 0 '' validate acl a ipv4 4
	assert_record dep_validated hy
	echo "PASS Hysteria $transport method negotiation/identity only; outer connection NOT verified"
	status_is 0 passwall_stop_acl_nodes a
	# F1 Global H1 binds SOCKS to the same frozen primary identity.
	uci set passwall.settings.tcp_node=hy
	capture; status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
	probe 0 '' resolve global GLOBAL ipv4 4
	assert_record dep_resolved hy global
	probe 0 '' validate global GLOBAL ipv4 4
	assert_record dep_validated hy global
	status_is 0 passwall_stop_global_nodes
	echo "PASS Global Hysteria $transport frozen SOCKS candidate/method only; no outer/DNS/helper/dep_ready"
done

# Both families and dual transparent TCP options use unchanged B3.3-2 verifier.
TCP_PROXY_WAY=tproxy
for core in ss hy; do
	uci set passwall.a.tcp_node="$core"
	for family in 6 dual; do
		capture; status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv6 "$family" 0 warn
		probe 0 '' validate acl a ipv6 "$family"
		echo "PASS $core transparent TCP family=$family + native IPv4 SOCKS"
		status_is 0 passwall_stop_acl_nodes a
	done
done
# Retain the explicit A-format ACL fixture alongside F1 Global coverage.
TCP_PROXY_WAY=redirect
uci set passwall.a.tcp_node=hy; uci set passwall.a.udp_node=tcp; capture
cat > "$work/b1-declared-prepare.lua" <<'LUA'
local api=require('luci.passwall.api');local p=assert(api.jsonc.parse(arg[6]))
p.socks_tcp_socket={address='127.0.0.1',protocol='tcp',family='4',port=tonumber(p.local_socks_port)}
require('luci.passwall.runtime_binding').prepare(arg[1],arg[2],arg[3],arg[4],arg[5],api.jsonc.stringify(p))
LUA
_pw_bound_helper() {
	if [ "$1" = prepare ]; then shift; lua "$work/b1-declared-prepare.lua" "$@"
	else lua "$PW_BOUND_HELPER" "$@"; fi
}
status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
probe 0 '' resolve acl a ipv4 4
probe 0 '' validate acl a ipv4 4
instance=$(acl_config a tcp); instance=${instance%/*}
cp -p "$instance/bound.capabilities" "$work/b1-declared-caps"
python3 - "$instance/bound.capabilities" <<'PY'
import json,sys
p=sys.argv[1];c=json.load(open(p));assert c.pop('socks_tcp_socket')=={'4':True};json.dump(c,open(p,'w'))
PY
probe 1 dns_dep_identity resolve acl a ipv4 4
probe 1 dns_dep_identity validate acl a ipv4 4
cp -p "$work/b1-declared-caps" "$instance/bound.capabilities"
probe 0 '' validate acl a ipv4 4
status_is 0 passwall_stop_acl_nodes a
echo 'PASS B1-1 A-format ACL fixture: strict resolve/validate; legacy ACL and F1 Global candidates covered'
echo 'SKIP helper identity/outer connection/DNS/dnsmasq L1-L3: outside B3.3-3B; no dep_ready'
echo 'PASS read-only probes: per-call runtime manifest unchanged; no helper ports/cache/instance writes'
