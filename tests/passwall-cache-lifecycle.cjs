// Production cache, start/global/SOCKS/ACL/stop and nftables functions.
// UCI input, core execution, DNS processes and OS side effects are fixtures.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const Module = require('node:module');
const fixturePath = path.join(__dirname, 'passwall-client-isolation.cjs');
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath; fixture.paths = module.paths;
fixture._compile(fs.readFileSync(fixturePath, 'utf8').split("run('cleanup preserves")[0] +
  '\nmodule.exports={common,func,app};', fixturePath);
const {common, func, app} = fixture.exports;
const utils = fs.readFileSync(path.join(__dirname, '../luci-app-passwall/root/usr/share/passwall/utils.sh'), 'utf8').replace(/\r\n/g, '\n');
const cache = ['shell_quote', 'del_cache_var', 'set_cache_var', 'set_cache_vars', 'get_cache_var', 'eval_cache_var'].map(n => func(utils, n)).join('\n');
const image = process.env.PASSWALL_CACHE_DOCKER;
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
function run(name, code) {
  if (process.env.PASSWALL_CACHE_CASE && !name.includes(process.env.PASSWALL_CACHE_CASE)) return;
  const input = common + '\n' + cache + '\n' + code;
  if (image) cp.execFileSync('docker', ['run', '--rm', '--pull=never', '--network', 'none', '-i', '--entrypoint', '/bin/ash', image], {input, stdio: ['pipe', 'inherit', 'inherit']});
  else cp.execFileSync(bash, ['-s'], {input, stdio: ['pipe', 'inherit', 'inherit']});
  console.log('PASS ' + name + (image ? ' [OpenWrt BusyBox ash]' : ' [Git Bash/bash]'));
}
run('cache API: file authority, local/exported values, child deletion, empty/missing file and isolation', `
cat > "$work/cache-api.sh" <<'CACHE_API'
${cache}
CACHE_API
export TMP_PATH
set_cache_var CACHE_KEEP keep
CACHE_PROBE=inherited;export CACHE_PROBE
[ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'environment used as cache'
set_cache_var CACHE_PROBE stored
CACHE_PROBE=shadow
[ "$(get_cache_var CACHE_PROBE)" = stored ] || fail 'file did not win'
del_cache_var CACHE_PROBE || fail 'delete failed'
[ -z "\${CACHE_PROBE+x}" ] || fail 'exported shell copy retained'
[ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'deleted value returned'
set_cache_var CACHE_PROBE parent
sh -c '. "$1"; del_cache_var CACHE_PROBE' sh "$work/cache-api.sh" || fail 'child delete failed'
[ "$CACHE_PROBE" = parent ] || fail 'child unexpectedly mutated parent shell'
[ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'inherited parent value resurrected'
local_scope() {
  local CACHE_PROBE=local
  [ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'local shadow used as cache'
  set_cache_var CACHE_PROBE persisted
  del_cache_var CACHE_PROBE
  [ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'local value survived deletion'
}
local_scope
set_cache_var CACHE_PROBE_extra similar
set_cache_var CACHE_PROBE ''
del_cache_var CACHE_PROBE;del_cache_var CACHE_PROBE
[ "$(get_cache_var CACHE_PROBE_extra)" = similar ] && [ "$(get_cache_var CACHE_KEEP)" = keep ] || fail 'other keys damaged'
set_cache_var LOCAL_DNS '192.168.1.1#53'
set_cache_var LOCAL_DNS "$LOCAL_DNS"
[ "$LOCAL_DNS" = '192.168.1.1#53' ] && [ "$(get_cache_var LOCAL_DNS)" = "$LOCAL_DNS" ] || fail 'setter shell publication changed'
set_cache_var CACHE_PROBE old
sed() { return 1; }
if del_cache_var CACHE_PROBE;then fail 'I/O error hidden';fi
if set_cache_var CACHE_PROBE new;then fail 'setter ignored failed deletion';fi
unset -f sed
[ "$(get_cache_var CACHE_PROBE)" = old ] || fail 'failed write changed persisted value'
: > "$TMP_PATH/var"
[ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'empty file resurrected value'
rm -f "$TMP_PATH/var"
del_cache_var CACHE_PROBE || fail 'missing-file delete not idempotent'
[ -z "$(get_cache_var CACHE_PROBE)" ] || fail 'missing file resurrected value'
`);

const aliases = ['config_n_get', 'uci'].map(n => func(common, n).replace(n + '()', 'fixture_' + n + '()')).join('\n');
const setup = aliases + '\n' + ['eval_set_val'].map(n => func(utils, n)).join('\n') + '\n' +
  ['run_socks', 'start_global', 'gen_hysteria_config', 'check_hysteria_node', 'start_hysteria', 'start', 'stop', 'start_socks'].map(n => func(app, n)).join('\n') + String.raw`
config_n_get() {
  case "$1:$2" in
    a:mode) echo "$acl_mode";; a:node) echo "$acl_node";; a:dns_mode) echo "$acl_dns";;
    a:use_global_config) echo 0;; old:type) echo Xray;;hy:type) echo Hysteria;;
    good:address|rust:address|hy:address) echo example.com;; good:port|rust:port|hy:port) echo 8388;;
    *) fixture_config_n_get "$@";;
  esac
}
config_get_type() { [ "$1" != missing ] && echo nodes; }
uci() {
  fixture_uci "$@"
  if [ "$1:$2:$3" = '-q:show:passwall.a' ];then
    echo "passwall.a.sources='00:11:22:33:44:55'"
    echo "passwall.a.dns_mode='$acl_dns'"
  fi
}
lua_api() { case "$1" in iprange*) echo false;; ip_or_mac*) echo mac;;esac; }
check_host() { return 0; }
json_init() { json_node=; };json_add_string() { [ "$1" != node ] || json_node=$2; }
json_dump() { printf '{"node":"%s"}' "$json_node"; }
UTIL_HYSTERIA="$work/generator.lua";HYSTERIA_RUNTIME="$work/manager.lua";touch "$HYSTERIA_RUNTIME"
lua() {
  if [ "$1:$2" = "$HYSTERIA_RUNTIME:start" ];then
    echo hysteria-launch >> "$events";[ "$runtime_failure" != hysteria ];return
  fi
  echo '{}'
}
get_config() {
  ENABLED=$global_enabled;ENABLED_DEFAULT_ACL=$global_enabled;ENABLED_ACLS=1;SOCKS_ENABLED=0;NODE=$global_node
  REDIR_PORT=$global_port;REDIRECT_LIST='ss hysteria';TPROXY_LIST='ss hysteria'
  DNS_SHUNT=dnsmasq;DNS_MODE=tcp;GLOBAL_DNSMASQ_PORT=11400
  # Match get_config(): desired state stays in Shell until the endpoint commits.
  set_cache_var ENABLED_ACLS 1
}
start_dns() {
  [ -z "$(get_cache_var ACL_GLOBAL_node)" ] || fail 'global published before DNS completed'
  [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'global success marker published before DNS completed'
  [ -n "$GLOBAL_SOCKS_server" ] || fail 'DNS started without native SOCKS'
  DNS_REDIRECT_PORT=11400;ACL_default_dns_port=11400
}
start_haproxy() { :; };start_crontab() { :; };stop_crontab() { :; };clean_log() { :; };delete_ip2route() { :; }
check_run_environment() { USE_TABLES=fw; }
busybox() { if [ "$active_residue" = 1 ];then active_residue=0;return 0;fi;return 1; }
xargs() { cat >/dev/null;echo process-cleanup >> "$events"; }
logger() { :; };sleep() { :; };sysctl() { return 0; };ulimit() { :; }
mkdir() { local dir;for dir in "$@";do case "$dir" in -p|/tmp/etc|/tmp/log) :;;*) command mkdir -p "$dir";;esac;done; }
printf 'case "$1" in start) load_acl;;stop) echo firewall-stop >> "$events";;esac\n' > "$APP_PATH/fw.sh"
items=a;nft_prerouting_chain=PSW_NAT;acl_mode=1;acl_node=good;acl_dns=dns2socks
global_enabled=0;global_node=good;global_port=1041;runtime_failure=;active_residue=0
reset_state() { command mkdir -p "$TMP_PATH";rm -rf "$TMP_ACL_PATH";command mkdir -p "$TMP_ACL_PATH";: > "$TMP_PATH/var";: > "$events";ENABLED_ACLS=1; }
assert_forwarded() {
  local port=$1 proto
  for proto in tcp udp;do grep "^nft .*ip protocol $proto" "$events" | grep -q ":$port" || fail "$proto port $port missing";done
}
assert_no_old_port() { ! grep '^nft ' "$events" | grep -q ':19999' || fail 'old global port forwarded'; }
`;
// Inject failures at command boundaries; cache/start/ACL/nftables code stays real.
const faults = String.raw`
fault_key=;partial_write=0;fail_temp_cleanup=0;fail_rollback=0
printf() {
  # Fail the success marker, not start()'s initial explicit disabled state.
  if [ "$2" = ENABLED_DEFAULT_ACL ] && [ "$3" = "'0'" ];then command printf "$@";return;fi
  if [ "$1" = '%s=%s\n' ] && { [ "$2" = "$fault_key" ] || { [ "$fail_rollback" = 1 ] && [ "$2" = ACL_a_failed ]; }; };then
    [ "$partial_write" != 1 ] || command printf "%s='unfinished" "$2"
    return 1
  fi
  command printf "$@"
}
sed() {
  if [ "$fail_rollback" = 1 ] && [ "$2" = '/^ACL_a_redir_port=/d' ] && [ "$3" = "$TMP_PATH/var" ];then return 1;fi
  command sed "$@"
}
rm() {
  if [ "$fail_temp_cleanup" = 1 ];then case "$*" in *'/var.'*) return 1;;esac;fi
  if [ "$fail_rollback" = 1 ] && [ "$2" = "$TMP_ACL_PATH/a" ];then return 1;fi
  command rm "$@"
}
seed_other_state() {
  set_cache_vars ACL_keep_redir_port 18888 acl_node_shared_redir_port 17777 s1 good || fail 'seed failed'
  echo alive > "$TMP_ACL_PATH/shared.alive"
}
assert_other_state() {
  [ "$(get_cache_var ACL_keep_redir_port)" = 18888 ] && [ "$(get_cache_var acl_node_shared_redir_port)" = 17777 ] && [ "$(get_cache_var s1)" = good ] || fail 'unrelated cache changed'
  [ -f "$TMP_ACL_PATH/shared.alive" ] || fail 'shared instance damaged'
}
assert_no_global() {
  local key
  for key in ACL_GLOBAL_node ACL_GLOBAL_redir_port ACL_default_dns_port GLOBAL_SOCKS_server;do
    [ -z "$(get_cache_var "$key")" ] || fail "partial global state: $key"
  done
}
assert_global() {
  [ "$(get_cache_var ACL_GLOBAL_node)" = good ] && [ "$(get_cache_var ACL_GLOBAL_redir_port)" = 1041 ] &&
    [ "$(get_cache_var ACL_default_dns_port)" = 11400 ] && [ "$(get_cache_var GLOBAL_SOCKS_server)" = 127.0.0.1:1070 ] || fail 'global cache damaged'
}
`;
run('cache write faults: real mkdir failure, printf/partial append, rename and cleanup failures preserve file and shell', faults + String.raw`
set_cache_vars CACHE_PROBE old CACHE_KEEP keep || fail 'seed failed'
saved_path=$TMP_PATH;touch "$work/not-a-directory";TMP_PATH="$work/not-a-directory/child"
if set_cache_var CACHE_PROBE new;then fail 'mkdir failure hidden';fi
[ "$CACHE_PROBE" = old ] || fail 'mkdir failure updated shell'
TMP_PATH=$saved_path
for scenario in printf partial rename cleanup;do
  fault_key=CACHE_PROBE;partial_write=0;fail_temp_cleanup=0
  case "$scenario" in
    partial) partial_write=1;;
    rename) fault_key=;mv() { return 1; };;
    cleanup) partial_write=1;fail_temp_cleanup=1;;
  esac
  if set_cache_var CACHE_PROBE new;then fail "$scenario failure hidden";fi
  [ "$CACHE_PROBE" = old ] || fail "$scenario failure updated shell"
  [ "$(get_cache_var CACHE_PROBE)" = old ] && [ "$(get_cache_var CACHE_KEEP)" = keep ] || fail "$scenario damaged live cache"
  [ "$scenario" != cleanup ] || ls "$TMP_PATH"/var.* >/dev/null 2>&1 || fail 'temporary cleanup failure not exercised'
  /bin/sh -n "$TMP_PATH/var" || fail 'partial record reached live cache'
  ! grep -q unfinished "$TMP_PATH/var" || fail 'partial append published'
  unset -f mv
done
fault_key=;fail_temp_cleanup=0;partial_write=0
set_cache_var CACHE_PROBE recovered || fail 'retry failed'
[ "$CACHE_PROBE" = recovered ] && [ "$(get_cache_var CACHE_PROBE)" = recovered ] || fail 'retry not persisted'
`);
run('global publication faults: each required field, partial append and failed temporary cleanup block downstream reuse', setup + faults + String.raw`
for fault in ACL_GLOBAL_node ACL_GLOBAL_redir_port ACL_default_dns_port GLOBAL_SOCKS_server enabled cleanup;do
  fault_key=;fail_temp_cleanup=0;partial_write=0
  reset_state;seed_other_state
  global_enabled=1;global_node=good;global_port=1041;acl_node=good;acl_dns=xray
  # Previous-cycle endpoints must be invalidated even when the new publication fails.
  set_cache_vars ACL_GLOBAL_node good ACL_GLOBAL_redir_port 19999 ACL_default_dns_port 19998 GLOBAL_SOCKS_server 127.0.0.1:19997
  fault_key=$fault;partial_write=1
  [ "$fault" != enabled ] || fault_key=ENABLED_DEFAULT_ACL
  [ "$fault" != cleanup ] || { fault_key=ACL_GLOBAL_node;fail_temp_cleanup=1; }
  if start;then fail "$fault global start reported success";fi
  [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'global success marker survived failed publication'
  assert_no_global;assert_other_state
  ! grep '^nft ' "$events" || fail 'firewall consumed failed publication'
  fault_key=;fail_temp_cleanup=0;partial_write=0
  # Try the real consumer again: missing global publication cannot bypass invalid DNS.
  (eval_cache_var;load_acl) || fail 'ordinary invalid ACL should remain isolated'
  [ "$(get_cache_var ACL_a_failed)" = 1 ] && [ -z "$(get_cache_var ACL_a_default)" ] || fail 'failed global inherited'
  ! grep '^nft ' "$events" || fail 'partial global endpoint used by downstream'
done
`);
run('ACL inheritance faults: every field including final default, rollback failures and app/start propagation', setup + faults + String.raw`
for fault in ACL_a_node ACL_a_redir_port ACL_a_dns_port ACL_a_default rollback;do
  fault_key=;fail_rollback=0;partial_write=0
  reset_state;seed_other_state
  set_cache_vars ACL_GLOBAL_node good ACL_GLOBAL_redir_port 1041 ACL_default_dns_port 11400 GLOBAL_SOCKS_server 127.0.0.1:1070
  acl_node=good;acl_dns=xray;acl_mode=1
  # A retry can encounter old per-ACL records: rollback failure must not allow them to forward.
  set_cache_vars ACL_a_node good ACL_a_redir_port 19999 ACL_a_dns_port 19998 ACL_a_default 1
  fault_key=$fault;partial_write=1
  [ "$fault" != rollback ] || { fault_key=ACL_a_default;fail_rollback=1; }
  status=0;load_acl || status=$?
  if [ "$fault" = rollback ];then
    [ "$status" = 1 ] || fail 'unsafe rollback was treated as recoverable'
  else
    [ "$status" = 2 ] || fail 'safe rollback did not retain recoverable failure status'
  fi
  [ -z "$(get_cache_var ACL_a_default)" ] || fail 'inheritance marker published on failure'
  ! grep '^nft ' "$events" || fail 'failed ACL cache used for forwarding'
  assert_global;assert_other_state
  if [ "$fault" != rollback ];then
    for key in node redir_port dns_port;do [ -z "$(get_cache_var ACL_a_$key)" ] || fail 'rollback left ACL publication';done
    [ "$(get_cache_var ACL_a_failed)" = 1 ] && [ ! -d "$TMP_ACL_PATH/a" ] || fail 'failure not recorded/cleaned'
  else
    [ "$(get_cache_var ACL_a_redir_port)" = 19999 ] && [ -d "$TMP_ACL_PATH/a" ] || fail 'rollback failure injection not exercised'
    [ -z "$(get_cache_var ACL_a_failed)" ] || fail 'failure-marker injection not exercised'
    grep -q 'cache cleanup failed' "$events" || fail 'rollback failure not diagnosed'
    if (eval_cache_var;load_acl);then fail 'consumer retry swallowed pending rollback failure';fi
    ! grep '^nft ' "$events" || fail 'consumer retry used residual ACL port'
  fi
done
fault_key=;fail_rollback=0;partial_write=0
reset_state;seed_other_state;global_enabled=1;global_node=good;global_port=1041;acl_dns=xray
fault_key=ACL_a_default
if start;then fail 'app start swallowed ACL publication failure';fi
[ -z "$(get_cache_var ACL_a_default)" ] || fail 'app start left default marker'
! grep '^nft ' "$events" | grep -q 'comment "a"' || fail 'app start forwarded incomplete inheritance'
assert_forwarded 1041
grep -q 'isolated ACL cache publication failures' "$events" || fail 'recoverable failure hidden from service caller'
assert_other_state
fault_key=
start || fail 'healthy start after failure failed'
[ "$(get_cache_var ACL_a_default)" = 1 ] && [ "$(get_cache_var ACL_a_redir_port)" = 1041 ] || fail 'normal inheritance regressed'
assert_forwarded 1041;assert_other_state
`);
run('production get_config: cache errors propagate through start, global enabled marker commits only after DNS', setup +
  func(setup, 'config_n_get').replace('config_n_get()', 'acl_config_n_get()') + '\n' + func(app, 'get_config') + '\n' + faults + String.raw`
config_n_get() {
  case "$1:$2" in
    '@global[0]:enabled') echo 1;;'@global[0]:node') echo good;;'@global[0]:acl_enable') echo 1;;
    *) acl_config_n_get "$@";;
  esac
}
for fault in ENABLED_ACLS GLOBAL_DNSMASQ_CONF GLOBAL_DNSMASQ_CONF_PATH healthy;do
  fault_key=;reset_state;seed_other_state
  fault_key=$fault
  if [ "$fault" = healthy ];then
    start || fail 'production get_config healthy start failed'
    [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 1 ] && [ "$(get_cache_var ACL_a_default)" = 1 ] || fail 'complete global not enabled'
    assert_forwarded 1041
  else
    if start;then fail 'get_config cache failure swallowed by start';fi
    [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'failed config published global enabled'
    assert_no_global
    ! grep -Eq '^process |^nft ' "$events" || fail 'get_config cache failure reached proxy/firewall startup'
  fi
  assert_other_state
done
`);
run('DNS_REDIRECT=0 preserves system dnsmasq cache semantics and allows complete ACL inheritance', setup + String.raw`
reset_state;global_enabled=1;global_node=good;acl_node=good;acl_dns=xray
DNS_REDIRECT=0
start_dns() { ACL_default_dns_port=; }
start || fail 'system DNS mode rejected'
[ -z "$(get_cache_var ACL_default_dns_port)" ] || fail 'system DNS mistaken for a dedicated dnsmasq instance'
[ "$(get_cache_var ACL_a_default)" = 1 ] && [ "$(get_cache_var ACL_a_dns_port)" = 53 ] || fail 'system DNS inheritance incomplete'
assert_forwarded 1041
`);
run('real cache + all seven ACL scenarios and shared-state isolation', setup + String.raw`
for scenario in direct-ss direct-retired direct-missing retired reuse independent-bad independent-good;do
  reset_state;acl_mode=1;acl_node=good;acl_dns=dns2socks
  set_cache_var ACL_keep_redir_port 18888;set_cache_var acl_node_shared_redir_port 17777
  set_cache_var s1 good;echo alive > "$TMP_ACL_PATH/shared.alive"
  case "$scenario" in
    direct-*) acl_mode=0;acl_dns=xray;set_cache_var ACL_GLOBAL_node good;set_cache_var ACL_GLOBAL_redir_port 1041
      case "$scenario" in direct-retired) acl_node=old;;direct-missing) acl_node=missing;;esac
      for key in node redir_port dns_port default fakedns;do set_cache_var "ACL_a_$key" 19999;done;;
    retired) acl_node=old;;
    reuse) set_cache_var ACL_GLOBAL_node good;set_cache_var ACL_GLOBAL_redir_port 1041;set_cache_var ACL_default_dns_port 11400;acl_dns=xray;;
    independent-bad) acl_dns=xray;;
  esac
  load_acl
  case "$scenario" in
    direct-*)
      [ -z "$(get_cache_var ACL_a_failed)" ] || fail 'direct ACL rejected'
      for key in node redir_port dns_port default fakedns;do [ -z "$(get_cache_var "ACL_a_$key")" ] || fail 'direct cache resurrected';done
      for proto in tcp udp;do
        grep "^nft .*ip protocol $proto .*counter return" "$events" | grep -F 'ether saddr {00:11:22:33:44:55}' | grep -v 'dport 53' | grep -q '"a"' || fail 'source exemption absent'
      done
      ! grep -Eq '^process |^ipt2socks |^dns ' "$events" || fail 'unused proxy started'
      [ "$(get_cache_var ACL_GLOBAL_redir_port)" = 1041 ] || fail 'global cache damaged';;
    retired|independent-bad)
      [ "$(get_cache_var ACL_a_failed)" = 1 ] && [ -z "$(get_cache_var ACL_a_redir_port)" ] || fail 'invalid ACL accepted'
      ! grep '^nft ' "$events" || fail 'failed ACL forwarded';;
    reuse)
      [ "$(get_cache_var ACL_a_default)" = 1 ] && [ "$(get_cache_var ACL_a_redir_port)" = 1041 ] || fail 'global not reused'
      ! grep -Eq '^process |^ipt2socks |^dns ' "$events" || fail 'duplicate proxy started'
      assert_forwarded 1041;;
    independent-good)
      port=$(get_cache_var ACL_a_redir_port);[ -n "$port" ] || fail 'independent port missing'
      grep -q '^process .*ss-local' "$events" && grep -q '^ipt2socks ' "$events" && grep -q '^dns ' "$events" || fail 'native SS/bridge/DNS missing'
      assert_forwarded "$port";;
  esac
  [ "$(get_cache_var ACL_keep_redir_port)" = 18888 ] && [ "$(get_cache_var acl_node_shared_redir_port)" = 17777 ] && [ "$(get_cache_var s1)" = good ] || fail 'unrelated cache damaged'
  [ -f "$TMP_ACL_PATH/shared.alive" ] || fail 'shared instance reclaimed'
done
`);
run('real start/global/ACL/nftables: stale cache, disabled/failed/successful global, different node, consecutive starts and restart', setup + String.raw`
for scenario in disabled disabled-invalid-dns ss-preflight-failure hysteria-runtime-failure success different-node;do
  reset_state;global_enabled=1;global_node=good;global_port=1041;runtime_failure=;acl_node=good;acl_dns=dns2socks
  set_cache_var ACL_GLOBAL_node good;set_cache_var ACL_GLOBAL_redir_port 19999
  set_cache_var ACL_default_dns_port 19998;set_cache_var GLOBAL_SOCKS_server 127.0.0.1:19997
  set_cache_var ACL_GLOBAL_failed 1;set_cache_var ACL_keep_redir_port 18888;set_cache_var acl_node_shared_redir_port 17777;set_cache_var s1 good
  case "$scenario" in
    disabled) global_enabled=0;;disabled-invalid-dns) global_enabled=0;acl_dns=xray;;
    ss-preflight-failure) global_node=bad;;
    hysteria-runtime-failure) global_node=hy;runtime_failure=hysteria;;
    success) acl_dns=xray;;different-node) acl_node=rust;;
  esac
  start
  assert_no_old_port
  case "$scenario" in
    disabled-invalid-dns) [ "$(get_cache_var ACL_a_failed)" = 1 ] && [ -z "$(get_cache_var ACL_a_redir_port)" ] || fail 'stale global bypassed DNS rejection';;
    success) [ "$(get_cache_var ACL_a_redir_port)" = 1041 ] && [ "$(get_cache_var ACL_a_default)" = 1 ] || fail 'new global not reused';assert_forwarded 1041;;
    *) port=$(get_cache_var ACL_a_redir_port);[ -n "$port" ] && [ "$port" != 1041 ] && [ -z "$(get_cache_var ACL_a_default)" ] || fail 'independent node inherited global';assert_forwarded "$port";;
  esac
  if [ "$global_enabled" = 0 ] || [ "$scenario" = ss-preflight-failure ] || [ "$scenario" = hysteria-runtime-failure ];then
    for key in ACL_GLOBAL_node ACL_GLOBAL_redir_port ACL_default_dns_port GLOBAL_SOCKS_server;do [ -z "$(get_cache_var "$key")" ] || fail 'old global publication retained';done
  fi
  [ "$(get_cache_var ACL_keep_redir_port)" = 18888 ] && [ "$(get_cache_var acl_node_shared_redir_port)" = 17777 ] && [ "$(get_cache_var s1)" = good ] || fail 'start cleared unrelated cache'
done
# Separate shell invocations share the cache file, matching app.sh service calls.
reset_state;global_enabled=1;global_node=good;global_port=1041;runtime_failure=;acl_node=good;acl_dns=xray
(start) || fail 'first start failed'
[ "$(get_cache_var ACL_a_redir_port)" = 1041 ] || fail 'first global not inherited'
global_port=1042;: > "$events"
(start) || fail 'consecutive start failed'
[ "$(get_cache_var ACL_a_redir_port)" = 1042 ] || fail 'old global port reused'
! grep '^nft ' "$events" | grep -q ':1041' || fail 'previous port forwarded'
global_enabled=0;acl_dns=dns2socks;: > "$events"
(start) || fail 'disabled-global start failed'
[ -z "$(get_cache_var ACL_a_default)" ] || fail 'previous inheritance flag retained'
port=$(get_cache_var ACL_a_redir_port);[ -n "$port" ] && [ "$port" != 1042 ] || fail 'disabled global reused'
assert_forwarded "$port"
(stop) || fail 'explicit stop failed'
[ ! -d "$TMP_PATH" ] || fail 'stop retained runtime directory'
global_enabled=1;global_port=1043;acl_dns=xray;: > "$events"
(start) || fail 'restart failed'
[ "$(get_cache_var ACL_a_redir_port)" = 1043 ] || fail 'restart did not publish new port'
assert_forwarded 1043
active_residue=1;global_port=1044;: > "$events"
(start) || fail 'residue cleanup/start failed'
[ "$(get_cache_var ACL_a_redir_port)" = 1044 ] || fail 'residue restart reused old port'
grep -q '^process-cleanup' "$events" && grep -q '^firewall-stop' "$events" || fail 'existing residue rollback bypassed'
! grep '^nft ' "$events" | grep -q ':1043' || fail 'residue port forwarded'
assert_forwarded 1044
`);

// Execute both production rule builders and their callers. Only command/OS
// boundaries are replaced: no cache, rollback, dispatch or rule body is mocked.
for (const backend of ['nftables', 'iptables']) {
  const fw = fs.readFileSync(path.join(__dirname, '../luci-app-passwall/root/usr/share/passwall', backend + '.sh'), 'utf8').replace(/\r\n/g, '\n');
  const helpers = backend === 'iptables'
    ? ['factor', 'dst', 'comment', 'add_port_rules', 'REDIRECT', 'get_jump_ipt', 'insert_rule_before', 'insert_rule_after']
    : ['factor', 'REDIRECT', 'get_jump_nft'];
  const constants = fw.split('\n').filter(line => /^(NFT[A-Z0-9_]*|IPSET_[A-Z0-9_]*|FAKE_IP|FAKE_IP_6|FWMARK)=/.test(line)).join('\n');
  run(backend + ' mixed ACL publication: real rules, source/ports, safe isolation, unsafe rollback and full startup status', setup + '\n' + constants + '\n' +
    helpers.concat(['load_acl', 'add_firewall_rule']).map(n => func(fw, n)).join('\n') + '\n' +
    func(fw, 'start').replace('start()', 'start_firewall()') + '\n' +
    func(setup, 'config_n_get').replace('config_n_get()', 'acl_config_n_get()') + '\n' +
    func(setup, 'uci').replace('uci()', 'acl_uci()') + '\n' + faults + '\nbackend=' + backend + '\n' + String.raw`
config_n_get() {
  case "$2" in
    use_direct_list|use_proxy_list|use_block_list|use_gfw_list|chn_list) echo 0;;
    *) acl_config_n_get "$@";;
  esac
}
uci() {
  acl_uci "$@"
  if [ "$1:$2" = '-q:show' ];then
    case "$3" in
      passwall.a) echo "passwall.a.sources='00:11:22:33:44:a1'";;
      passwall.b) echo "passwall.b.sources='00:11:22:33:44:b2'";;
      passwall.c) echo "passwall.c.sources='00:11:22:33:44:c3'";;
      *) return;;
    esac
    echo "$3.dns_mode='dns2socks'"
    echo "$3.use_direct_list='0'";echo "$3.use_proxy_list='0'"
    echo "$3.use_block_list='0'";echo "$3.use_gfw_list='0'";echo "$3.chn_list='0'"
  fi
}
printf() {
  if [ "$1" = '%s=%s\n' ] && { [ "$2" = "$fault_key" ] ||
    { { [ "$scenario" = marker ] || [ "$scenario" = unsafe-marker ]; } && [ "$2" = ACL_b_failed ]; }; };then return 1;fi
  command printf "$@"
}
sed() {
  if { [ "$scenario" = rollback-delete ] || [ "$scenario" = unsafe-marker ]; } &&
    [ "$2" = '/^ACL_b_redir_port=/d' ] && [ "$3" = "$TMP_PATH/var" ];then return 1;fi
  command sed "$@"
}
rm() {
  if { [ "$scenario" = rollback-dir ] || [ "$scenario" = unsafe-marker ]; } && [ "$2" = "$TMP_ACL_PATH/b" ];then return 1;fi
  command rm "$@"
}
iptables() { echo "iptables $*" >> "$events"; }
ip6tables() { echo "ip6tables $*" >> "$events"; }
ipt_n='iptables -t nat';ipt_m='iptables -t mangle';ipt_f='iptables -t filter'
ip6t_n='ip6tables -t nat';ip6t_m='ip6tables -t mangle';ip6t_f='ip6tables -t filter'
ipset() { case "$*" in *-R*) cat >/dev/null;;esac;return 0; }
ip() { :; }
gen_nft_tables() { :; };add_script_mwan3() { :; };mwan3_start() { :; };set_tproxy_sysctl() { :; }
gen_lanlist() { :; };gen_lanlist_6() { :; };get_local_ips() { :; };update_wan_sets() { :; }
insert_nftset() { cat >/dev/null; }
filter_vpsip() { :; };filter_haproxy() { :; };filter_vps_addr() { :; };filter_direct_node_list() { :; }
gen_include() { echo include-generated >> "$events"; }
start_crontab() { echo cron-start >> "$events"; }
RULES_PATH="$work/rules";USER_RULES_PATH=$RULES_PATH
mkdir -p "$RULES_PATH"
for file in chnroute chnroute6 direct_ip proxy_ip block_ip;do : > "$RULES_PATH/$file";done
printf 'case "$1" in start) start_firewall;;stop) echo firewall-stop >> "$events";;esac\n' > "$APP_PATH/fw.sh"
forward_rules() {
  if [ "$backend" = nftables ];then grep '^nft ' "$events" | grep -E 'redirect to :|tproxy .*to :';
  else grep -E '^(iptables|ip6tables) ' "$events" | grep -E -- '-j (REDIRECT|TPROXY)';fi
}
route_exists() {
  local source=$1 proto=$2 port=$3 family=$4 protocol='ip protocol' command_name=iptables
  [ "$family" != 6 ] || { protocol='meta l4proto';command_name=ip6tables; }
  if [ "$backend" = nftables ];then
    forward_rules | grep -F "$source" | grep -F "$protocol $proto" | grep -Eq ":$port([[:space:]]|$)"
  else
    forward_rules | grep "^$command_name " | grep -F "$source" | grep -F -- "-p $proto" | grep -Eq -- "--(to-ports|on-port) $port([[:space:]]|$)"
  fi
}
exercise() {
  local entry=$1 selected=$2 way=$3 status=0 expected=0 proto c_port family
  # Disable injection while seeding a previous per-ACL record and unrelated owners.
  scenario=;fault_key=;reset_state;seed_other_state
  items='a b c';acl_mode=1;acl_node=good;b_node=good;c_node=rust;acl_dns=dns2socks
  global_enabled=1;global_node=good;global_port=1041;NODE=good;REDIR_PORT=1041
  DNS_REDIRECT=1;DNS_REDIRECT_PORT=11400;PROXY_IPV6=1;TCP_PROXY_WAY=$way
  USE_DIRECT_LIST=0;USE_PROXY_LIST=0;USE_BLOCK_LIST=0;USE_GFW_LIST=0;CHN_LIST=0
  TCP_PROXY_DROP_PORTS=disable;UDP_PROXY_DROP_PORTS=disable
  nft_prerouting_chain=PSW_NAT;is_tproxy=
  [ "$way" != tproxy ] || { nft_prerouting_chain=PSW_MANGLE;is_tproxy=TPROXY; }
  set_cache_vars ACL_GLOBAL_node good ACL_GLOBAL_redir_port 1041 ACL_default_dns_port 11400 GLOBAL_SOCKS_server 127.0.0.1:1070 ENABLED_DEFAULT_ACL 1
  set_cache_vars ACL_b_node good ACL_b_redir_port 19999 ACL_b_dns_port 19998 ACL_b_default 1
  scenario=$selected
  if [ "$scenario" != healthy ];then fault_key=ACL_b_default;expected=1;fi
  if [ "$scenario" = isolated ];then expected=2;[ "$entry" != app ] || expected=1;fi
  case "$entry" in
    load) load_acl || status=$?;;
    firewall) start_firewall || status=$?;;
    app) start || status=$?;;
  esac
  [ "$status" = "$expected" ] || fail "$backend/$entry/$scenario/$way: status $status expected $expected"
  assert_other_state
  if [ "$scenario" = healthy ] || [ "$scenario" = isolated ];then
    c_port=$(get_cache_var ACL_c_redir_port);[ -n "$c_port" ] || fail 'valid following ACL not initialized'
    for proto in tcp udp;do
      for family in 4 6;do
        route_exists 00:11:22:33:44:a1 "$proto" 1041 "$family" || fail "valid A IPv$family $proto rule lost"
        route_exists 00:11:22:33:44:c3 "$proto" "$c_port" "$family" || fail "valid C IPv$family $proto rule lost"
        route_exists 默认 "$proto" 1041 "$family" || fail "global client IPv$family $proto rule lost"
        if [ "$scenario" = healthy ];then
          route_exists 00:11:22:33:44:b2 "$proto" 1041 "$family" || fail "healthy B IPv$family $proto rule lost"
        fi
      done
    done
    if [ "$scenario" = isolated ];then
      [ "$(get_cache_var ACL_b_failed)" = 1 ] && [ ! -d "$TMP_ACL_PATH/b" ] || fail 'B not isolated'
      for key in node redir_port dns_port default fakedns;do [ -z "$(get_cache_var ACL_b_$key)" ] || fail 'B cache survived';done
      ! forward_rules | grep -q '00:11:22:33:44:b2' || fail 'failed B forwarded'
    fi
    if [ "$entry" != load ];then
      grep -q '^include-generated$' "$events" && grep -q PSW_DIRECT "$events" || fail 'firewall finalization skipped'
    fi
    if [ "$entry" = app ];then
      grep -q '^cron-start$' "$events" || fail 'app finalization skipped'
      ! grep -q '^process-cleanup' "$events" || fail 'isolated error stopped independent instances'
    fi
  else
    ! forward_rules | grep -Eq '00:11:22:33:44:(a1|b2|c3)|默认' || fail 'untrusted ACL state consumed'
    ! grep -q '^include-generated$' "$events" || fail 'unsafe firewall exported as initialized'
    [ -z "$(get_cache_var ACL_b_default)" ] || fail 'unsafe B retained inheritance marker'
    if [ "$scenario" = marker ] || [ "$scenario" = unsafe-marker ];then
      [ -z "$(get_cache_var ACL_b_failed)" ] || fail 'marker failure not exercised'
    fi
    if [ "$scenario" = unsafe-marker ];then
      [ "$(get_cache_var ACL_b_redir_port)" = 19999 ] && [ -d "$TMP_ACL_PATH/b" ] || fail 'unsafe residue failure not exercised'
    fi
  fi
  ! forward_rules | grep -Eq ':19999([[:space:]]|$)|--(to-ports|on-port) 19999([[:space:]]|$)' || fail 'old B port reused'
  [ "$(get_cache_var ACL_GLOBAL_redir_port)" = 1041 ] && [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 1 ] || fail 'valid global state damaged'
  echo "PASS $backend/$entry/$scenario/$way"
}
for way in redirect tproxy;do
  for selected in healthy isolated rollback-delete rollback-dir marker unsafe-marker;do exercise load "$selected" "$way";done
done
for entry in firewall app;do
  for selected in healthy isolated unsafe-marker;do exercise "$entry" "$selected" redirect;done
done
# A global publication failure must return before either backend consumes old ports.
scenario=;fault_key=;reset_state;seed_other_state;PROXY_IPV6=0;items='a b c'
set_cache_vars ACL_GLOBAL_node good ACL_GLOBAL_redir_port 19999 ACL_default_dns_port 19998 GLOBAL_SOCKS_server 127.0.0.1:19997 ENABLED_DEFAULT_ACL 1
fault_key=ACL_GLOBAL_node
status=0;start || status=$?
[ "$status" != 0 ] && [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'global failure reported enabled'
assert_no_global;assert_other_state
! forward_rules | grep . || fail 'global publication failure generated forwarding'
! grep -q '^include-generated$' "$events" || fail 'failed global reached firewall startup'
`);
}
