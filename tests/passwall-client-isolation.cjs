// Runs production app.sh/ nftables.sh functions; only OS/core commands are stubbed.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const app = fs.readFileSync(path.join(__dirname, '../luci-app-passwall/root/usr/share/passwall/app.sh'), 'utf8').replace(/\r\n/g, '\n');
const nft = fs.readFileSync(path.join(__dirname, '../luci-app-passwall/root/usr/share/passwall/nftables.sh'), 'utf8').replace(/\r\n/g, '\n');
function func(text, name) {
  const start = text.indexOf('\n' + name + '() {') + 1;
  if (!start) throw Error('Missing ' + name);
  const end = text.slice(start).search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);
  return end < 0 ? text.slice(start) : text.slice(start, start + end);
}
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const common = `
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
CONFIG=passwall; TMP_PATH="$work/runtime"; TMP_PATH2="$work/cache"; TMP_ACL_PATH="$TMP_PATH/acl"
TMP_BIN_PATH="$TMP_PATH/bin"; TMP_SCRIPT_FUNC_PATH="$TMP_PATH/scripts"; TMP_ROUTE_PATH="$TMP_PATH/routes"
GLOBAL_ACL_PATH="$TMP_ACL_PATH/default"; APP_PATH="$work/app"; LOCK_PATH="$work/locks"
mkdir -p "$TMP_ACL_PATH" "$TMP_PATH2" "$APP_PATH" "$LOCK_PATH"
printf '#!/bin/sh\nexit 0\n' > "$APP_PATH/lease2hosts.sh"; chmod +x "$APP_PATH/lease2hosts.sh"
events="$work/events"; : > "$events"
fail() { echo "FAIL: $*" >&2; cat "$events" >&2; exit 1; }
echolog() { echo "log $*" >> "$events"; }
set_cache_var() { printf '%s' "$2" > "$TMP_PATH/key_$1"; eval "$1=\$2"; }
set_cache_vars() { while [ "$#" -gt 0 ]; do set_cache_var "$1" "$2" || return 1; shift 2; done; }
get_cache_var() { cat "$TMP_PATH/key_$1" 2>/dev/null; }
del_cache_var() { rm -f "$TMP_PATH/key_$1"; }
config_n_get() {
  case "$1:$2" in
    bad:type|late:type|good:type) echo SS;;
    retired:type) echo Hysteria2;;
    rust:type) echo SS-Rust;; ssr:type) echo SSR;; hy:type) echo SS-Rust;;
    a:enabled|b:enabled|c:enabled|d:enabled|e:enabled) echo 1;;
    a:mode|b:mode|c:mode|d:mode|e:mode) echo 1;;
    a:node) echo "$a_node";; b:node) echo "$b_node";; c:node) echo "$c_node";;
    d:node) echo ssr;; e:node) echo hy;;
    s1:enabled) echo 1;; s1:node) echo good;; s1:port) echo 1080;;
    @global_delay*:start_daemon) echo 0;;
    *) printf '%s' "\${3-}";;
  esac
}
config_get_type() { echo nodes; }
gen_ss_config() { case "$1" in *bad*) echo bad-method >&2; return 1;; esac; echo '{}' > "$2"; }
run_socks() {
  local arg node config_file
  for arg in "$@"; do case "$arg" in node=*) node="\${arg#*=}";; config_file=*) config_file="\${arg#*=}";; esac; done
  if [ "$node" = late ] && [ "$sid" = b ]; then
    echo "failed-port $redir_port" >> "$events"
    echo partial > "$TMP_PATH/$config_file"
    return 1
  fi
  echo '{}' > "$TMP_PATH/$config_file"
  echo "socks $node" >> "$events"; return 0
}
run_ipt2socks() { echo "ipt2socks $*" >> "$events"; }
run_dns2socks() { echo "dns $*" >> "$events"; }
ln_run() { echo "process $*" >> "$events"; }
get_new_port() { echo "$1"; }
has_1_65535() { [ "$1" = '1:65535' ]; }
normalize_dns() { echo "$1"; }
lua() { return 0; }
first_type() { echo "$1"; }
ENABLED_ACLS=1; ENABLED_DEFAULT_ACL=0; CLIENT_PROXY=1; NODE=global
TCP_NO_REDIR_PORTS=disable; UDP_NO_REDIR_PORTS=disable; TCP_REDIR_PORTS=1:65535; UDP_REDIR_PORTS=1:65535
TCP_PROXY_MODE=proxy; UDP_PROXY_MODE=proxy; TCP_PROXY_WAY=redirect; PROXY_IPV6=0
LOCAL_DNS=223.5.5.5; DEFAULT_DNS=223.5.5.5
uci() {
  if [ "$1" = show ]; then
    for id in $items; do echo "passwall.$id=acl_rule"; done
    [ "$SOCKS_ENABLED" != 1 ] || echo 'passwall.s1=socks'
    return
  fi
  if [ "$1" = -q ] && [ "$2" = show ]; then
    local id="\${3#passwall.}" n
    n=$(config_n_get "$id" node)
    printf "passwall.%s.enabled='1'\npasswall.%s.node='%s'\npasswall.%s.remarks='%s'\n" "$id" "$id" "$n" "$id" "$id"
    echo "passwall.$id.mode='$(config_n_get "$id" mode)'"
    [ "$id" != b ] || echo "passwall.$id.log='1'"
    return
  fi
  return 1
}
${func(app, 'check_node_supported')}
${func(app, 'check_dns_config')}
${func(app, 'fail_acl')}
${func(app, 'check_ss_node')}
${func(app, 'fail_ss_acl')}
${func(app, 'acl_app')}
${func(nft, 'factor')}
${func(nft, 'REDIRECT')}
${func(nft, 'get_jump_nft')}
${func(nft, 'load_acl')}
nft() { echo "nft $*" >> "$events"; }
nft_rule_dual() { echo "nft-dual $*" >> "$events"; }
gen_nftset() { :; }
NFTABLE_NAME='inet passwall'; FWMARK=1
`;
function run(name, code) {
  if (process.env.PASSWALL_ISOLATION_CASE && !name.includes(process.env.PASSWALL_ISOLATION_CASE)) return;
  cp.execFileSync(bash, ['-s'], {input: common + '\n' + code, stdio: ['pipe','inherit','inherit']});
  console.log('PASS ' + name);
}
run('cleanup preserves similarly named nodes and unrelated state', `
set_cache_var acl_node_bad_socks_port 9998
set_cache_var acl_node_bad_redir_port 9999
set_cache_var ACL_a_redir_port 9999
printf 'node_bad_deadbeef=9997\nnode_bad_deadbeef_ipv6=1\nnode_bad_extra_deadbeef=8888\n' > "$TMP_PATH/var"
mkdir -p "$TMP_ACL_PATH/a"
echo stale > "$TMP_ACL_PATH/bad_SOCKS_9998.json"
echo valid > "$TMP_ACL_PATH/bad_SOCKS_9998_SOCKS_7777.json"
fail_ss_acl a bad
[ ! -e "$TMP_ACL_PATH/bad_SOCKS_9998.json" ] || fail 'stale config retained'
[ -e "$TMP_ACL_PATH/bad_SOCKS_9998_SOCKS_7777.json" ] || fail 'similarly named config deleted'
! grep -q '^node_bad_deadbeef' "$TMP_PATH/var" || fail 'stale DNS state retained'
grep -q '^node_bad_extra_deadbeef=8888$' "$TMP_PATH/var" || fail 'similarly named DNS state deleted'
[ -z "$(get_cache_var ACL_a_redir_port)" ] || fail 'failed ACL cache retained'
`);
run('ACL mode=0 keeps source-specific TCP/UDP exemptions without checking or starting nodes', String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() {
  case "$1:$2" in
    a:mode) echo 0;; a:dns_mode) echo xray;; old:type) echo "$retired_core";;
    *) config_original "$@";;
  esac
}
eval "$(declare -f uci | sed '1s/uci/uci_original/')"
uci() {
  uci_original "$@"
  if [ "$1:$2:$3" = '-q:show:passwall.a' ]; then
    echo "passwall.a.sources='00:11:22:33:44:55'"
    echo "passwall.a.dns_mode='xray'"
  fi
}
lua_api() { case "$1" in iprange*) echo false;; ip_or_mac*) echo mac;; esac; }
eval "$(declare -f check_node_supported | sed '1s/check_node_supported/check_node_original/')"
check_node_supported() { echo checked-node >> "$events"; check_node_original "$@"; }
eval "$(declare -f check_ss_node | sed '1s/check_ss_node/check_ss_original/')"
check_ss_node() { echo checked-ss >> "$events"; check_ss_original "$@"; }
eval "$(declare -f check_dns_config | sed '1s/check_dns_config/check_dns_original/')"
check_dns_config() { echo checked-dns >> "$events"; check_dns_original "$@"; }
check_hysteria_node() { fail 'unused Hysteria node checked'; }
config_get_type() { [ "$1" != missing ] && echo nodes; }
items=a;PROXY_IPV6=1
for way in redirect tproxy; do
  TCP_PROXY_WAY=$way;is_tproxy=;nft_prerouting_chain=PSW_NAT
  [ "$way" != tproxy ] || { is_tproxy=1;nft_prerouting_chain=PSW_MANGLE; }
  for node_case in good Xray sing-box missing; do
      a_node=$node_case
      case "$node_case" in Xray|sing-box) a_node=old;retired_core=$node_case;; esac
      rm -f "$TMP_PATH"/key_*;: > "$events";ENABLED_ACLS=1
      set_cache_var ACL_GLOBAL_node good;set_cache_var ACL_GLOBAL_redir_port 1041
      set_cache_var acl_node_good_socks_port 11111;set_cache_var acl_node_good_redir_port 11211
      set_cache_var ACL_a_failed 1
      for key in node redir_port dns_port default fakedns;do set_cache_var "ACL_a_$key" 19999;done
      load_acl
      [ -z "$(get_cache_var ACL_a_failed)" ] || fail 'direct ACL rejected'
      [ "$(cat "$TMP_ACL_PATH/a/source_list")" = 'mac:00:11:22:33:44:55' ] || fail 'source lost'
      for key in node redir_port dns_port default fakedns;do
        [ -z "$(get_cache_var "ACL_a_$key")" ] || fail 'direct ACL retained proxy state'
      done
      [ "$(get_cache_var ACL_GLOBAL_redir_port)" = 1041 ] || fail 'global port changed'
      [ "$(get_cache_var acl_node_good_redir_port)" = 11211 ] || fail 'shared instance changed'
      ! grep -Eq '^checked-|^socks |^ipt2socks |^dns |^process ' "$events" || fail 'unused node/DNS checked or started'
      for proto in tcp udp;do
        grep "^nft .*ip protocol $proto .*counter return comment" "$events" | grep -F 'ether saddr {00:11:22:33:44:55}' | grep -v 'dport 53' | grep -q '"a"' || fail "IPv4 $proto exemption missing"
        grep "^nft .*PSW_MANGLE_V6 meta l4proto $proto .*counter return comment" "$events" | grep -F 'ether saddr {00:11:22:33:44:55}' | grep -v 'dport 53' | grep -q '"a"' || fail "IPv6 $proto exemption missing"
      done
      ! grep '^nft ' "$events" | grep -Eq 'tproxy|redirect to :19999|redirect to :1041' || fail 'direct traffic forwarded'
  done
done
`);
run('ACL effective DNS: reuse started global SS, reject retired nodes and invalid independent DNS', String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() {
  case "$1:$2" in
    old:type) echo Xray;; a:dns_mode) echo "$acl_dns";; a:use_global_config) echo "$inherit";;
    *) config_original "$@";;
  esac
}
eval "$(declare -f uci | sed '1s/uci/uci_original/')"
uci() {
  uci_original "$@"
  if [ "$1:$2:$3" = '-q:show:passwall.a' ]; then
    echo "passwall.a.dns_mode='$acl_dns'"
    echo "passwall.a.use_global_config='$inherit'"
  fi
}
items=a;NODE=good;GLOBAL_DNSMASQ_PORT=11400;nft_prerouting_chain=PSW_NAT
for scenario in retired reuse inherit independent-bad independent-good global-not-started;do
  rm -rf "$TMP_ACL_PATH";mkdir -p "$TMP_ACL_PATH";rm -f "$TMP_PATH"/key_*;: > "$events"
  ENABLED_ACLS=1;a_node=good;acl_dns=xray;inherit=0
  case "$scenario" in
    retired) a_node=old;;
    reuse|inherit) set_cache_var ACL_GLOBAL_node good;set_cache_var ACL_GLOBAL_redir_port 1041;set_cache_var ACL_default_dns_port 11400;
      [ "$scenario" != inherit ] || { inherit=1;a_node=old; };;
    independent-good) acl_dns=dns2socks;;
    global-not-started) set_cache_var ACL_GLOBAL_failed 1;;
  esac
  load_acl
  case "$scenario" in
    retired|independent-bad|global-not-started)
      [ "$(get_cache_var ACL_a_failed)" = 1 ] || fail 'invalid independent ACL accepted'
      [ -z "$(get_cache_var ACL_a_redir_port)" ] || fail 'invalid ACL published port'
      [ ! -d "$TMP_ACL_PATH/a" ] || fail 'invalid ACL source directory retained'
      ! grep -Eq '^socks |^ipt2socks |^dns |^nft ' "$events" || fail 'invalid ACL started or forwarded'
      ;;
    *)
      [ -z "$(get_cache_var ACL_a_failed)" ] || fail 'valid ACL rejected'
      port=$(get_cache_var ACL_a_redir_port)
      if [ "$scenario" = independent-good ];then
        [ -n "$port" ] && [ "$port" != 1041 ] || fail 'independent ACL port missing'
        grep -q '^socks good$' "$events" && grep -q '^ipt2socks ' "$events" && grep -q '^dns ' "$events" || fail 'independent SS/DNS not started'
        [ -z "$(get_cache_var ACL_a_default)" ] || fail 'independent ACL inherited failed/unstarted global'
      else
        [ "$port" = 1041 ] && [ "$(get_cache_var ACL_a_default)" = 1 ] || fail 'global listener not inherited'
        [ "$(get_cache_var ACL_a_dns_port)" = 11400 ] || fail 'global DNS not inherited'
        ! grep -Eq '^socks |^ipt2socks |^dns |unsupported backend' "$events" || fail 'unused independent DNS checked or started'
      fi
      for proto in tcp udp;do
        grep "^nft .*ip protocol $proto" "$events" | grep -q ":$port" || fail "$proto forwarding missing"
      done
      ;;
  esac
done
`);
run('invalid-first and interleaved ACLs; valid SS/Rust/SSR TCP+UDP rules survive', `
for layout in first interleaved late shared; do
  rm -rf "$TMP_ACL_PATH"; mkdir -p "$TMP_ACL_PATH"; rm -f "$TMP_PATH"/key_*; : > "$events"
  ENABLED_ACLS=1; items='a b c d e'
  if [ "$layout" = first ]; then a_node=bad; b_node=good; c_node=rust; failed=a
  elif [ "$layout" = late ]; then a_node=good; b_node=late; c_node=rust; failed=b
  elif [ "$layout" = shared ]; then a_node=late; b_node=late; c_node=rust; failed=b
  else a_node=good; b_node=bad; c_node=rust; failed=b; fi
  failed_node=$(config_n_get "$failed" node)
  set_cache_var "acl_node_\${failed_node}_socks_port" 9998
  set_cache_var "acl_node_\${failed_node}_redir_port" 9999
  [ "$layout" != late ] && [ "$layout" != shared ] || { del_cache_var "acl_node_\${failed_node}_socks_port"; del_cache_var "acl_node_\${failed_node}_redir_port"; }
  mkdir -p "$TMP_ACL_PATH/$failed"; echo stale > "$TMP_ACL_PATH/$failed/stale.json"
  if [ "$layout" = first ] || [ "$layout" = interleaved ]; then
    echo stale > "$TMP_ACL_PATH/\${failed_node}_SOCKS_9998.json"
  fi
  printf 'node_%s_deadbeef=9997\nnode_unrelated_hash=8877\n' "$failed_node" > "$TMP_PATH/var"
  load_acl
  [ "$(get_cache_var "ACL_\${failed}_failed")" = 1 ] || fail 'failure not recorded'
  [ ! -d "$TMP_ACL_PATH/$failed" ] || fail 'failed ACL directory retained'
  [ ! -e "$TMP_ACL_PATH/\${failed_node}_SOCKS_9998.json" ] || fail 'stale config retained'
  if [ "$layout" = first ] || [ "$layout" = interleaved ]; then
    ! grep -q "^node_\${failed_node}_" "$TMP_PATH/var" || fail 'stale DNS cache retained'
  fi
  grep -q '^node_unrelated_hash=8877$' "$TMP_PATH/var" || fail 'unrelated DNS cache removed'
  if [ "$layout" = shared ]; then
    [ "$(get_cache_var acl_node_late_redir_port)" = "$(get_cache_var ACL_a_redir_port)" ] || fail 'shared instance cache lost'
    good_socks=$(get_cache_var acl_node_late_socks_port)
    [ -f "$TMP_ACL_PATH/late_SOCKS_\${good_socks}.json" ] || fail 'shared config deleted'
  else
    for key in socks_port redir_port enable_log; do [ -z "$(get_cache_var "acl_node_\${failed_node}_$key")" ] || fail 'stale node cache'; done
  fi
  for key in node redir_port dns_port; do [ -z "$(get_cache_var "ACL_\${failed}_$key")" ] || fail 'failed ACL cache'; done
  for id in a b c d e; do
    [ "$id" != "$failed" ] || continue
    port=$(get_cache_var "ACL_\${id}_redir_port")
    [ -n "$port" ] || fail "valid ACL $id was skipped"
    grep 'nft .*ip protocol tcp' "$events" | grep -q ":$port" || fail "TCP rule missing: $id"
    grep 'nft .*ip protocol udp' "$events" | grep -q ":$port" || fail "UDP rule missing: $id"
  done
  ! grep '^nft .*9999' "$events" || fail 'failed port forwarded'
  failed_port=$(awk '/^failed-port / {print $2}' "$events")
  if [ -n "$failed_port" ]; then
    ! grep '^nft ' "$events" | grep -q ":$failed_port" || fail 'late failure forwarded'
  fi
  ! grep -q "^dns flag=acl_$failed " "$events" || fail 'failed ACL DNS started'
  ! grep -E 'ipt2socks flag=acl_bad' "$events" || fail 'failed bridge started'
  # Exercise the nftables failure guard even if an old directory reappears.
  mkdir -p "$TMP_ACL_PATH/$failed"; echo any > "$TMP_ACL_PATH/$failed/source_list"
  set_cache_var "ACL_\${failed}_redir_port" 9999
  set_cache_var "ACL_\${failed}_node" "$failed_node"
  acl_app() { :; }; : > "$events"; load_acl
  ! grep '^nft .*9999' "$events" || fail 'stale directory forwarded'
  ${func(app, 'acl_app')}
done
`);
run('invalid/valid global SS and retired Hysteria2 with independent SOCKS; explicit stop and real failure rollback', `
${func(app, 'start')}
${func(app, 'stop')}
${func(app, 'start_socks')}
get_config() { ENABLED=1; SOCKS_ENABLED=1; ENABLED_ACLS=0; ENABLED_DEFAULT_ACL=1; NODE="$global_node"; REDIR_PORT=1041; }
start_haproxy() { :; }
export events
printf '#!/bin/sh\necho independent-socks >> "$events"\n' > "$APP_PATH/app.sh"
chmod +x "$APP_PATH/app.sh"
start_global() { GLOBAL_SOCKS_server=127.0.0.1:1070; echo global-start >> "$events"; [ "$runtime_failure" != core ]; }
start_dns() { ACL_default_dns_port=11400; echo global-dns >> "$events"; [ "$runtime_failure" != dns ]; }
start_crontab() { echo cron-start >> "$events"; }
stop_crontab() { echo cron-stop >> "$events"; }
clean_log() { :; }; eval_cache_var() { :; }; delete_ip2route() { echo route-cleanup >> "$events"; }
check_run_environment() { USE_TABLES=fw; }
busybox() { return 1; }
xargs() { cat >/dev/null; echo process-cleanup >> "$events"; }
sysctl() { return 0; }; logger() { :; }; ulimit() { :; }
mkdir() { local dir; for dir in "$@"; do case "$dir" in -p|/tmp/etc|/tmp/log) :;; *) command mkdir -p "$dir";; esac; done; }
printf 'case "$1" in start) echo firewall-start >> "$events";; stop) echo firewall-stop >> "$events";; esac\n' > "$APP_PATH/fw.sh"
for global_node in bad good retired; do
  command mkdir -p "$TMP_PATH" "$TMP_ACL_PATH"; : > "$events"; runtime_failure=
  start
  grep -q '^independent-socks$' "$events" || fail 'SOCKS not started'
  ! grep -q process-cleanup "$events" || fail 'SOCKS stopped on validation failure'
  if [ "$global_node" != good ]; then
    ! grep -Eq '^global-start|^global-dns' "$events" || fail 'invalid global started'
    [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'global forwarding flag retained'
  else grep -q '^global-start' "$events" && grep -q '^global-dns' "$events" || fail 'valid global missing'; fi
  (stop)
  [ ! -d "$TMP_PATH" ] || fail 'explicit stop left runtime state'
  grep -q process-cleanup "$events" && grep -q firewall-stop "$events" && grep -q route-cleanup "$events" || fail 'stop incomplete'
done
for runtime_failure in core dns; do
  command mkdir -p "$TMP_PATH" "$TMP_ACL_PATH"; : > "$events"; global_node=good
  (start)
  grep -q process-cleanup "$events" || fail 'real failure rollback removed'
done
`);
