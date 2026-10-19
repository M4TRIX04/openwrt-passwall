// Executes production Lua, including the launcher and server orchestration.
// UCI, /proc, filesystem and core execution are OS-boundary test doubles.
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict'), cp=require('node:child_process');
const {lua,lauxlib,lualib,to_luastring:S,to_jsstring:J}=require('fengari');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,'luci-app-passwall',p),'utf8').replace(/^#![^\n]*\n/,'').replace(/\r\n/g,'\n');
const L=lauxlib.luaL_newstate();lualib.luaL_openlibs(L);
function run(s){
 if(process.env.PASSWALL_NATIVE_LUA_DOCKER){
  cp.execFileSync('docker',['run','--rm','-i','--entrypoint','/bin/sh',process.env.PASSWALL_NATIVE_LUA_DOCKER,'-c',
   `apk add --no-cache lua5.1 lua5.1-cjson >&2 && lua5.1 -e 'native_json=require("cjson"); dofile("/dev/stdin")'`],{input:s,stdio:['pipe','inherit','inherit']});return;
 }
 const status=lauxlib.luaL_dostring(L,S(s));assert.equal(status,lua.LUA_OK,status?J(lua.lua_tostring(L,-1)):'');
}
run(String.raw`
files={};nodes={};servers={};rules={};commands={};processes={};counter=100;encoded={};enc=0
local function stringify(t) enc=enc+1;local k=native_json and native_json.encode(t) or 'json:'..enc;encoded[k]=t;return k end
local function iterator(t) local i=0;return function() i=i+1;return t[i] end end
api={s_config='passwall_server',S_TMP_PATH='/tmp/etc/passwall_server',
 jsonc={parse=function(k)
  if native_json then local ok,v=pcall(native_json.decode,k);if ok then return v end;return nil end
  return encoded[k]
 end,stringify=stringify},
 base64Encode=function(s) return s=='secret' and 'c2VjcmV0' or '' end,
 base64Decode=function(s) return s=='c2VjcmV0' and 'secret' or '' end,
 is_ipv6=function(s) return s:find(':',1,true)~=nil end,
 uci_get_c=function(id) return nodes[id] end,
 uci_get_s=function(id) if id=='@global[0]' then return '1' end end,
 uci_foreach_s=function(_,fn) for _,s in ipairs(servers) do fn(s) end end,
 get_app_path=function() return '/usr/bin/hysteria' end,uci_save=function() end,remove=function() end,
 md5_string=function(s) return (s:gsub('[^%w]','_')) end}
api.fs={access=function(p) return files[p]~=nil or p:match('/fd$')~=nil end,
 readfile=function(p)
  local pid=p:match('^/proc/(%d+)/stat$')
  if pid then local proc=processes[tonumber(pid)];if not proc or proc.dead then return nil end;return pid..' (hy) S '..string.rep('0 ',18)..'123 0' end
  if p:match('^/proc/net/') then
   local proto=p:match('/([^/]+)$');local lines={}
   for id,proc in pairs(processes) do if not proc.dead and not no_listener then
    for _,v in ipairs(proc.listeners) do if v[1]==proto then lines[#lines+1]=string.format('0: 00000000:%04X 00000000:0000 %s 0 0 0 0 0 %d',v[2],proto=='tcp' and '0A' or '07',id) end end
   end end;return table.concat(lines,'\n')
  end
  return files[p]
 end,
 writefile=function(p,s) files[p]=s;return #s end,remove=function(p) files[p]=nil;return true end,
 rename=function(a,b) files[b]=files[a];files[a]=nil;return true end,
 mkdir=function() return true end,rmdir=function() return true end,
 symlink=function(_,p) files[p]='link';return true end,
 readlink=function(p) local pid=p:match('^/proc/(%d+)/fd/');if pid then return 'socket:['..pid..']' end end,
 dir=function(p) if p:match('/fd$') then return iterator({'3'}) end
  local names={};for f in pairs(files) do if f:sub(1,#p+1)==p..'/' and not f:sub(#p+2):find('/') then names[#names+1]=f:sub(#p+2) end end;return iterator(names) end}
api.sys={call=function(s)
 commands[#commands+1]=s
 local pid=s:match('kill %-TERM (%d+)') or s:match('kill %-KILL (%d+)');if pid then processes[tonumber(pid)].dead=true end
 local family=s:match('^(ip6?tables) ')
 local key=s:gsub(' %-C OUTPUT ',' -A OUTPUT '):gsub(' %-D OUTPUT ',' -A OUTPUT '):gsub(' 2>/dev/null$','')
 if s:find(' -C OUTPUT ',1,true) then return query_error and 2 or ((preexisting_rule or (rule_state or {})[key]) and 0 or 1) end
 if s:find(' -D OUTPUT ',1,true) then
  if delete_error == family or delete_error == 'all' then return 2 end
  local present=(rule_state or {})[key];if rule_state then rule_state[key]=nil end
  return present and 0 or 1
 end
 if s:find(' -A OUTPUT ',1,true) and not deny_rules then rule_state=rule_state or {};rule_state[key]=true end
 if deny_rules and s:find(' -A OUTPUT ',1,true) then return 1 end
 return 0
end,exec=function(s)
 if s:find('--version',1,true) then return version or 'hysteria version v1.3.5 build commit\n' end
 if s:find('echo $!',1,true) then
  counter=counter+1;local file=s:match(" %-c '([^']+)'");local c=encoded[files[file]];assert(c,'missing launch config')
  local listeners={}
  if s:find(" 'server' ",1,true) then listeners={{c.protocol=='faketcp' and 'tcp' or 'udp',tonumber(c.listen:match(':(%d+)$'))}}
  else for _,k in ipairs({'socks5','http','redirect_tcp','tproxy_tcp','tproxy_udp'}) do if c[k] then listeners[#listeners+1]={k=='tproxy_udp' and 'udp' or 'tcp',tonumber(c[k].listen:match(':(%d+)$'))} end end end
  processes[counter]={listeners=listeners,dead=immediate_exit};return tostring(counter)
 end;return ''
end}
modules={['luci.passwall.api']=api,['luci.util']={shellquote=function(s) return "'"..s.."'" end},
 ['nixio']={bin={b64decode=function(s) return ({['c2VjcmV0']='secret',['AA==']=string.char(0),['YQBi']='a'..string.char(0)..'b'})[s] end,b64encode=function(s) return ({secret='c2VjcmV0',[string.char(0)]='AA==',['a'..string.char(0)..'b']='YQBi'})[s] or '' end},nanosleep=function() end,open=function() return {lock=function() if lock_busy then return false end; assert(not lock_owned);lock_owned=true;return true end,close=function() lock_owned=false end} end,getaddrinfo=function(host,family) assert(family=='any');return {{address='203.0.113.1'}} end}}
require=function(n) return assert(modules[n],n) end;module=function() end;arg={}
files['/cert']='cert';files['/key']='key';files['/ca']='CA'
${read('luasrc/passwall/util_hysteria.lua')}
hy={gen_config=gen_config,gen_config_server=gen_config_server};modules['luci.passwall.util_hysteria']=hy
function node(protocol) return {type='Hysteria',address='example.com',port='443',protocol=protocol,
 hysteria_auth_type='string',hysteria_auth_password='secret',hysteria_up_mbps='10',hysteria_down_mbps='50',
 tls_certificateFile='/cert',tls_keyFile='/key',hysteria_recv_window='1048576'} end
function rejected(fn,...) local ok,err=pcall(fn,...);assert(not ok,tostring(err)) end
for _,protocol in ipairs({'udp','faketcp','wechat-video'}) do
 nodes.n=node(protocol)
 for _,way in ipairs({'redirect','tproxy'}) do
  local c=encoded[hy.gen_config({node='n',local_socks_address='::1',local_socks_port='1080',local_http_port='8080',local_redir_port='1041',tcp_proxy_way=way})]
  assert(c.protocol==protocol and c.auth_str=='secret' and c.auth==nil and c.recv_window==1048576)
  assert(c.socks5.listen=='[::1]:1080' and c.http.listen=='127.0.0.1:8080')
  assert(c.tproxy_udp.listen=='0.0.0.0:1041' and c[way=='redirect' and 'redirect_tcp' or 'tproxy_tcp'])
  for _,k in ipairs({'tls','quic','bandwidth','transport','realm','tcpTProxy','udpTProxy'}) do assert(c[k]==nil,k) end
 end
 local c=hy.gen_config_server(nodes.n)
 assert(c.recv_window_client==1048576 and c.recv_window==nil and c.auth.mode=='password' and c.auth.config.password=='secret')
 assert(c.cert=='/cert' and c.key=='/key' and not c.disable_udp)
 for k,field in pairs({hysteria_disable_mtu_discovery='disable_mtu_discovery',hysteria_lazy_start='lazy_start',tls_allowInsecure='insecure',fast_open='fast_open'}) do
  for _,v in ipairs({'0','1'}) do nodes.n[k]=v;local c=encoded[hy.gen_config({node='n',local_socks_port='1080'})];assert(c[field]==(v=='1')) end
  nodes.n[k]='yes';rejected(hy.gen_config,{node='n',local_socks_port='1080'});nodes.n[k]=nil
 end
 nodes.n.hysteria_udp='0';assert(hy.gen_config_server(nodes.n).disable_udp);nodes.n.hysteria_udp=nil
 nodes.n.hysteria_auth_type='base64';nodes.n.hysteria_auth_password='c2VjcmV0'
 assert(encoded[hy.gen_config({node='n',local_socks_port='1080'})].auth=='c2VjcmV0');rejected(hy.gen_config_server,nodes.n)
 nodes.n.hysteria_auth_password='bad!';rejected(hy.gen_config,{node='n',local_socks_port='1080'})
 nodes.n=node(protocol);nodes.n.address='2001:db8::1';assert(encoded[hy.gen_config({node='n',local_socks_port='1080'})].server=='[2001:db8::1]:443')
end
for _,entry in ipairs({{'port','0'},{'port','65536'},{'hysteria_up_mbps','abc'},{'hysteria_down_mbps','-1'},
 {'hysteria_recv_window','10'},{'hysteria_auth_type','userpass'},{'hysteria_auth_password',''},
 {'hysteria_hop','1000-2000'},{'protocol','hysteria2'}}) do
 nodes.n=node('udp');nodes.n[entry[1]]=entry[2];rejected(hy.gen_config,{node='n',local_socks_port='1080'})
end
for _,field in ipairs({'tls_certificateFile','tls_keyFile'}) do local n=node('udp');n[field]='/missing';rejected(hy.gen_config_server,n);n[field]=nil;rejected(hy.gen_config_server,n) end
nodes.n=node('udp');nodes.n.hysteria_up_mbps=nil;rejected(hy.gen_config,{node='n',local_socks_port='1080'})
nodes.n=node('udp')
local v6=encoded[hy.gen_config({node='n',local_redir_port='1041',tcp_proxy_way='tproxy',proxy_ipv6='1'})]
assert(v6.tproxy_tcp.listen=='[::]:1041' and v6.tproxy_udp.listen=='[::]:1041')
rejected(hy.gen_config,{node='n',local_redir_port='1041',tcp_proxy_way='redirect',proxy_ipv6='1'})
${read('luasrc/passwall/hysteria_runtime.lua')}
runtime={start=start,stop=stop};modules['luci.passwall.hysteria_runtime']=runtime
function launch(protocol,mode,scope)
 nodes.n=node(protocol);local file='/tmp/etc/'..scope..'/'..protocol..'.json'
 files[file]=mode=='server' and stringify(hy.gen_config_server(nodes.n)) or hy.gen_config({node='n',local_socks_port='1080',local_redir_port='1041',tcp_proxy_way='tproxy'})
 return {config=file,bin='/usr/bin/hysteria',scope=scope,mode=mode}
end
for _,protocol in ipairs({'udp','faketcp','wechat-video'}) do for _,mode in ipairs({'client','server'}) do
 local v=launch(protocol,mode,mode);assert(runtime.start(v));assert(files[v.config]);assert(runtime.start(v));runtime.stop(mode);assert(not files[v.config])
end end
for _,failure in ipairs({'exit','listener','version','rules'}) do
 local good=launch('udp','client','client');assert(runtime.start(good));local goodpid=counter
 local bad=launch('faketcp','client','client')
 immediate_exit=failure=='exit';no_listener=failure=='listener';version=failure=='version' and 'hysteria version v2.6.0' or nil;deny_rules=failure=='rules'
 rejected(runtime.start,bad);immediate_exit=false;no_listener=false;version=nil;deny_rules=false
 assert(not processes[goodpid].dead and files[good.config] and not files[bad.config]);runtime.stop('client');assert(processes[goodpid].dead)
end
local dropped=false;for _,cmd in ipairs(commands) do if cmd:find(' -D OUTPUT ',1,true) then dropped=true end end;assert(dropped)
-- Shared core rules survive stopping one scope; external pre-existing rules
-- must never become owned by this launcher.
local one=launch('faketcp','client','client');assert(runtime.start(one))
local two=launch('faketcp','client','second');two.scope='server';assert(runtime.start(two))
commands={};runtime.stop('client')
for _,cmd in ipairs(commands) do assert(not cmd:find(' -D OUTPUT ',1,true)) end
runtime.stop('server')
commands={};preexisting_rule=true
local external=launch('faketcp','client','client');assert(runtime.start(external));runtime.stop('client')
for _,cmd in ipairs(commands) do assert(not cmd:find(' -D OUTPUT ',1,true)) end
preexisting_rule=false
-- Fault injection runs the production release loop, including partial IPv6 cleanup.
local v=launch('faketcp','server','server');assert(runtime.start(v))
delete_error='all';query_error=nil
rejected(runtime.stop,'server') -- failed deletion, successful query confirms still present
delete_error='iptables';query_error=true
rejected(runtime.stop,'server');assert(not lock_owned)
local pending=0;for p in pairs(files) do if p:match('passwall_hysteria1/.*%.json$') then pending=pending+1 end end;assert(pending==1)
-- IPv6 was deleted once; retry must not repeat that successful release.
commands={};delete_error=nil;query_error=nil;runtime.stop('server')
for _,cmd in ipairs(commands) do assert(not cmd:match('^ip6tables .* %-D OUTPUT ')) end
runtime.stop('server') -- idempotent after success
-- Query errors at acquisition must not install new rules.
commands={};v=launch('faketcp','client','client');query_error=true;rejected(runtime.start,v);query_error=nil
for _,cmd in ipairs(commands) do assert(not cmd:find(' -A OUTPUT ',1,true)) end
runtime.stop('client')
lock_busy=true;rejected(runtime.stop,'server');lock_busy=false;runtime.stop('server');assert(not lock_owned)
-- Binary authentication bypasses the public decoder that strips NUL.
nodes.n=node('udp');nodes.n.hysteria_auth_type='base64'
for _,encoded_auth in ipairs({'AA==','YQBi'}) do nodes.n.hysteria_auth_password=encoded_auth;assert(encoded[hy.gen_config({node='n',local_socks_port='1080'})].auth==encoded_auth) end
api.uci={foreach=function(_,_,_,fn) for name,r in pairs(rules) do r['.name']=name;fn(r) end end,
 delete=function(_,_,name) rules[name]=nil end,section=function(_,_,_,name) rules[name]={} end,set=function(_,_,name,k,v) rules[name][k]=v end}
io.open=function(p) return {write=function(self,s) files[p]=(files[p] or '')..s;return self end,close=function() return true end} end
servers={}
for i,protocol in ipairs({'udp','faketcp','wechat-video'}) do local n=node(protocol);n['.name']='s'..i;n.enable='1';n.firewall_allow='1';n.remarks=protocol;servers[#servers+1]=n end
local bad=node('udp');bad['.name']='bad';bad.enable='1';bad.port='0';bad.firewall_allow='1';table.insert(servers,2,bad)
arg={'start'}
${read('luasrc/passwall/server_app.lua')}
assert(not rules.passwall_server_bad)
assert(rules.passwall_server_s1.proto=='udp' and rules.passwall_server_s2.proto=='tcp' and rules.passwall_server_s3.proto=='udp')
files['/tmp/etc/passwall_hysteria1']='directory'
arg={'stop'}
${read('luasrc/passwall/server_app.lua')}
assert(next(rules)==nil)
-- Stop failure must not abort shared firewall and directory cleanup.
servers={node('faketcp')};servers[1]['.name']='retry';servers[1].enable='1';servers[1].firewall_allow='1'
arg={'start'}
${read('luasrc/passwall/server_app.lua')}
local removed=false;api.remove=function() removed=true end
delete_error='all';query_error=true;arg={'stop'}
local stopped,stop_error=pcall(function()
${read('luasrc/passwall/server_app.lua')}
end)
assert(not stopped and removed and next(rules)==nil and tostring(stop_error):find('cannot remove/verify',1,true))
local generic_cleanup=false;for _,command in ipairs(commands) do if command:find("xargs kill -9",1,true) then generic_cleanup=true end end;assert(generic_cleanup)
delete_error=nil;query_error=nil;runtime.stop('server')
`);
console.log('PASS real v1 generators: transports, auth, IPv4/IPv6, flags, fields and validation');
console.log('PASS real launcher: Client/Server x 3 modes, restart/stop, failures, faketcp rule cleanup');
console.log('PASS real server_app: mixed instances, mode-specific firewall and stop');
const app=read('root/usr/share/passwall/app.sh');
const branches=[...app.matchAll(/\n\thysteria\)\n([\s\S]*?)\n\t;;/g)];assert.equal(branches.length,2);
const bodies=branches.map(b=>b[1]);
bodies.push(app.slice(app.indexOf('run_hysteria_acl() {'),app.indexOf('run_socks() {'))+'\nrun_hysteria_acl n config 1041 1080 /dev/null warn || return 1');
const bash=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/bin/bash';
for(const body of bodies) cp.execFileSync(bash,['-s'],{stdio:['pipe','inherit','inherit'],input:`
set -eu
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
config_file="$work/config";log_file=/dev/null;loglevel=warn;bind=127.0.0.1;socks_port=1080;http_port=8080
TMP_PATH="$work"
REDIR_PORT=1041;TCP_PROXY_WAY=tproxy;node_socks_bind=127.0.0.1;GLOBAL_SOCKS_port=1080;GLOBAL_HTTP_port=8080;on_node_http=1;no_run=
json_init() { :; };json_add_string() { :; };json_dump() { echo '{}'; };config_n_get() { echo warn; }
gen_hysteria_config() { [ "$fail" != config ] || return 1;echo '{}' > "$2"; }
start_hysteria() { [ "$fail" != startup ] || { rm -f "$1";return 1; };echo started > "$work/started"; }
branch() { ${body}\nreturn 0; }
for protocol in udp faketcp wechat-video; do
 for fail in config startup good; do
  rm -f "$work/started" "$config_file"
  if branch;then [ "$fail" = good ];test -f "$work/started";else [ "$fail" != good ];test ! -f "$work/started";test ! -f "$config_file";fi
 done
done
`});
console.log('PASS real global/SOCKS shell branches: generation/launch failure propagation');

// Reuse the first-stage OS fixture, not its SS-specific expected results.
// Production ACL/nftables/start/stop functions are extracted by that fixture.
const fixturePath=path.join(__dirname,'passwall-client-isolation.cjs');
let fixture=fs.readFileSync(fixturePath,'utf8').split("run('cleanup preserves")[0];
fixture=fixture.replace('hy:type) echo Hysteria2','hy:type|hybad:type) echo Hysteria');
const addition=String.raw`
run('Hysteria mixed ACLs: invalid first/interleaved and valid TCP+UDP forwarding', \`
\${func(app,'gen_hysteria_config')}
\${func(app,'check_hysteria_node')}
\${func(app,'fail_hysteria_acl')}
HYSTERIA_RUNTIME=not-installed
lua() { case "$*" in *hybad*) [ "$failure_stage" = runtime ] || return 1;; esac;echo '{}'; }
eval "$(declare -f run_socks | sed '1s/run_socks/run_socks_fixture/')"
run_socks() { case "$*" in *node=hybad*) [ "$failure_stage" != runtime ] || return 1;;esac;run_socks_fixture "$@"; }
run_hysteria_acl() { run_socks node="$1" config_file="$2"; }
UTIL_HYSTERIA=util_hysteria
for layout in first middle late; do
  failure_stage=config;[ "$layout" != late ] || failure_stage=runtime
  if [ "$layout" = first ]; then a_node=hybad;b_node=hy;c_node=rust;failed=a;else a_node=hy;b_node=hybad;c_node=rust;failed=b;fi
  items='a b c';load_acl
  [ "$(get_cache_var ACL_\${failed}_failed)" = 1 ] || fail 'failure not recorded'
  [ -z "$(get_cache_var ACL_\${failed}_redir_port)" ] || fail 'failed port cached'
  [ -z "$(get_cache_var acl_node_hybad_redir_port)" ] || fail 'failed node cached'
  for id in a b c; do
    [ "$id" != "$failed" ] || continue
    port=$(get_cache_var ACL_\${id}_redir_port)
    [ -n "$port" ] || fail 'valid ACL skipped'
    grep 'nft .*ip protocol tcp' "$events" | grep -q ":$port" || fail 'TCP missing'
    grep 'nft .*ip protocol udp' "$events" | grep -q ":$port" || fail 'UDP missing'
  done
done
\`);
run('Hysteria invalid global and startup failure preserve independent SOCKS; stop cleans', \`
\${func(app,'check_hysteria_node')}
\${func(app,'start')}
\${func(app,'stop')}
\${func(app,'start_socks')}
gen_hysteria_config() { [ "$global_node" != hybad ] || return 1;echo '{}' > "$2"; }
get_config() { ENABLED=1;SOCKS_ENABLED=1;ENABLED_ACLS=0;ENABLED_DEFAULT_ACL=1;NODE="$global_node"; }
start_haproxy() { :; };export events
printf '#!/bin/sh\necho independent-socks >> "$events"\n' > "$APP_PATH/app.sh";chmod +x "$APP_PATH/app.sh"
start_global() { echo global-start >> "$events";[ "$runtime_failure" != core ]; }
start_dns() { echo global-dns >> "$events"; }
start_crontab() { :; };stop_crontab() { :; };clean_log() { :; };eval_cache_var() { :; };delete_ip2route() { :; }
check_run_environment() { USE_TABLES=fw; }
busybox() { return 1; };xargs() { cat >/dev/null;echo process-cleanup >> "$events"; }
sysctl() { return 0; };logger() { :; };ulimit() { :; }
mkdir() { local dir;for dir in "$@";do case "$dir" in -p|/tmp/etc|/tmp/log) :;; *) command mkdir -p "$dir";;esac;done; }
printf 'echo firewall-$1 >> "$events"\n' > "$APP_PATH/fw.sh"
for global_node in hybad hy; do
  for runtime_failure in good core; do
    command mkdir -p "$TMP_PATH" "$TMP_ACL_PATH";: > "$events"
    start
    grep -q independent-socks "$events" || fail 'independent SOCKS missing'
    ! grep -q process-cleanup "$events" || fail 'independent SOCKS killed'
    if [ "$global_node" = hybad ] || [ "$runtime_failure" = core ];then
      [ "$(get_cache_var ENABLED_DEFAULT_ACL)" = 0 ] || fail 'failed global forwarding enabled'
      ! grep -q global-dns "$events" || fail 'failed global DNS started'
    else grep -q global-dns "$events" || fail 'valid global DNS missing';fi
    (stop)
    grep -q process-cleanup "$events" || fail 'explicit stop incomplete'
  done
done
\`);
`;
fixture+=String.raw`
run('Hysteria same-node ACL failure preserves previous owner and nftables ports', \`
\${func(app,'fail_hysteria_acl')}
\${func(app,'gen_hysteria_config')}
\${func(app,'start_hysteria')}
\${func(app,'run_hysteria_acl')}
HYSTERIA_RUNTIME=runtime.lua;UTIL_HYSTERIA=generator.lua;runtime_fail=1
check_hysteria_node() { return 0; }
json_init() { json_data=''; }
json_add_string() { json_data="$json_data$1=$2|"; }
json_dump() { echo "$json_data"; }
lua() {
  [ "$1" != generator.lua ] || { echo '{}';return 0; }
  [ "$1" = runtime.lua ] || return 0
  if [ "$2" = start ];then
    local file="$3";file="\${file#config=}";file="\${file%%|*}"
    if [ "$sid" = b ] && [ "$runtime_fail" = 1 ];then echo "failed-port $redir_port" >> "$events";return 1;fi
    echo start >> "$events";echo alive > "$file.alive";return 0
  fi
  [ "$2:$3" = stop:client ] || fail 'wrong cleanup action'
  echo "cleanup $4" >> "$events";rm -f "$4" "$4.alive"
}
a_node=hy;b_node=hy;c_node=rust;items='a b c';load_acl
old_port=$(get_cache_var ACL_a_redir_port);old_socks=$(get_cache_var acl_node_hy_socks_port)
[ -n "$old_port" ] && [ "$(get_cache_var acl_node_hy_redir_port)" = "$old_port" ] || fail 'owner cache changed'
[ -f "$TMP_ACL_PATH/hy_SOCKS_\${old_socks}.json.alive" ] || fail 'owner killed'
[ "$(get_cache_var ACL_b_failed)" = 1 ] && [ -z "$(get_cache_var ACL_b_redir_port)" ] || fail 'failed ACL published'
! grep -q "cleanup $TMP_ACL_PATH/hy_SOCKS_\${old_socks}.json$" "$events" || fail 'wrong instance stopped'
grep 'nft .*ip protocol tcp' "$events" | grep -q ":$old_port" || fail 'owner TCP rule missing'
grep 'nft .*ip protocol udp' "$events" | grep -q ":$old_port" || fail 'owner UDP rule missing'
[ -n "$(get_cache_var ACL_c_redir_port)" ] || fail 'following other core skipped'
failed_port=$(awk '/^failed-port/{print $2}' "$events")
! grep 'nft .*protocol' "$events" | grep -q ":$failed_port" || fail 'failed forwarding retained'
failed_file=$(awk '/^cleanup/{print $2}' "$events")
[ ! -e "$failed_file" ] || fail 'failed config retained'
# A successful logged instance is reused; enabling logs needs only one new instance.
rm -rf "$TMP_PATH";mkdir -p "$TMP_ACL_PATH";: > "$events"
a_node=hy;b_node=hy;c_node=hy
runtime_fail=0
load_acl
[ "$(grep -c '^start$' "$events")" = 2 ] || fail 'logged instance unnecessarily duplicated'
[ "$(get_cache_var ACL_b_redir_port)" = "$(get_cache_var ACL_c_redir_port)" ] || fail 'logged instance not shared'
\`);
run('Full run_socks returns success for local endpoints without tail override', \`
\${func(app,'run_socks')}
eval_set_val() { local pair;for pair in "$@";do eval "$pair";done; }
config_n_get() { case "$2" in type) echo Hysteria;;address) echo 127.0.0.1;;port) echo 443;;esac; }
json_init() { :; };json_add_string() { :; };json_dump() { echo '{}'; }
gen_hysteria_config() { echo '{}' > "$2"; };start_hysteria() { echo launched >> "$events"; }
HYSTERIA_BIN=hysteria
check_host() { return 0; }
run_socks node=hy config_file=local.json bind=127.0.0.1 socks_port=1080 || fail 'local endpoint returned failure'
grep -q launched "$events" || fail 'actual startup branch skipped'
\`);
`.replace(/\\`/g,'`').replace(/\\\$\{func\(/g,'${func(');
// Escape only the nested template delimiters/interpolations used above.
fixture+=addition.replace(/\\`/g,'`').replace(/\\\$\{func\(/g,'${func(');
const Module=require('node:module');
const m=new Module(fixturePath,module);m.filename=fixturePath;m.paths=module.paths;m._compile(fixture,fixturePath);