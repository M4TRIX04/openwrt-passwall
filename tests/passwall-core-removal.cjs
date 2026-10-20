// Real LuCI pages are executed; filesystem/UCI/CBI widgets are boundary fixtures.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),cp=require('node:child_process'),Module=require('node:module');
const {lua,lauxlib,lualib,to_luastring:S,to_jsstring:J}=require('fengari');
const base=path.resolve(__dirname,'../luci-app-passwall');
const read=p=>fs.readFileSync(path.join(base,p),'utf8').replace(/\r\n/g,'\n');
for(const p of [
 'luasrc/model/cbi/passwall/client/type/0_socks.lua',
 'luasrc/model/cbi/passwall/client/type/1_sing-box.lua',
 'luasrc/model/cbi/passwall/client/type/2_xray.lua',
 'luasrc/model/cbi/passwall/server/type/1_sing-box.lua',
 'luasrc/model/cbi/passwall/server/type/2_xray.lua',
 'luasrc/passwall/util_xray.lua','luasrc/passwall/util_sing-box.lua',
 'luasrc/model/cbi/passwall/client/include/shunt_options.lua',
 'luasrc/model/cbi/passwall/client/shunt_rules.lua',
 'luasrc/view/passwall/rule/shunt_rule_list.htm','luasrc/view/passwall/include/node_change.htm'
]) assert.ok(!fs.existsSync(path.join(base,p)),p);
const makefile=read('Makefile'),appText=read('root/usr/share/passwall/app.sh');
assert.ok(!/select PACKAGE_(xray-core|sing-box)\b/.test(makefile));
assert.ok(makefile.includes('select PACKAGE_ipt2socks')&&makefile.includes('+dns2socks'));
assert.ok(!/util_xray|util_sing-box|run_xray|run_singbox/.test(appText));
assert.ok(appText.includes('run_ipt2socks flag=acl_')&&appText.includes('run_dns2socks flag=acl_'));
console.log('PASS removed implementation files/launchers absent; ipt2socks and dns2socks retained');
function run(code){const L=lauxlib.luaL_newstate();lualib.luaL_openlibs(L);
 const rc=lauxlib.luaL_dostring(L,S(code));assert.equal(rc,lua.LUA_OK,rc?J(lua.lua_tostring(L,-1)):'');}
for(const page of ['global','acl_config','socks_config'])run(`
local fields,sections={},{}
translate=function(v) return v end;translatef=string.format
local nodes={
 {id='ss',type='SS',remarks='ss',remark='SS',node_type='normal'},
 {id='hy',type='Hysteria',remarks='hy',remark='Hysteria',node_type='normal'}
}
local data={ss=nodes[1],hy=nodes[2],['@global[0]']={node='ss'},rule={node='hy'}}
data['@global_forwarding[0]']=setmetatable({},{__index=function() return 'disable' end})
arg={'rule'}
local function field(self,name)
 local f={option=name,values={},keylist={},dependencies={}}
 f.value=function(self,key) self.values[key]=true;self.keylist[#self.keylist+1]=key end
 f.depends=function(self,a,b) self.dependencies[#self.dependencies+1]={a,b} end
 f.formvalue=function() return nil end
 fields[name]=f;self.fields[name]=f;return f
end
local function section(_,class,id)
 local s={section=id,sectiontype=id,fields={},tab=function() end}
 s.option=function(self,_,name) return field(self,name) end
 s.taboption=function(self,_,_,name) return field(self,name) end
 sections[#sections+1]=s;return s
end
for _,name in ipairs({'NamedSection','TypedSection','Value','ListValue','Flag','DynamicList','DummyValue','HideValue','MultiValue'}) do _G[name]={} end
Map=function() return {
 config='passwall',get=function(_,id,key) local n=data[id];if not n then return nil end;if key then return n[key] end;return n end,
 section=section,appendTemplate=function() end,template_path=function(_,v) return v end,
 foreach=function(_,kind,fn)
  if kind=='socks' then fn({['.name']='socks_local',enabled='1',node='hy',port='1080'}) end
 end
} end
api={datatypes={},i18n={translate=translate},fs={access=function(p) return p:find('/rules/',1,true)~=nil end},
 set_default_cbi=function() end,get_valid_nodes=function() return nodes end,
 is_finded=function() return true end,finded_com=function() error('removed core detection still used') end,
 return_map=function(m) return m end,url=function(v) return v end,
 get_network_devices=function() return {} end,get_cache_var=function() end,
 sys={net={mac_hints=function() end}},jsonc={stringify=function() return '[]' end}
}
require=function() return api end
io.popen=function() return {read=function() return 'nft_redir nft_tproxy' end,close=function() end} end
local function page()
${read('luasrc/model/cbi/passwall/client/'+page+'.lua')}
end
page()
local main=sections[1].fields
assert(main.node.values.ss and main.node.values.hy)
${page==='socks_config'?`
assert(fields.port and fields.http_port and fields.enable_autoswitch)
local native_http=false
for _,d in ipairs(fields.http_port.dependencies) do
 assert(d[1].node~='ss')
 if d[1].node=='hy' then native_http=true end
end
assert(native_http,'Hysteria native HTTP hidden')
`:`
assert(not main.node.values.socks_local,'SOCKS service alias still selectable as a proxy node')
assert(fields.dns_shunt.values.dnsmasq and fields.dns_shunt.values['chinadns-ng'])
assert(not fields.dns_mode.values.xray and not fields.dns_mode.values['sing-box'])
assert(not fields.xray_dns_mode and not fields.singbox_dns_mode and not fields.remote_fakedns)
assert(fields.use_direct_list and fields.use_proxy_list and fields.use_block_list and fields.chn_list)
${page==='global'?"assert(fields.smartdns_dns_mode.values.socks and fields.smartdns_remote_dns and fields.smartdns_direct_dns)":"assert(fields.dns_mode.values.dns2socks)"}
`}
`);
console.log('PASS real global/ACL pages retain basic DNS, rules and SOCKS choices without core detection');

const dnsmasq=read('root/usr/share/passwall/helper_dnsmasq.lua');
run(`
local tinsert=table.insert
local lines={
 'domain=lan','local=/lan/','server=/lan/127.0.0.1#53',
 'server=/168.192.in-addr.arpa/127.0.0.1#53',
 'srv-host=_vlmcs._tcp.lan,kms.lan,1688,0,100',
 'address=/kms.lan/192.168.1.2','addn-hosts=/etc/hosts',
 'server=8.8.8.8','port=53','dhcp-range=192.168.1.100,192.168.1.200'
}
local sys={exec=function() return 'lan' end}
local fs={access=function() return true end}
io.lines=function() local i=0;return function() i=i+1;return lines[i] end end
${dnsmasq.slice(dnsmasq.indexOf('function copy_instance('),dnsmasq.indexOf('function add_rule('))}
local result=copy_instance({['-LISTEN_PORT']='11400',['-return']='1'})
local found={};for _,v in ipairs(result) do found[v]=true end
for i=1,7 do assert(found[lines[i]],'LAN DNS/SRV entry lost: '..lines[i]) end
assert(found['port=11400'] and not found['port=53'] and not found['server=8.8.8.8'])
`);
console.log('PASS real dnsmasq copy preserves LAN/reverse lookup, local hosts and KMS SRV');

// Reuse boundary fixtures, while executing the actual app/nftables functions.
const fixturePath=path.join(__dirname,'passwall-client-isolation.cjs');
const fixture=new Module(fixturePath,module);fixture.filename=fixturePath;fixture.paths=module.paths;
fixture._compile(fs.readFileSync(fixturePath,'utf8').split("run('cleanup preserves")[0]+'\nmodule.exports={common,func,app,nft};',fixturePath);
const {common,func,app}=fixture.exports;
const bash=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/bin/bash';
function shell(name,code){cp.execFileSync(bash,['-s'],{input:common+'\n'+code,stdio:['pipe','inherit','inherit']});console.log('PASS '+name);}
shell('mixed ACLs: removed nodes and retired DNS skip only their own TCP/UDP rules',String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() {
 case "$1:$2" in old:type) echo "$removed_type";;b:dns_mode) echo "$old_dns";;*) config_original "$@";;esac
}
for removed_type in Xray sing-box Socks; do
 for failure in node dns; do
  rm -f "$TMP_PATH"/key_*;: > "$events";ENABLED_ACLS=1
  items='a b c';a_node=good;c_node=rust;b_node=old;old_dns=dns2socks
  [ "$failure" != dns ] || { b_node=good;old_dns=$removed_type; }
  set_cache_var ACL_b_node old;set_cache_var ACL_b_redir_port 19999
  mkdir -p "$TMP_ACL_PATH/b";echo any > "$TMP_ACL_PATH/b/source_list"
  load_acl
  [ "$(get_cache_var ACL_b_failed)" = 1 ] || fail 'failure marker absent'
  [ -z "$(get_cache_var ACL_b_redir_port)" ] || fail 'failed ACL port published'
  [ ! -d "$TMP_ACL_PATH/b" ] || fail 'failed ACL directory retained'
  ! grep '^nft .*19999' "$events" || fail 'failed ACL forwarded'
  for id in a c;do
   port=$(get_cache_var "ACL_"$id"_redir_port")
   [ -n "$port" ] || fail 'valid ACL skipped'
   grep 'nft .*ip protocol tcp' "$events" | grep -q ":$port" || fail 'valid TCP missing'
   grep 'nft .*ip protocol udp' "$events" | grep -q ":$port" || fail 'valid UDP missing'
  done
 done
done
`);
shell('DNS validation keeps native backends and rejects retired modes',String.raw`
for shunt in dnsmasq chinadns-ng;do
 for mode in udp tcp dns2socks;do check_dns_config "$shunt" "$mode" global || fail 'valid global DNS rejected';done
 check_dns_config "$shunt" dns2socks acl || fail 'valid ACL DNS rejected'
done
check_dns_config smartdns socks global || fail 'SmartDNS SOCKS lost'
for mode in xray sing-box;do
 if check_dns_config dnsmasq "$mode" global;then fail 'retired global DNS accepted';fi
 if check_dns_config smartdns "$mode" global;then fail 'retired SmartDNS backend accepted';fi
done
`);

shell('real start: retired global DNS preserves independent SOCKS and valid ACLs; stop remains complete',
 ['start','stop','start_socks','start_global','run_socks'].map(n=>func(app,n)).join('\n')+String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() {
 case "$1:$2" in good:address) echo example.com;;good:port) echo 8388;;*) config_original "$@";;esac
}
eval_set_val() { eval "$*"; }
json_init() { :; };json_add_string() { :; };json_dump() { echo good; };check_host() { return 0; }
get_config() {
 ENABLED=1;SOCKS_ENABLED=1;ENABLED_ACLS=1;ENABLED_DEFAULT_ACL=1;NODE=good
 DNS_SHUNT=dnsmasq;DNS_MODE=$legacy_mode;REDIR_PORT=1041;REDIRECT_LIST=ss;TPROXY_LIST=ss
 : # Desired global state is published by start() after DNS succeeds.
}
start_haproxy() { :; };start_dns() { ACL_default_dns_port=11400;echo global-dns >> "$events"; }
start_crontab() { :; };stop_crontab() { echo cron-stop >> "$events"; }
clean_log() { :; };eval_cache_var() { :; };delete_ip2route() { echo route-cleanup >> "$events"; }
check_run_environment() { USE_TABLES=fw; }
busybox() { return 1; };xargs() { cat >/dev/null;echo process-cleanup >> "$events"; }
sysctl() { return 0; };logger() { :; };ulimit() { :; }
mkdir() { local dir;for dir in "$@";do case "$dir" in -p|/tmp/etc|/tmp/log) :;;*) command mkdir -p "$dir";;esac;done; }
printf 'case "$1" in start) load_acl;;stop) echo firewall-stop >> "$events";;esac\n' > "$APP_PATH/fw.sh"
export events
printf '#!/bin/sh\necho independent-socks >> "$events"\n' > "$APP_PATH/app.sh";chmod +x "$APP_PATH/app.sh"
items='a c';a_node=good;c_node=rust
for legacy_mode in xray sing-box tcp;do
 command mkdir -p "$TMP_PATH" "$TMP_ACL_PATH";: > "$events"
 start
 grep -q '^independent-socks$' "$events" || fail 'independent SOCKS not started'
 ! grep -q '^process-cleanup' "$events" || fail 'independent service stopped on invalid DNS'
 for id in a c;do
  port=$(get_cache_var "ACL_"$id"_redir_port")
  [ -n "$port" ] || fail 'valid ACL disabled by global DNS'
  grep 'nft .*ip protocol tcp' "$events" | grep -q ":$port" || fail 'valid TCP ACL missing'
  grep 'nft .*ip protocol udp' "$events" | grep -q ":$port" || fail 'valid UDP ACL missing'
 done
 if [ "$legacy_mode" = tcp ];then
  [ "$(get_cache_var ACL_GLOBAL_redir_port)" = 1041 ] || fail 'valid global did not publish port'
  grep -q '^global-dns$' "$events" || fail 'valid global DNS missing'
 else
  [ -z "$(get_cache_var ACL_GLOBAL_redir_port)" ] || fail 'invalid global port retained'
  [ "$(get_cache_var ACL_GLOBAL_failed)" = 1 ] || fail 'invalid global not marked'
  ! grep -q '^global-dns$' "$events" || fail 'retired DNS was started'
  ! grep '^nft ' "$events" | grep -q ':1041' || fail 'invalid global port forwarded'
 fi
 (stop)
 [ ! -d "$TMP_PATH" ] || fail 'stop retained runtime state'
 grep -q '^process-cleanup' "$events" && grep -q '^firewall-stop' "$events" || fail 'stop skipped shared cleanup'
done
`);

shell('real run_socks: native SS retained and removed HTTP conversion not launched',func(app,'run_socks')+String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() { case "$1:$2" in good:address) echo example.com;;good:port) echo 8388;;*) config_original "$@";;esac; }
eval_set_val() { eval "$*"; };json_init() { :; };json_add_string() { :; };json_dump() { echo good; };check_host() { return 0; }
run_socks node=good bind=127.0.0.1 socks_port=1080 http_port=8080 config_file=ss.json http_config_file=ss_http.json || fail 'native SS SOCKS rejected'
test -f "$TMP_PATH/ss.json" || fail 'native SS config missing'
grep -q '^process ss-local ' "$events" || fail 'ss-local not launched'
grep -q 'HTTP conversion has been removed' "$events" || fail 'legacy HTTP not diagnosed'
test ! -f "$TMP_PATH/ss_http.json" || fail 'removed HTTP converter configured'
`);

shell('real start_dns/dns2socks uses native node listener and preserves LAN upstream',
 ['get_direct_dns_mode','start_dns','run_dns2socks'].map(n=>func(app,n)).join('\n')+String.raw`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() { case "$1:$2" in @global*:socks_server) echo "$legacy_socks";;*) config_original "$@";;esac; }
eval_set_val() { eval "$*"; };format_dns() { echo "$1"; }
lua() { echo "lua $*" >> "$events"; }
items=;DNS_SHUNT=dnsmasq;DNS_MODE=dns2socks;DNS_REDIRECT=1;NEXT_DNS_LISTEN_PORT=15353
GLOBAL_SOCKS_server=127.0.0.1:1070;REMOTE_DNS='1.1.1.1#53';DNS_CACHE=0;USE_DEFAULT_DNS=direct
LOCAL_DNS=192.168.1.1;DEFAULT_DNS=192.168.1.1
start_dns || fail 'valid native DNS failed'
grep '^process dns2socks ' "$events" | grep -q '127.0.0.1:1070' || fail 'DNS did not use native SOCKS'
grep 'helper_dnsmasq.lua add_rule' "$events" | grep -q -- '-LOCAL_DNS 192.168.1.1#53' || fail 'LAN DNS upstream changed'
legacy_socks=198.51.100.1:1080;: > "$events"
if start_dns;then fail 'legacy external SOCKS DNS silently accepted';fi
! grep '^process ' "$events" || fail 'legacy external SOCKS DNS started a process'
grep -q 'legacy socks_server=' "$events" || fail 'legacy SOCKS DNS diagnostic absent'
`);
