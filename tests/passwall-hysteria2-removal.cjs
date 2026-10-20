// Execute production loaders and shell dispatchers with OS-boundary fixtures.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const Module = require('node:module');
const {lua, lauxlib, lualib, to_luastring, to_jsstring} = require('fengari');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, 'luci-app-passwall', p), 'utf8').replace(/\r\n/g, '\n');
for (const p of ['client/type/5_hysteria2.lua', 'server/type/5_hysteria2.lua']) {
  assert.ok(!fs.existsSync(path.join(root, 'luci-app-passwall/luasrc/model/cbi/passwall', p)));
}
assert.ok(!fs.existsSync(path.join(root, 'luci-app-passwall/luasrc/passwall/util_hysteria2.lua')));
const appSource = read('root/usr/share/passwall/app.sh');
assert.ok(!appSource.includes('UTIL_HYSTERIA2'));
assert.ok(!/\n\thysteria2\)/.test(appSource));
const L = lauxlib.luaL_newstate(); lualib.luaL_openlibs(L);
function run(code) {
  const status = lauxlib.luaL_dostring(L, to_luastring(code));
  assert.equal(status, lua.LUA_OK, status ? to_jsstring(lua.lua_tostring(L, -1)) : '');
}
for (const side of ['client', 'server']) {
  // Run the real loader, injecting both old filenames as if left on disk.
  const p = side === 'client' ? 'client/node_config.lua' : 'server/server_config.lua';
  run(`
local loaded = {}
local names = {'5_hysteria2.lua', '5_hysteria.lua', 'hysteria2.lua', '4_ss.lua', '1_sing-box.lua', 'sing-box.lua', '2_xray.lua', 'xray.lua'${side==='client'?", '0_socks.lua', 'socks.lua'":''}}
api = {appname='passwall',s_config='passwall_server',set_default_cbi=function() end,
 fs={dir=function() local i=0;return function() i=i+1;return names[i] end end},
 url=function() return '/' end, return_map=function(m) return m end}
require=function() return api end
arg={'test'};translate=function(v) return v end
luci={http={formvalue=function() end}}
Map=function() return {config='passwall',get=function() return {} end,appendTemplate=function() end,
 foreach=function() end,section=function() return {option=function() return {value=function() end} end} end} end
loadfile=function(p) loaded[#loaded+1]=p;return function() end end
setfenv=function(f) return f end; getfenv=function() return {} end
local function page()
${read('luasrc/model/cbi/passwall/' + p)}
end
page()
assert(#loaded==2)
for _,p in ipairs(loaded) do assert(not p:find('hysteria2',1,true)) end
`);
}
console.log('PASS real Client/Server type loaders ignore legacy Hysteria2 files; H1/SS remain loadable');
// The v1 pages themselves still register the same type, transports and CA field.
for (const side of ['client', 'server']) {
  run(`
local types, fields = {}, {}
api.finded_com=function() return true end
local function section()
 return {option=function(_,_,name)
  local field={option=name, values={},value=function(self,k) self.values[k]=true end,
   depends=function() end}
  fields[name]=field;return field
 end}
end
NamedSection=section
api.set_type_cbi=function() end;api.type_cbi_section=function() end
local parent={sectiontype='nodes',fields={type={value=function(_,name) types[name]=true end}},val={type='Hysteria'}}
local function page(...)
${read('luasrc/model/cbi/passwall/' + side + '/type/5_hysteria.lua')}
end
page({},parent)
assert(types.Hysteria and not types.Hysteria2)
assert(fields.protocol.values.udp and fields.protocol.values.faketcp and fields.protocol.values['wechat-video'])
${side === 'client' ? "assert(fields.ca)" : "assert(fields.tls_certificateFile and fields.tls_keyFile)"}
`);
}
console.log('PASS real v1 Client/Server pages register all three transports, CA and server certificates');
const apiSource = read('luasrc/passwall/api.lua');
run(`
uci_get_c=function() return '0' end
uci_foreach_c=function(_,fn)
 for _,node in ipairs({
  {type='Hysteria2',remarks='old',address='example.com',port='443'},
  {['.name']='hy',type='Hysteria',remarks='v1',address='example.com',port='443'},
  {type='Xray',protocol='hysteria2',remarks='embedded',address='example.com',port='443'}
 ,{type='sing-box',remarks='old',address='example.com',port='443'}
 ,{type='Socks',remarks='old',address='example.com',port='1080'}
 }) do fn(node) end
end
getmetatable('').__mod=function(fmt,args) return string.format(fmt,(unpack or table.unpack)(args)) end
trim=function(v) return v end;is_ip=function() return true end;is_ipv6=function() return false end
datatypes={hostname=function() return true end}
${apiSource.slice(apiSource.indexOf('function get_valid_nodes()'), apiSource.indexOf('function get_node_list()'))}
local nodes=get_valid_nodes()
assert(#nodes==1 and nodes[1].type=='Hysteria')
uci_get_c=function(id)
 if id=='service' then return {node='ss',autoswitch_backup_node={'xray','hy','sb','remote','hy'}} end
 if id=='@global_other[0]' then return '0' end
end
${apiSource.slice(apiSource.indexOf('function get_socks_backup_nodes('),apiSource.indexOf('function cleanEmptyTables('))}
assert(get_socks_backup_nodes('service')=='hy')
assert(get_socks_backup_nodes('missing')=='')
`);
console.log('PASS real valid-node selection rejects Hysteria2 and removed embedded cores');
run(`
local function components()
${read('luasrc/passwall/com.lua')}
end
local c=components()
assert(not c.hysteria2 and c.hysteria:get_url():match('/releases/tags/v1%.3%.5$'))
assert(c.hysteria.cmd_version:match('^%-%-version'))
assert(not c.xray and not c['sing-box'])
local com=c
uci_get_c=function() return '/custom/old-core' end
get_bin_version_cache=function() error('retired component version command executed') end
${apiSource.slice(apiSource.indexOf('function get_app_path('),apiSource.indexOf('function get_app_version('))}
${apiSource.slice(apiSource.indexOf('function get_app_version('),apiSource.indexOf('\nlocal function is_file',apiSource.indexOf('function get_app_version(')))}
assert(get_app_path('xray')==nil and get_app_path('sing-box')==nil)
assert(get_app_version('xray')==nil and get_app_version('sing-box')==nil)
`);
console.log('PASS real component registry only offers pinned Hysteria v1.3.5 and --version');
const fixturePath = path.join(__dirname, 'passwall-client-isolation.cjs');
let fixture = fs.readFileSync(fixturePath, 'utf8').split("run('cleanup preserves")[0];
const addition = String.raw`
run('retired Hysteria2: real SOCKS/global dispatch rejects before creating configs', \`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() { case "$1:$2" in old:type) echo Hysteria2;; embedded:type) echo Xray;;embedded:protocol) echo hysteria2;;*) config_original "$@";;esac; }
if check_node_supported embedded;then fail 'removed embedded core accepted';fi
eval_set_val() { eval "$*"; }
\${func(app,'run_socks')}
\${func(app,'start_global')}
if run_socks node=old bind=127.0.0.1 socks_port=1080 config_file=old.json;then fail 'retired SOCKS accepted';fi
NODE=old
if start_global;then fail 'retired global accepted';fi
[ ! -e "$TMP_PATH/old.json" ] || fail 'retired config created'
! grep -Eq '^process |^ipt2socks |^dns ' "$events" || fail 'retired process started'
\`);
run('retired Hysteria2 ACL: skip failed rule and continue valid TCP/UDP rules', \`
eval "$(declare -f config_n_get | sed '1s/config_n_get/config_original/')"
config_n_get() { case "$1:$2" in old:type) echo Hysteria2;;*) config_original "$@";;esac; }
items='a b c';a_node=good;b_node=old;c_node=rust
mkdir -p "$TMP_ACL_PATH/b";echo any > "$TMP_ACL_PATH/b/source_list"
set_cache_var ACL_b_node old;set_cache_var ACL_b_redir_port 19999
load_acl
[ "$(get_cache_var ACL_b_failed)" = 1 ] || fail 'failure not recorded'
[ -z "$(get_cache_var ACL_b_redir_port)" ] || fail 'retired ACL port published'
[ ! -d "$TMP_ACL_PATH/b" ] || fail 'retired ACL source list retained'
! grep '^nft .*19999' "$events" || fail 'retired ACL forwarded'
for id in a c;do
 port=$(get_cache_var "ACL_\${id}_redir_port")
 [ -n "$port" ] || fail 'valid neighbour skipped'
 grep 'nft .*ip protocol tcp' "$events" | grep -q ":$port" || fail 'valid TCP missing'
 grep 'nft .*ip protocol udp' "$events" | grep -q ":$port" || fail 'valid UDP missing'
done
\`);
`.replace(/\\`/g, '`').replace(/\\\$\{func\(/g, '${func(');
const mod = new Module(fixturePath, module);
mod.filename = fixturePath; mod.paths = module.paths;
mod._compile(fixture + addition, fixturePath);
