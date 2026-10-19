// NODE_PATH must provide the existing validation tools: luaparse and fengari.
// Run: node tests/passwall-lite-manual.cjs
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const parser = require('luaparse');
const {lua, lauxlib, lualib, to_luastring, to_jsstring} = require('fengari');
const root = path.resolve(__dirname, '..', 'luci-app-passwall');
const read = p => fs.readFileSync(path.join(root, p), 'utf8').replace(/^#![^\n]*\n/, '');
let luaCount = 0, jsCount = 0;
function walk(dir) {
  for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (file.endsWith('.lua')) {
      parser.parse(fs.readFileSync(file, 'utf8'), {luaVersion: '5.1'});
      luaCount++;
    } else if (file.endsWith('.htm')) {
      const text = fs.readFileSync(file, 'utf8');
      for (const match of text.matchAll(/<script\b(?:<%[\s\S]*?%>|[^>])*?>([\s\S]*?)<\/script>/g)) {
        if (/type="text\/(?:html|template)"/.test(match[0].slice(0, match[0].indexOf('\n')))) continue;
        if (!match[1].trim()) continue;
        // Template branches can render mutually exclusive declarations. Check
        // the edited templates separately below, with each LuCI variant.
        if (!/node_list|node_config/.test(file)) continue;
        for (const jsLuci of [false, true]) {
          let script = match[1].replace(/<% if not api.is_js_luci\(\) then -%>([\s\S]*?)<% end -%>/g, (_, body) => jsLuci ? '' : body);
          script = script.replace(/<%[\s\S]*?%>/g, '');
          new vm.Script(script, {filename: file});
          jsCount++;
        }
      }
    }
  }
}
walk(root);
console.log(`PASS Lua 5.1 syntax: ${luaCount} files; node template JS: ${jsCount} variants`);
const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);
function run(code) {
  const status = lauxlib.luaL_dostring(L, to_luastring(code));
  assert.equal(status, lua.LUA_OK, lua.lua_isstring(L, -1) ? to_jsstring(lua.lua_tostring(L, -1)) : 'Lua failure');
}
run(`
local files, commands, rules = {}, {}, {}
local nodes = {}
local servers = {}
local api = {
  s_config='passwall_server', S_TMP_PATH='/tmp/etc/passwall_server',
  sys={call=function(cmd) table.insert(commands,cmd) end},
  jsonc={stringify=function(config) return config end, parse=function(config) return config end},
  uci={foreach=function(_,_,_,fn) for name,rule in pairs(rules) do rule['.name']=name; fn(rule) end end,
    delete=function(_,_,name) rules[name]=nil end,
    section=function(_,_,_,name) rules[name]={} end,
    set=function(_,_,name,key,value) rules[name][key]=value end},
  uci_save=function() end, remove=function() end,
  uci_get_c=function(id) return nodes[id] end,
  uci_get_s=function(id, key) if id=='@global[0]' then return '1' end return {password='server-secret'} end,
  uci_foreach_s=function(_, fn) for _,server in ipairs(servers) do fn(server) end end,
  is_ipv6=function(s) return s:find(':',1,true) ~= nil end,
  get_ipv6_only=function(s) return s:gsub('^%[',''):gsub('%]$','') end,
  get_app_path=function(name) return '/usr/bin/'..name end,
  base64Decode=function(s) return s end
}
local modules = {['luci.passwall.api']=api}
require=function(name) return assert(modules[name],name) end
module=function() end
arg={}
${read('luasrc/passwall/util_shadowsocks.lua')}
local ss = {gen_config=gen_config, gen_config_server=gen_config_server, validate_method=validate_method}
modules['luci.passwall.util_shadowsocks']=ss
for _,method in ipairs({'aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305'}) do
  nodes.test={type='SS',address='example.com',port='8388',password='secret',method=method,
    plugin='v2ray-plugin',plugin_opts='server;tls',plugin_enabled='1'}
  local config=ss.gen_config({node='test',local_addr='0.0.0.0',local_port='1041',mode='tcp_and_udp',tcp_tproxy=true,plugin_sh='/must-not-write'})
  assert(config.method==method and config.password=='secret' and config.mode=='tcp_and_udp' and config.tcp_tproxy)
  assert(config.plugin==nil and config.plugin_opts==nil)
  assert(plugin_sh==nil and plugin_bin==nil)
  local server=ss.gen_config_server({type='SS',user='user',port='8388',method=method,timeout='300'})
  assert(server.method==method and server.server_port==8388 and server.password=='server-secret')
end
for _,method in ipairs({'aes-128-cfb','2022-blake3-aes-128-gcm','chacha20-poly1305','',false}) do
  nodes.invalid={type='SS',address='example.com',port='8388',method=method}
  local ok,err=pcall(ss.gen_config,{node='invalid'})
  assert(not ok and err:find('unsupported or missing method',1,true))
  ok,err=pcall(ss.gen_config_server,{type='SS',method=method})
  assert(not ok and err:find('unsupported or missing method',1,true))
end
nodes.missing={type='SS',address='example.com',port='8388'}
assert(not pcall(ss.gen_config,{node='missing'}))
assert(not pcall(ss.gen_config_server,{type='SS'}))
nodes.rust={type='SS-Rust',address='example.com',port='8388',method='aes-128-gcm',plugin='obfs-local',plugin_opts='obfs=http'}
assert(ss.gen_config({node='rust'}).servers[1].plugin=='obfs-local')
ss.gen_config({node='test'})
assert(plugin_sh==nil and plugin_bin==nil)
nodes.ssr={type='SSR',address='example.com',port='8388',method='aes-128-cfb',protocol='origin',obfs='plain'}
assert(ss.gen_config({node='ssr'}).protocol=='origin')
${read('luasrc/passwall/util_hysteria2.lua')}
modules['luci.passwall.util_hysteria2']={gen_config=gen_config,gen_config_server=gen_config_server}
nodes.hy={type='Hysteria2',address='example.com',port='443',hysteria2_auth_password='secret'}
local client=gen_config({node='hy',local_socks_port='1070',local_redir_port='1041',tcp_proxy_way='redirect'})
assert(client.socks5 and client.tcpRedirect and client.udpTProxy and client.auth=='secret')
-- Run the entire real service dispatcher with in-memory filesystem/UCI stubs.
io.open=function(name, mode)
  return {write=function(_,value)
    if mode=='a' then files[name]=(files[name] or '')..value else files[name]=value end
  end,close=function() end}
end
servers={
 {['.name']='ss',enable='1',type='SS',remarks='ss',port='8388',method='aes-128-gcm',user='user',udp_forward='1',firewall_allow='1'},
 {['.name']='custom',enable='1',type='SS',remarks='custom',port='8389',custom='1',config_str={server_port=8389,method='aes-256-gcm',plugin='obfs-server',plugin_opts='obfs=http'}},
 {['.name']='hy',enable='1',type='Hysteria2',remarks='hy',port='443',firewall_allow='1'}
}
arg={'start'}
${read('luasrc/passwall/server_app.lua')}
assert(files['/tmp/etc/passwall_server/ss.json'].server_port==8388)
assert(files['/tmp/etc/passwall_server/custom.json'].plugin==nil)
assert(files['/tmp/etc/passwall_server/custom.json'].plugin_opts==nil)
assert(files['/tmp/etc/passwall_server/hy.json'].listen==':443')
local joined=table.concat(commands,string.char(10))
assert(joined:find('ss%-server %-c') and joined:find(' %-u'))
assert(joined:find('hysteria %-c .- server'))
assert(rules.passwall_server_ss.dest_port==8388 and rules.passwall_server_hy.dest_port==443)
arg={'stop'}
${read('luasrc/passwall/server_app.lua')}
assert(next(rules)==nil)
-- Invalid legacy UCI and custom JSON must not write configs, run commands,
-- or open firewall ports; a valid neighbour must still start.
files,commands,rules={},{},{}
servers={
 {['.name']='old_bad',enable='1',type='SS',remarks='bad',port='9001',method='aes-128-cfb',firewall_allow='1'},
 {['.name']='old_missing',enable='1',type='SS',remarks='missing',port='9002',firewall_allow='1'},
 {['.name']='json_bad',enable='1',type='SS',remarks='bad-json',port='9003',custom='1',config_str={method='none'},firewall_allow='1'},
 {['.name']='json_missing',enable='1',type='SS',remarks='missing-json',port='9004',custom='1',config_str={},firewall_allow='1'},
 {['.name']='json_invalid',enable='1',type='SS',remarks='invalid-json',port='9005',custom='1',config_str='invalid-json',firewall_allow='1'},
 {['.name']='good',enable='1',type='SS',remarks='good',port='9006',method='aes-256-gcm',user='user',firewall_allow='1'}
}
arg={'start'}
${read('luasrc/passwall/server_app.lua')}
for _,name in ipairs({'old_bad','old_missing','json_bad','json_missing','json_invalid'}) do
  assert(files['/tmp/etc/passwall_server/'..name..'.json']==nil)
  assert(rules['passwall_server_'..name]==nil)
  assert(files['/tmp/log/passwall_server.log']:find('SS server '..name..' rejected:',1,true))
  for _,command in ipairs(commands) do assert(not command:find('/'..name..'.json',1,true)) end
end
assert(files['/tmp/etc/passwall_server/good.json'] and rules.passwall_server_good)
assert(files['/tmp/log/passwall_server.log']:find('unsupported or missing method',1,true))
assert(files['/tmp/log/passwall_server.log']:find('invalid server JSON',1,true))
`);
console.log('PASS real SS/Hysteria generators and server start/stop, ports/firewall, legacy plugin isolation, Rust/SSR regression');
const controller=read('luasrc/controller/passwall.lua');
for (const name of ['node_subscribe','link_add_node','gen_client_config','subscribe_manual']) assert.ok(!controller.includes('function '+name+'('));
for (const name of ['node_config','server_config','add_node','update_config','server_update_config']) {
  assert.ok(controller.includes('"'+name+'"'), name);
}
for (const p of ['client/type/4_ss.lua','client/type/5_hysteria2.lua','server/type/4_ss.lua','server/type/5_hysteria2.lua']) assert.ok(fs.existsSync(path.join(root,'luasrc/model/cbi/passwall',p)));
assert.ok(!read('luasrc/model/cbi/passwall/client/type/4_ss.lua').includes('plugin'));
assert.ok(!read('luasrc/model/cbi/passwall/client/node_config.lua').includes('link_share'));
assert.ok(!read('luasrc/view/passwall/node_config/footer.htm').includes('fromUrl'));
console.log('PASS manual client/server routes/types retained; removed UI references absent');
for (const match of controller.matchAll(/(?<![.\w])call\("([^"]+)"\)/g)) assert.ok(controller.includes('function '+match[1]+'('), 'dangling handler '+match[1]);
for (const match of controller.matchAll(/cbi\(appname \..*?"(\/[^"\n]+)"/g)) assert.ok(fs.existsSync(path.join(root,'luasrc/model/cbi/passwall',match[1]+'.lua')), 'dangling CBI '+match[1]);
run(`
local data, saved, response = {}, 0, nil
local form = {group='private'}
api={gen_random_char=function() return 'manual' end,is_finded=function(bin) return bin=='ss-local' or bin=='ss-redir' end}
uci={section=function() data.manual={} end}
c_config='passwall'
http={formvalue=function(key) return form[key] end}
uci_set=function(id,key,value) data[id][key]=value end
uci_save=function() saved=saved+1 end
http_write_json=function(value) response=value end
http_write_json_ok=function() response=true end
http_write_json_error=function() error('save failed') end
jsonParse=function(value) return value end
${controller.slice(controller.indexOf('function update_config()'),controller.indexOf('function set_node()'))}
add_node()
assert(data.manual.type=='SS' and data.manual.group=='private' and saved==1)
form={id='manual',data={address='example.com',port='8388',method='aes-128-gcm',password='secret'}}
update_config()
assert(data.manual.address=='example.com' and data.manual.method=='aes-128-gcm' and saved==2 and response==true)
`);
const app=read('root/usr/share/passwall/app.sh');
const ssBlocks=[...app.matchAll(/\n\tss\)\n([\s\S]*?)\n\t;;/g)];
assert.equal(ssBlocks.length,2);
assert.ok(ssBlocks.every(m=>m[1].includes('tcp_and_udp') && !m[1].includes('plugin')));
assert.ok(ssBlocks[0][1].includes('ss-local') && ssBlocks[1][1].includes('ss-redir'));
assert.ok(ssBlocks.every(m=>m[1].includes('gen_ss_config "$(json_dump)" "$config_file" || return 1')));
console.log('PASS controller manual create/save, handler/CBI references, SS TCP/UDP startup paths');
