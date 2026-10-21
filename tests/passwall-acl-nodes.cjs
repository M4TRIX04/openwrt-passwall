// Native processes/sockets + actual B1/B2/B3.1 functions, cache API and generators.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
const app=read('luci-app-passwall/root/usr/share/passwall/app.sh'),utils=read('luci-app-passwall/root/usr/share/passwall/utils.sh');
function func(s,n){const start=s.indexOf('\n'+n+'() {')+1;assert(start>0,n);const rest=s.slice(start),end=rest.search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);return end<0?rest:rest.slice(0,end);}
for(const p of ['luci-app-passwall/root/usr/share/passwall/app.sh','luci-app-passwall/root/usr/share/passwall/nftables.sh',
 'luci-app-passwall/root/usr/share/passwall/iptables.sh','luci-app-passwall/root/etc/init.d/passwall'])
 assert(!/acl_nodes\.sh|passwall_(?:start|stop)_acl_nodes|passwall_acl_node_ready/.test(read(p)),'B3.1 activated: '+p);
const image=process.env.PASSWALL_B3_DOCKER;
if(!image){console.log('SKIP native B3.1 (set PASSWALL_B3_DOCKER to existing Alpine image)');process.exit(0);}
let script='set -e\napk add --no-cache lua5.1 lua5.1-cjson lua5.1-socket dnsmasq >&2\n';
const files={
 '/tmp/b2-api.lua':'tests/b2-api.lua',
 '/tmp/node_config.sh':'luci-app-passwall/root/usr/share/passwall/node_config.sh',
 '/tmp/global_nodes.sh':'luci-app-passwall/root/usr/share/passwall/global_nodes.sh',
 '/tmp/acl_nodes.sh':'luci-app-passwall/root/usr/share/passwall/acl_nodes.sh',
 '/tmp/util_shadowsocks.lua':'luci-app-passwall/luasrc/passwall/util_shadowsocks.lua',
 '/tmp/util_hysteria.lua':'luci-app-passwall/luasrc/passwall/util_hysteria.lua',
 '/tmp/hysteria_runtime.lua':'luci-app-passwall/luasrc/passwall/hysteria_runtime.lua',
 '/tmp/acl-listener.lua':'tests/acl-listener.lua'
};
let i=0;for(const [dest,src] of Object.entries(files)){const end='__B3_FILE_'+i+++'__';script+="cat > "+dest+" <<'"+end+"'\n"+read(src)+'\n'+end+'\n';}
const helpers=['shell_quote','del_cache_var','set_cache_var','set_cache_vars','get_cache_var','get_new_port','check_port_exists','get_process_start_time'].map(n=>func(utils,n)).join('\n')+'\n'+
 ['check_node_supported','gen_ss_config','gen_hysteria_config','start_hysteria'].map(n=>func(app,n)).join('\n');
const setup=read('tests/shell-global-nodes.sh').split('[ -z "${PW_B2_TRACE:-}" ] || set -x')[0];
assert(setup.includes('config_is()'));
script+=setup.replace('# PRODUCTION_HELPERS',()=>helpers)+read('tests/shell-acl-nodes.sh');
cp.execFileSync('docker',['run','--rm','--pull=never','--cap-add','SYS_PTRACE','-i','--env','PW_B3_TRACE','--entrypoint','/bin/ash',image],{input:script,stdio:['pipe','inherit','inherit']});
console.log('PASS inactive B3.1: native Lua 5.1 / actual processes and TCP/UDP socket ownership; proxy/xtables/lock boundaries remain fixtures');
