// Executes real B2 shell, cache API, generators and Hysteria manager in native Lua.
// Optional isolated test dependencies only: lua5.1, cjson, dnsmasq in a disposable Alpine container.
// PASSWALL_B2_DOCKER=doocs/md:latest node tests/passwall-global-nodes.cjs
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
const app=read('luci-app-passwall/root/usr/share/passwall/app.sh');
const utils=read('luci-app-passwall/root/usr/share/passwall/utils.sh');
function func(s,n){const start=s.indexOf('\n'+n+'() {')+1;assert(start>0,n);const r=s.slice(start),end=r.search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);return end<0?r:r.slice(0,end);}
assert(!/global_nodes\.sh|passwall_(?:start|stop)_global_nodes/.test(app),'B2 activated');
for(const p of ['luci-app-passwall/root/usr/share/passwall/nftables.sh','luci-app-passwall/root/usr/share/passwall/iptables.sh',
 'luci-app-passwall/root/etc/init.d/passwall'])assert(!/global_nodes\.sh|passwall_(?:start|stop)_global_nodes/.test(read(p)),p);
const image=process.env.PASSWALL_B2_DOCKER;
const container=process.env.PASSWALL_B2_CONTAINER;
if(!image&&!container){console.log('SKIP native B2 integration (set PASSWALL_B2_DOCKER or prepared PASSWALL_B2_CONTAINER)');process.exit(0);}
let script=container?'set -e\n':'set -e\napk add --no-cache lua5.1 lua5.1-cjson dnsmasq >&2\n';
const files={
 '/tmp/b2-api.lua':'tests/b2-api.lua',
 '/tmp/global_nodes.sh':'luci-app-passwall/root/usr/share/passwall/global_nodes.sh',
 '/tmp/node_config.sh':'luci-app-passwall/root/usr/share/passwall/node_config.sh',
 '/tmp/util_shadowsocks.lua':'luci-app-passwall/luasrc/passwall/util_shadowsocks.lua',
 '/tmp/util_hysteria.lua':'luci-app-passwall/luasrc/passwall/util_hysteria.lua',
 '/tmp/hysteria_runtime.lua':'luci-app-passwall/luasrc/passwall/hysteria_runtime.lua'
};
let i=0;for(const [dest,src]of Object.entries(files)){const end='__B2_FILE_'+i+++'__';script+="cat > "+dest+" <<'"+end+"'\n"+read(src)+'\n'+end+'\n';}
const helpers=['shell_quote','del_cache_var','set_cache_var','set_cache_vars','get_cache_var','get_new_port','check_port_exists','get_process_start_time'].map(n=>func(utils,n)).join('\n')+'\n'+
 ['check_node_supported','gen_ss_config','gen_hysteria_config','start_hysteria'].map(n=>func(app,n)).join('\n');
script+=read('tests/shell-global-nodes.sh').replace('# PRODUCTION_HELPERS',()=>helpers);
// dnsmasq hardens /proc inspection; this capability stays inside the test PID namespace.
if(container){
 assert(/^[a-f0-9]{64}$/.test(container),'full task-owned container ID required');
 const info=JSON.parse(cp.execFileSync('docker',['inspect',container],{encoding:'utf8'}))[0];
 assert(!['host','container'].some(x=>info.HostConfig.NetworkMode.startsWith(x))&&!info.HostConfig.PidMode&&!info.HostConfig.Privileged);
 assert(info.Mounts.length===1&&info.Mounts[0].Destination==='/workspace'&&!info.Mounts[0].RW);
 cp.execFileSync('docker',['exec','-i',container,'/bin/ash'],{input:script,stdio:['pipe','inherit','inherit']});
}else cp.execFileSync('docker',['run','--rm','--pull=never','--cap-add','SYS_PTRACE','-i','--env','PW_B2_TRACE','--entrypoint','/bin/ash',image],{input:script,stdio:['pipe','inherit','inherit']});
console.log('PASS inactive B2 integration: native Lua + real process/socket ownership; DNSMASQ is a listener fixture, not a proxy core');
