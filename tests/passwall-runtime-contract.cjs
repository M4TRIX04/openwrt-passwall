// Execute new production helpers; OS/core identities are tested separately.
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
const image=process.env.PASSWALL_CONTRACT_NATIVE_DOCKER,uci=process.env.PASSWALL_UCI_DOCKER;
assert(image&&uci,'Set PASSWALL_CONTRACT_NATIVE_DOCKER and PASSWALL_UCI_DOCKER');
const snapshot='luci-app-passwall/root/usr/share/passwall/runtime_snapshot.sh';
for(const f of ['app.sh','nftables.sh','iptables.sh'])assert(!/runtime_snapshot|endpoint_contract/.test(read('luci-app-passwall/root/usr/share/passwall/'+f)),f);
let script=read('tests/shell-runtime-snapshot.sh').replace('# PRODUCTION_HELPERS',()=>read('luci-app-passwall/root/usr/share/passwall/node_config.sh')+'\n'+read(snapshot));
cp.execFileSync('docker',['run','--rm','--pull=never','--network','none','-i','--entrypoint','/bin/ash',uci],{input:script,stdio:['pipe','inherit','inherit']});
script='set -e\napk add --no-cache lua5.1 lua5.1-cjson >/dev/null\n';
for(const p of ['luci-app-passwall/luasrc/passwall/endpoint_contract.lua','luci-app-passwall/luasrc/passwall/util_hysteria.lua','luci-app-passwall/luasrc/passwall/util_shadowsocks.lua','tests/endpoint-contract.lua']){
 script+="cat > /tmp/"+path.basename(p)+" <<'__CONTRACT_FILE__'\n"+read(p)+'\n__CONTRACT_FILE__\n';
}
script+='lua5.1 /tmp/endpoint-contract.lua\n';
cp.execFileSync('docker',['run','--rm','--pull=never','-i','--entrypoint','/bin/ash',image],{input:script,stdio:['pipe','inherit','inherit']});
console.log('PASS B3.3-1 contract helpers remain outside production startup/firewall/DNS');
