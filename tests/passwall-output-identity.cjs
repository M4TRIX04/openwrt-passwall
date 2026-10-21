// Linux socket + optional kernel counters in a disposable network namespace.
// No host networking, host firewall, proxy binary downloads or production hooks.
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
const image=process.env.PASSWALL_CONTRACT_NATIVE_DOCKER;assert(image,'Set PASSWALL_CONTRACT_NATIVE_DOCKER');
const api=read('luci-app-passwall/luasrc/passwall/api.lua');
const start=api.indexOf('function exec_call_as_gid('),end=api.indexOf('\nfunction ',start+1);assert(start>0&&end>start);
const launcher=`local nixio=require 'nixio'
require 'nixio.util'
local function trim(s) return (s:gsub('^%s+',''):gsub('%s+$','')) end
${api.slice(start,end)}
local command='python3 /tmp/output-identity.py child'
for i=2,#arg do assert(arg[i]:match('^[a-z0-9]+$'));command=command..' '..arg[i] end
local rc,out=exec_call_as_gid(command,tonumber(arg[1]));io.write(out);os.exit(rc)
`;
// Fixed test-only nixio source, built against native Lua 5.1; not an IPK/runtime dependency.
const sha='580b6b1d9ec3a79edb8e2a5a9c4700b9c320ff6a';
let script=`set -eu
apk add --no-cache build-base linux-headers lua5.1 lua5.1-dev lua5.1-cjson python3 nftables iptables ip6tables curl >/dev/null
curl -fsSL https://codeload.github.com/openwrt/luci/tar.gz/${sha} | tar -xz -C /tmp luci-${sha}/libs/luci-lib-nixio
cd /tmp/luci-${sha}/libs/luci-lib-nixio/src
make compile LUA_CFLAGS=-I/usr/include/lua5.1 FPIC=-fPIC NIXIO_LDFLAGS='-lm -ldl -shared' >/tmp/nixio-build.log 2>&1 || { cat /tmp/nixio-build.log;exit 1; }
mkdir -p /usr/lib/lua/5.1
cp nixio.so /usr/lib/lua/5.1/
mkdir -p /usr/share/lua/5.1/nixio
cp ../root/usr/lib/lua/nixio/*.lua /usr/share/lua/5.1/nixio/
echo 'TEST native nixio source ${sha}'
cat > /tmp/gid-launch.lua <<'__LAUNCHER__'
${launcher}
__LAUNCHER__
cat > /tmp/output-identity.py <<'__IDENTITY__'
${read('tests/output-identity.py')}
__IDENTITY__
cat > /tmp/endpoint_contract.lua <<'__ENDPOINT__'
${read('luci-app-passwall/luasrc/passwall/endpoint_contract.lua')}
__ENDPOINT__
lua5.1 - <<'__RESOLVER__'
local endpoint=dofile('/tmp/endpoint_contract.lua')
local node={type='SS',address='localhost',port='8388'}
for _,preference in ipairs({'ipv4-only','ipv6-only'}) do
 local binding=endpoint.bind('generation.native',string.rep('a',32),'ss',node,preference)
 assert(binding.family==(preference=='ipv4-only' and 4 or 6))
 assert(endpoint.check(binding,'generation.native',string.rep('a',32),'ss',node))
end
print('PASS production endpoint default resolver with native nixio.getaddrinfo and localhost A/AAAA')
__RESOLVER__
`;
for(const p of ['luci-app-passwall/luasrc/passwall/util_hysteria.lua','luci-app-passwall/luasrc/passwall/util_shadowsocks.lua','tests/endpoint-contract.lua']){
 script+="cat > /tmp/"+path.basename(p)+" <<'__NATIVE_FILE__'\n"+read(p)+'\n__NATIVE_FILE__\n';
}
script+=`PASSWALL_EXPECT_NATIVE_NIXIO=1 lua5.1 /tmp/endpoint-contract.lua
python3 /tmp/output-identity.py
`;
cp.execFileSync('docker',['run','--rm','--init','--pull=never','--cap-add','NET_ADMIN','--cap-add','NET_RAW','-i','--entrypoint','/bin/ash',image],{input:script,stdio:['pipe','inherit','inherit']});
