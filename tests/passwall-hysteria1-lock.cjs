// Uses production runtime with real Lua 5.1/nixio kernel locks in disposable Linux.
const cp=require('node:child_process'),path=require('node:path');
const image=process.env.PASSWALL_NATIVE_LUA_DOCKER;
if(!image) throw Error('Set PASSWALL_NATIVE_LUA_DOCKER to an Alpine image; this test requires real nixio.');
const script=String.raw`
set -eu
apk add --no-cache build-base linux-headers lua5.1-dev lua5.1-cjson curl >/dev/null
curl -fsSL https://codeload.github.com/openwrt/luci/tar.gz/refs/heads/master | tar -xz -C /tmp luci-master/libs/luci-lib-nixio
cd /tmp/luci-master/libs/luci-lib-nixio/src
make compile LUA_CFLAGS=-I/usr/include/lua5.1 FPIC=-fPIC NIXIO_LDFLAGS='-lm -ldl -shared' >/tmp/build.log 2>&1 || { cat /tmp/build.log;exit 1; }
cp nixio.so /usr/lib/lua/5.1/
mkdir -p /usr/share/lua/5.1/nixio
cp ../root/usr/lib/lua/nixio/*.lua /usr/share/lua/5.1/nixio/
cat >/tmp/worker.lua <<'LUA'
local nixio=require 'nixio'
local fs=require 'nixio.fs'
local json=require 'cjson'
package.preload['luci.passwall.api']=function() return {
 fs=fs,jsonc={parse=json.decode,stringify=function(v) return json.encode(v) end},sys={call=function(s) return os.execute(s)/256 end},
 is_ipv6=function() return false end,
 uci_get_c=function() return {address='127.0.0.1',port='443',hysteria_up_mbps='10',hysteria_down_mbps='20',hysteria_auth_type='base64',hysteria_auth_password='YQBi'} end,
 base64Decode=function(s) return nixio.bin.b64decode(s):gsub('%z','') end
} end
package.preload['luci.util']=function() return {shellquote=function(s) return "'"..s.."'" end} end
local runtime='/workspace/luci-app-passwall/luasrc/passwall/hysteria_runtime.lua'
local mode=arg[1];arg={};dofile(runtime)
if mode=='hold' then
 -- Enter the real locked() function, stopping inside the critical section.
 local first=true;local original=fs.dir
 fs.dir=function(p)
  if first and p=='/tmp/etc/passwall_hysteria1' then
   first=false;fs.writefile('/tmp/held','ready');nixio.nanosleep(40)
  end
  return original(p)
 end
end
local manager=package.loaded['luci.passwall.hysteria_runtime']
if mode=='start' then
 local ok,err=pcall(manager.start,{mode='invalid',scope='client'})
 assert(not ok and tostring(err):find('invalid Hysteria mode',1,true))
else manager.stop('client') end
dofile('/workspace/luci-app-passwall/luasrc/passwall/util_hysteria.lua')
local generated=package.loaded['luci.passwall.util_hysteria'].gen_config({node='n',local_socks_port='1080'})
assert(json.decode(generated).auth=='YQBi')
LUA
mkdir -p /tmp/etc/passwall_hysteria1/lock
# Interrupted legacy mkdir initialization must not prevent the new kernel lock.
lua5.1 /tmp/worker.lua normal
lua5.1 /tmp/worker.lua hold & holder=$!
while [ ! -f /tmp/held ]; do kill -0 "$holder";sleep .05;done
# The competing production call must time out and must not steal the live lock.
if lua5.1 /tmp/worker.lua normal >/tmp/contender.out 2>&1;then exit 1;fi
grep -q 'registry is busy' /tmp/contender.out
kill -0 "$holder"
# SIGKILL must release the kernel lock without manual directory cleanup.
kill -9 "$holder";wait "$holder" 2>/dev/null || :
lua5.1 /tmp/worker.lua normal
# Concurrent start/stop callers serialize using the same stable inode.
pids=''
for mode in normal start normal start normal start;do
 lua5.1 /tmp/worker.lua "$mode" & pids="$pids $!"
done
for child in $pids;do wait "$child";done
lua5.1 -e 'local n=require("nixio");assert(n.bin.b64decode("AA==")==string.char(0));assert(n.bin.b64encode("a"..string.char(0).."b")=="YQBi")'
echo 'PASS real nixio: legacy stale directory, active lock, SIGKILL recovery, concurrent cleanup, binary Base64'
`;
cp.execFileSync('docker',['run','--rm','-i','--entrypoint','/bin/sh','--mount',`type=bind,source=${path.resolve(__dirname,'..')},target=/workspace,readonly`,image],{input:script,stdio:['pipe','inherit','inherit']});
