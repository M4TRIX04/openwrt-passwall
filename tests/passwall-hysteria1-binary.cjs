// Optional real v1.3.5 integration smoke test, in a disposable network namespace.
// No host ports/network namespace or workspace writes. Requires Docker approval.
const cp=require('node:child_process');
const path=require('node:path');
if(!process.env.PASSWALL_HYSTERIA_BINARY_DOCKER){
 console.log('SKIP official Hysteria binary smoke test (set PASSWALL_HYSTERIA_BINARY_DOCKER)');process.exit(0);
}
const script=String.raw`
set -eu
apk add --no-cache lua5.1 lua5.1-cjson openssl curl iptables ip6tables nodejs >/dev/null
wget -q -T 30 -O /tmp/hysteria https://github.com/HyNetworks/hysteria/releases/download/v1.3.5/hysteria-linux-amd64
chmod +x /tmp/hysteria
/tmp/hysteria --version
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key -out /tmp/cert -days 1 -subj /CN=localhost >/dev/null 2>&1
cat > /tmp/generate.lua <<'LUA'
local protocol, auth = arg[1], arg[2]
arg={}
package.path='/workspace/luci-app-passwall/luasrc/?.lua;'..package.path
local cjson=require 'cjson'
-- Binary smoke test only uses the literal 'secret'; raw byte behavior is
-- separately covered with the real nixio module by passwall-hysteria1-lock.
package.preload['nixio']=function() return {bin={
 b64decode=function(s) return s=='c2VjcmV0' and 'secret' or '' end,
 b64encode=function(s) return s=='secret' and 'c2VjcmV0' or '' end
}} end
local node={type='Hysteria',protocol=protocol,address='127.0.0.1',port='34443',
 hysteria_auth_type='string',hysteria_auth_password='secret',hysteria_up_mbps='10',hysteria_down_mbps='50',
 tls_allowInsecure='1',tls_certificateFile='/tmp/cert',tls_keyFile='/tmp/key'}
package.preload['luci.passwall.api']=function() return {
 jsonc={stringify=function(c) return cjson.encode(c) end,parse=cjson.decode},uci_get_c=function() return node end,
 fs={access=function(p) local f=io.open(p);if f then f:close();return true end;return false end},
 is_ipv6=function(s) return s:find(':',1,true)~=nil end,
 base64Decode=function(s) return s=='c2VjcmV0' and 'secret' or '' end,
 base64Encode=function(s) return s=='secret' and 'c2VjcmV0' or '' end
} end
dofile('/workspace/luci-app-passwall/luasrc/passwall/util_hysteria.lua')
local hy=require 'luci.passwall.util_hysteria'
local f=assert(io.open('/tmp/server.json','w'));f:write(cjson.encode(hy.gen_config_server(node)));f:close()
if auth=='base64' then node.hysteria_auth_type='base64';node.hysteria_auth_password='c2VjcmV0'
elseif auth=='wrong' then node.hysteria_auth_password='wrong-password' end
local f=assert(io.open('/tmp/client.json','w'));f:write(hy.gen_config({node='node',local_socks_port='18081',local_http_port='18082',local_redir_port='18084',tcp_proxy_way='tproxy',proxy_ipv6='1'}));f:close()
LUA
node -e 'require("http").createServer((q,s)=>s.end("hysteria-smoke-ok")).listen(18080,"127.0.0.1");const u=require("dgram").createSocket("udp4");u.on("message",(m,r)=>u.send(m,r.port,r.address));u.bind(18083,"127.0.0.1")' & web=$!
cat >/tmp/udp.cjs <<'JS'
const net=require('net'),dgram=require('dgram'),assert=require('assert');
const t=net.connect(18081,'127.0.0.1');let data=Buffer.alloc(0),state=0;
const timer=setTimeout(()=>{console.error('SOCKS UDP timeout');process.exit(1)},5000);
t.on('error',e=>{throw e});t.on('connect',()=>t.write(Buffer.from([5,1,0])));
t.on('data',b=>{
 data=Buffer.concat([data,b]);
 if(state===0&&data.length>=2){assert.deepEqual([...data.subarray(0,2)],[5,0]);data=data.subarray(2);state=1;t.write(Buffer.from([5,3,0,1,0,0,0,0,0,0]));}
 if(state===1&&data.length>=10){
  assert.equal(data[1],0);assert.equal(data[3],1);state=2;
  const port=data.readUInt16BE(8),u=dgram.createSocket('udp4');
  u.on('message',m=>{assert.equal(m.subarray(-12).toString(),'udp-smoke-ok');clearTimeout(timer);u.close();t.end();});
  u.send(Buffer.concat([Buffer.from([0,0,0,1,127,0,0,1,70,163]),Buffer.from('udp-smoke-ok')]),port,'127.0.0.1');
 }
});
JS
server=;client=
cleanup() { kill $client $server $web 2>/dev/null || :; }
trap cleanup EXIT
for protocol in udp wechat-video faketcp; do
 for auth in string base64; do
  lua5.1 /tmp/generate.lua "$protocol" "$auth"
  /tmp/hysteria --no-check -c /tmp/server.json server >/tmp/server.log 2>&1 & server=$!
  sleep 1
  /tmp/hysteria --no-check -c /tmp/client.json client >/tmp/client.log 2>&1 & client=$!
  ok=0
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
   if curl -fsS --max-time 2 --noproxy '' --socks5-hostname 127.0.0.1:18081 http://127.0.0.1:18080/ | grep -q hysteria-smoke-ok;then ok=1;break;fi
   sleep 1
  done
  if [ "$ok" != 1 ];then cat /tmp/server.log /tmp/client.log;exit 1;fi
  curl -fsS --max-time 3 --noproxy '' --proxy http://127.0.0.1:18082 http://127.0.0.1:18080/ | grep -q hysteria-smoke-ok
  node /tmp/udp.cjs
  kill "$client" "$server";wait "$client" 2>/dev/null || :;wait "$server" 2>/dev/null || :
  client=;server=
  echo "PASS official v1.3.5 $protocol Client/Server $auth auth SOCKS/HTTP TCP + SOCKS UDP"
 done
done
lua5.1 /tmp/generate.lua udp wrong
/tmp/hysteria --no-check -c /tmp/server.json server >/tmp/server.log 2>&1 & server=$!
/tmp/hysteria --no-check -c /tmp/client.json client >/tmp/client.log 2>&1 & client=$!
sleep 2
if curl -fsS --max-time 2 --noproxy '' --socks5-hostname 127.0.0.1:18081 http://127.0.0.1:18080/;then exit 1;fi
grep -qi 'auth\|password' /tmp/client.log
echo 'PASS official v1.3.5 wrong password rejected'
`;
cp.execFileSync('docker',['run','--rm','-i','--cap-add=NET_ADMIN','--entrypoint','/bin/sh',
 '--mount',`type=bind,source=${path.resolve(__dirname,'..')},target=/workspace,readonly`,
 process.env.PASSWALL_HYSTERIA_BINARY_DOCKER,'-s'],{input:script,stdio:['pipe','inherit','inherit']});
