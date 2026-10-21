local json = require "cjson"
local contract = dofile('/tmp/endpoint_contract.lua')
local node
package.preload['luci.passwall.api'] = function() return {
	jsonc = {stringify=function(v) return json.encode(v) end, parse=json.decode}, uci_get_c=function() return node end,
	fs={access=function(p) return p=='/tmp/custom-ca' end},
	is_ipv6=function(s) return s:find(':',1,true)~=nil end,
	get_ipv6_only=function(s) return s end
} end
arg={}
dofile('/tmp/util_hysteria.lua'); dofile('/tmp/util_shadowsocks.lua')
local hy = package.loaded['luci.passwall.util_hysteria']
local ss = package.loaded['luci.passwall.util_shadowsocks']
local generation='generation.abc123';local digest=string.rep('a',32)
local function rejects(f) local ok=pcall(f);assert(not ok) end
local calls=0
local answers={{address='2001:db8::2'},{address='192.0.2.2'},{address='192.0.2.1'},{address='2001:0db8:0:0:0:0:0:2'}}
local function resolve(name) assert(name=='server.example');calls=calls+1;return answers end
local h={type='Hysteria', address='Server.Example',port='443', protocol='udp',
	hysteria_up_mbps='10',hysteria_down_mbps='20',tls_allowInsecure='0',
	hysteria_ca='/tmp/custom-ca',hysteria_obfs='secret-obfs',hysteria_auth_type='string',hysteria_auth_password='secret'}
for _,protocol in ipairs({'udp','faketcp','wechat-video'}) do
	h.protocol=protocol
	for _,preference in ipairs({'ipv4','ipv6','ipv4-only','ipv6-only'}) do
		local before=calls;local b=contract.bind(generation,digest,'hy',h,preference,resolve)
		assert(calls==before+1 and #b.addresses==3)
		assert(h.address=='Server.Example' and h.tls_serverName==nil)
		assert(b.generator_node.tls_serverName=='server.example')
		assert(contract.check(b,generation,digest,'hy',h) and calls==before+1)
		node=b.generator_node
		local config=json.decode(hy.gen_config({node='hy',local_tcp_redir_port='1041',local_udp_redir_port='1051',tcp_proxy_way='tproxy'}))
		local outer=contract.config(b,config)
		assert(outer[1]==(protocol=='faketcp' and 'tcp' or 'udp'))
		assert(config.ca==h.hysteria_ca and config.obfs==h.hysteria_obfs and not config.insecure and config.auth_str=='secret')
		rejects(function() contract.check(b,'generation.other',digest,'hy',h) end)
		rejects(function() contract.check(b,generation,string.rep('b',32),'hy',h) end)
		local receipt=contract.instance(b,'/tmp/instance/config.json',digest,123,456)
		assert(receipt.generation==generation and receipt.pid=='123' and receipt.state=='unverified')
		assert(contract.check_instance(receipt,b,'/tmp/instance/config.json',digest,123,456))
		rejects(function() contract.check_instance(receipt,b,'/tmp/old/config.json',digest,123,456) end)
		rejects(function() contract.check_instance(receipt,b,'/tmp/instance/config.json',digest,123,457) end)
		config.server='server.example:443';rejects(function() contract.config(b,config) end)
	end
end
h.tls_serverName='explicit.example'
local b=contract.bind(generation,digest,'hy',h,'ipv4',resolve)
assert(b.generator_node.tls_serverName=='explicit.example')
local changed=json.decode(json.encode(h));changed.hysteria_auth_password='changed'
rejects(function() contract.check(b,generation,digest,'hy',changed) end)
local shuffled={answers[4],answers[3],answers[2],answers[1]}
local ordered=contract.bind(generation,digest,'hy',h,'ipv4',function() return shuffled end)
assert(contract.check(ordered,generation,digest,'hy',h))
assert(ordered.address==b.address and #ordered.addresses==#b.addresses)
for i,v in ipairs(b.addresses) do assert(ordered.addresses[i].address==v.address and ordered.addresses[i].family==v.family) end
node=b.generator_node
local c=json.decode(hy.gen_config({node='hy',local_socks_port='1070'}));c.insecure=true
rejects(function() contract.config(b,c) end)
c.insecure=false;c.auth_str='changed';rejects(function() contract.config(b,c) end)
local base64=json.decode(json.encode(h));base64.hysteria_auth_type='base64';base64.hysteria_auth_password='YQBi'
base64.protocol='udp'
local binary_auth=contract.bind(generation,digest,'hy',base64,'ipv4',resolve)
node=binary_auth.generator_node
if pcall(require,'nixio') then
	assert(contract.config(binary_auth,json.decode(hy.gen_config({node='hy',local_socks_port='1070'})))[1]=='udp')
	print('PASS real generator/native nixio: Base64 authentication with embedded NUL preserved')
else
	assert(os.getenv('PASSWALL_EXPECT_NATIVE_NIXIO')~='1','native nixio required in identity fixture')
	print('SKIP native Base64 generator case here; run passwall-output-identity.cjs for native nixio coverage')
end
answers={{address='192.0.2.9'}}
local next_binding=contract.bind('generation.new',digest,'hy',h,'ipv4',resolve)
assert(next_binding.address=='192.0.2.9' and b.address=='192.0.2.1')
rejects(function() contract.check(next_binding,generation,digest,'hy',h) end)
for _,result in ipairs({{},{{address='not-an-ip'}},{{address='256.1.2.3'}},{{address=':::'}},{{address='2001:db8::1%eth0'}}}) do
	rejects(function() contract.bind(generation,digest,'hy',h,'ipv4',function() return result end) end)
end
rejects(function() contract.bind(generation,digest,'hy',h,'ipv6-only',resolve) end)
rejects(function() contract.bind(generation,digest,'hy',h,'ipv4',function() error('DNS failure') end) end)
for _,ip in ipairs({'127.0.0.1','2001:db8::1','[2001:db8::1]'}) do
	local s={type='SS',address=ip,port='8388',method='aes-128-gcm',password='secret'}
	for _,mode in ipairs({'tcp_only','udp_only','tcp_and_udp'}) do
		local binding=contract.bind(generation,digest,'ss',s,'ipv6',function() error('literal resolved') end)
		node=binding.generator_node
		local config=json.decode(ss.gen_config({node='ss',local_addr='0.0.0.0',local_port='1041',mode=mode}))
		local outer=contract.config(binding,config)
		assert(#outer==(mode=='tcp_and_udp' and 2 or 1))
		assert(outer[1]==(mode=='udp_only' and 'udp' or 'tcp'))
		config.server_port=8389;rejects(function() contract.config(binding,config) end)
	end
end
rejects(function() contract.bind(generation,digest,'hy',{type='Hysteria',address='::ffff:192.0.2.1',port='443'},'ipv6') end)
print('PASS native Lua 5.1: one resolution, A/AAAA preference/dedup, pinning, actual H1/SS generators, TLS/CA/obfs/auth, outer protocols and epoch isolation')
