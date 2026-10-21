-- Listener-only executable fixture. No proxy logic is reimplemented here.
local socket, json = require 'socket', require 'cjson'
if arg[1]=='--version' then print('hysteria version v1.3.5');return end
local c, file, port, socks, tcp, udp, relay, redirect, v6 = {}, nil, nil, nil, true, true, false, false, false
for i=1,#arg do
 if arg[i]=='-c' then file=arg[i+1] end
 if arg[i]=='-l' then port=tonumber(arg[i+1]);relay=true end
 if arg[i]=='-p' then socks=tonumber(arg[i+1]) end
 if arg[i]=='-T' then udp=false end
 if arg[i]=='-U' then tcp=false end
 if arg[i]=='-R' then redirect=true end
 if arg[i]=='-B' then v6=true end
end
if file then local f=assert(io.open(file));c=json.decode(f:read('*a'));f:close() end
local f=assert(io.open(os.getenv('PW_CORE_EVENTS'),'a'));f:write(json.encode({file=file,relay=relay,tcp=tcp,udp=udp,socks=socks,redirect=redirect,v6=v6,args=arg})..'\n');f:close()
local remote=c.server or ''
if remote:match('^exit%.invalid') or (relay and io.open(os.getenv('PW_RELAY_FAIL'))) then os.exit(3) end
if remote:match('^stall%.invalid') then socket.sleep(30);return end
local handles, seen = {}, {}
local function listen(proto,p,family)
 if (remote:match('^tcp%-missing%.invalid') and proto=='tcp') or (remote:match('^udp%-missing%.invalid') and proto=='udp') then return end
 local key=proto..p..family;if seen[key] then return end;seen[key]=true
 local s=assert(socket[proto..(family==6 and '6' or '')]())
 s:setoption('reuseaddr',true)
 if family==6 then assert(s:setoption('ipv6-v6only',true)) end
 if proto=='tcp' then assert(s:bind(family==6 and '::' or '0.0.0.0',p));assert(s:listen(16))
 else assert(s:setsockname(family==6 and '::' or '0.0.0.0',p)) end
 handles[#handles+1]=s
end
if relay then
 if tcp then listen('tcp',port,4);if v6 then listen('tcp',port,6) end end
 if udp then listen('udp',port,4);if v6 then listen('udp',port,6) end end
elseif c.method then
 if c.mode~='udp_only' then listen('tcp',c.local_port,4) end
 if c.mode~='tcp_only' then listen('udp',c.local_port,4) end
else
 for _,k in ipairs({'redirect_tcp','tproxy_tcp','tproxy_udp','socks5','http'}) do
  if c[k] then local p=assert(tonumber(c[k].listen:match(':(%d+)$')));listen(k=='tproxy_udp' and 'udp' or 'tcp',p,c[k].listen:sub(1,1)=='[' and 6 or 4) end
 end
end
while true do socket.sleep(1) end
