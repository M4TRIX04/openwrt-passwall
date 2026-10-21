-- Isolated firewall command boundary. Never calls nft/xtables or a kernel API.
local json = require 'cjson'
local name = arg[1]; table.remove(arg, 1)
local path = assert(os.getenv('PW_FW_KERNEL'))
local function read(p) local f=io.open(p);if not f then return nil end;local s=f:read('*a');f:close();return s end
local state=json.decode(read(path) or '{}')
state.chains=state.chains or {}
local original=json.encode(state)
do local f=assert(io.open(path..'.audit','a'));f:write(name..' '..table.concat(arg,' ')..'\n');f:close() end
local function save() local f=assert(io.open(path,'w'));assert(f:write(json.encode(state)));assert(f:close()) end
local function fault(kind)
 local p=path..'.'..kind;local v=read(p);if not v then return false end
 local n=tonumber(v) or 1
 if n>1 then local f=assert(io.open(p,'w'));f:write(n-1);f:close();return false end
 return true
end
local function key(f,t,c) return f..'/'..t..'/'..c end
if name=='dump' then
 local ctx=assert(read(arg[2]..'/context'));local token=ctx:match('[^\n]+\n[^\n]+\n[^\n]+\n([^\n]+)')
 local way,ipv6=ctx:match('[^\n]+\n([^\n]+)\n([^\n]+)')
 print('FW_CASE '..json.encode({name=arg[1],token=token,chains=state.chains,way=way,ipv6=ipv6,backend=ctx:match('^[^\n]+')}));return
end
if name=='reset' then
 state={chains={['4/mangle/PSW_DNS']={'KEEP DNS SRV KMS'},['4/nat/PSW']={'KEEP LEGACY'},['6/mangle/EXTERNAL']={'KEEP EXTERNAL'}}};save();return
end
local family=name:match('^ip6') and '6' or '4'
local table_name='mangle'
for i,v in ipairs(arg) do if v=='-t' then table_name=arg[i+1] end end
local function listing(nft)
 if fault('query') then os.exit(2) end
 if nft then
  print('table inet passwall {')
  for k in pairs(state.chains) do if not k:find('PSW') and not k:find('EXTERNAL') then print(' chain '..k:match('[^/]+$')..' { }') end end
  print('}')
 else for k in pairs(state.chains) do if k:match('^'..family..'/'..table_name..'/') then print('-N '..k:match('[^/]+$')) end end end
end
if name=='nft' and arg[1]=='list' then listing(true);return end
for _,v in ipairs(arg) do if v=='-S' then listing(false);return end end
if (name=='nft' and (arg[1]:match('^flush ') or arg[1]:match('^delete '))) or arg[5]=='-F' or arg[5]=='-X' then
 if fault('delete') then os.exit(2) end
 if name=='nft' then
  local op,c=arg[1]:match('^(%w+) chain inet passwall ([%w]+)$');assert(op and c)
  for k in pairs(state.chains) do if k:match('/'..c..'$') then if op=='flush' then state.chains[k]={} else state.chains[k]=nil end end end
 else
  local op,c;for i,v in ipairs(arg) do if v=='-F' or v=='-X' then op=v;c=arg[i+1] end end
  assert(c);local k=key(family,table_name,c);assert(state.chains[k]);state.chains[k]=op=='-F' and {} or nil
 end
 save();return
end
local batch
if name=='nft' then assert(arg[1]=='-f');batch=assert(read(arg[2]))
else assert(name:match('restore$'));batch=io.read('*a') end
for line in batch:gmatch('[^\n]+') do
 if fault('apply') then
  -- One nft batch / one restore table is atomic in the normal model. Earlier
  -- successful restore invocations remain. .partial models an uncertain
  -- userspace/transport failure, deliberately requiring conservative cleanup.
  if not read(path..'.partial') then state=json.decode(original) end
  save();os.exit(2)
 end
 if name=='nft' then
  local c=line:match('^create chain inet passwall (%w+)$')
  if c then
   local f=c:sub(-1);local t=(c:match('[NR][46]$') and 'nat' or 'mangle');local k=key(f,t,c)
   assert(not state.chains[k],'chain collision');state.chains[k]={}
  else
   local c,rule=line:match('^add rule inet passwall (%w+) (.+)$');assert(c and rule,line)
   local k=key(c:sub(-1),c:match('[NR][46]$') and 'nat' or 'mangle',c)
   assert(state.chains[k]);assert(not rule:find('jump ') and not rule:find('hook '),'unexpected hook')
   state.chains[k][#state.chains[k]+1]=rule
  end
 else
  if line:sub(1,1)=='*' then table_name=line:sub(2)
  elseif line:sub(1,1)==':' then local c=assert(line:match('^:(%w+) %- %[0:0%]$'));local k=key(family,table_name,c);assert(not state.chains[k]);state.chains[k]={}
  elseif line~='COMMIT' then
   local c,rule=line:match('^%-A (%w+) (.+)$');assert(c and rule,line)
   assert(not (table_name=='nat' and rule:find('%-j DROP')),'DROP in nat')
   local k=key(family,table_name,c);assert(state.chains[k]);state.chains[k][#state.chains[k]+1]=rule
  end
 end
end
save()
local killpid=read(path..'.kill')
if killpid then
 assert(killpid:match('^%d+%s*$'));os.remove(path..'.kill')
 os.execute('kill -TERM '..killpid)
 os.execute('sleep 0.05')
end
