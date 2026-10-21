-- OS adapters for native Lua tests. Production generators/runtime are unmodified.
-- Real files, processes and sockets; nixio lock is a serialized-test boundary.
local json = require 'cjson'
local function quote(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function call(s) return os.execute(s) / 256 end
local function exec(s) local f=assert(io.popen(s));local v=f:read('*a');f:close();return v end
local function read(p) local f=io.open(p,'rb');if not f then return nil end;local s=f:read('*a');f:close();return s end
local fs = {
 access=function(p) return call('[ -e '..quote(p)..' ]')==0 end,
 readfile=read,
 writefile=function(p,s) local f=io.open(p,'wb');if not f then return nil end;local ok=f:write(s);f:close();return ok and #s end,
 rename=os.rename, remove=os.remove,
 symlink=function(a,b) return call('ln -s '..quote(a)..' '..quote(b))==0 end,
 readlink=function(p) return exec('readlink '..quote(p)..' 2>/dev/null'):gsub('\n$','') end,
 dir=function(p) local f=assert(io.popen('ls -1 '..quote(p)..' 2>/dev/null'));return function() local n=f:read('*l');if not n then f:close() end;return n end end
}
package.preload['luci.passwall.api']=function() return {
 fs=fs,jsonc={parse=function(s) local ok,v=pcall(json.decode,s);if ok then return v end end,stringify=function(v) return json.encode(v) end},
 sys={call=call,exec=exec}, md5_string=function(s) return (s:gsub('[^%w]','_')) end,
 uci_get_c=function(id) return json.decode(assert(read(os.getenv('PW_TEST_NODES'))))[id] end,
 is_ipv6=function(s) return s:find(':',1,true)~=nil end,
 get_ipv6_only=function(s) return s:gsub('^%[',''):gsub('%]$','') end
} end
package.preload['luci.util']=function() return {shellquote=quote} end
package.preload.nixio=function() return {
 open=function() return {lock=function() return true end,close=function() end} end,
 nanosleep=function() call('sleep 0.01') end,
 getaddrinfo=function(host) if host:match('^[%x%.:]+$') then return {{address=host}} end end
} end
local file=arg[1]
table.remove(arg,1);arg[0]=file
dofile(file)
