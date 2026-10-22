-- Native Linux adapter only: real nixio/UCI/files/processes/socket diagnostics.
-- The launcher functions below are extracted unchanged from production api.lua.
local root = assert(os.getenv("PW_BOUND_REPO"))
local nixio = require "nixio"
require "nixio.util"
local fs, json = require "nixio.fs", require "cjson"
local function quote(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function exec(s) local f=assert(io.popen(s)); local out=f:read('*a'); f:close(); return out end
local function call(s) return os.execute(s)/256 end
local function trim(s) return (s:gsub('^%s+',''):gsub('%s+$','')) end
local api = {fs=fs, DIRECT_GID=9911, jsonc={parse=function(s) local ok,v=pcall(json.decode,s); if ok then return v end end,
	stringify=function(v) return json.encode(v) end}, sys={exec=exec,call=call},
	is_ipv6=function(s) return s:find(':',1,true)~=nil end,
	get_ipv6_only=function(s) return s:gsub('^%[',''):gsub('%]$','') end,
	uci_get_c=function() error('BOUND TEST: live UCI generator read is forbidden') end}
api.md5_file=function(p) return exec('md5sum '..quote(p)):sub(1,32) end
api.md5_string=function(s)
	local path=trim(exec('mktemp /tmp/bound-md5.XXXXXX'))
	assert(fs.writefile(path,s)==#s); local d=api.md5_file(path); assert(fs.remove(path)); return d
end
local source=assert(fs.readfile(root..'/luci-app-passwall/luasrc/passwall/api.lua'))
for _,name in ipairs({'exec_call','exec_call_as_gid'}) do
	local start=assert(source:find('function '..name..'(',1,true))
	local last=assert(source:find('\nfunction ',start+1,true))
	local env={nixio=nixio,trim=trim};setmetatable(env,{__index=_G})
	local fn=assert(loadstring(source:sub(start,last-1)));setfenv(fn,env);fn();api[name]=env[name]
end
package.preload['luci.passwall.api']=function() return api end
package.preload['luci.util']=function() return {shellquote=quote} end
for _,name in ipairs({'endpoint_contract','util_hysteria','util_shadowsocks','hysteria_runtime','runtime_binding'}) do
	package.preload['luci.passwall.'..name]=function() return dofile(root..'/luci-app-passwall/luasrc/passwall/'..name..'.lua') end
end
local file=arg[1];table.remove(arg,1);arg[0]=file;dofile(file)
