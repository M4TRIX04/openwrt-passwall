-- Small, instance-scoped launcher for Hysteria 1; other cores keep their launcher.
module("luci.passwall.hysteria_runtime", package.seeall)
local api = require "luci.passwall.api"
local fs = api.fs
local json = api.jsonc
local nixio = require "nixio"
local quote = require("luci.util").shellquote
local registry = "/tmp/etc/passwall_hysteria1"
local function call(s) return api.sys.call(s) == 0 end
local function read(p) return fs.readfile(p) end
local function write(p, s)
 assert(fs.writefile(p .. ".new", s), "Hysteria 1: cannot write " .. p)
 assert(fs.rename(p .. ".new", p), "Hysteria 1: cannot publish " .. p)
end
local function identity(pid)
	local s = read("/proc/" .. tostring(pid) .. "/stat")
	if not s then return nil end
	local rest = s:match("^%d+ %b() (.*)")
	local fields = {}; for v in (rest or ""):gmatch("%S+") do fields[#fields+1] = v end
	if fields[1] == "Z" then return nil end
	return fields[20]
end
local function alive(r) return r.pid and r.birth and identity(r.pid) == r.birth end
local function entries()
	local t = {}
	for name in fs.dir(registry) do
		if name:match("%.json$") then
			local r = json.parse(read(registry .. "/" .. name) or "")
			if r then t[#t+1] = {path=registry .. "/" .. name, value=r} end
		end
	end
	return t
end
local function release(path, r, keep_config)
 local term_status, kill_status
 if alive(r) then
  term_status = api.sys.call("kill -TERM " .. r.pid)
  for _=1,10 do if not alive(r) then break end; nixio.nanosleep(0,100000000) end
  if alive(r) then kill_status = api.sys.call("kill -KILL " .. r.pid) end
  for _=1,10 do if not alive(r) then break end; nixio.nanosleep(0,100000000) end
 end
 assert(not alive(r), "Hysteria 1: cannot stop owned process (pid=" .. tostring(r.pid) ..
  " birth=" .. tostring(r.birth) .. " current=" .. tostring(r.pid and identity(r.pid)) ..
  " TERM=" .. tostring(term_status) .. " KILL=" .. tostring(kill_status) .. ")")
 r.released = r.released or {}
 write(path, json.stringify(r))
 local errors = {}
 for _, rule in ipairs(r.rules or {}) do
  if not r.released[rule] then
   local used = false
   for _, other in ipairs(entries()) do
    if other.path ~= path and not (other.value.released or {})[rule] then
     for _, v in ipairs(other.value.rules or {}) do if v == rule then used = true end end
    end
   end
   local marker = registry .. "/rule_" .. api.md5_string(rule)
   local done = used or not fs.access(marker)
   if not done then
    local status = api.sys.call(rule:gsub(" %-A OUTPUT ", " -D OUTPUT ", 1))
    if status == 0 then done = true
    else
     -- xtables -C: only status 1 means absent; errors must remain retryable.
     done = api.sys.call(rule:gsub(" %-A OUTPUT ", " -C OUTPUT ", 1) .. " 2>/dev/null") == 1
    end
   end
   if done then
    if not used and fs.access(marker) then
     assert(fs.remove(marker), "cannot release Hysteria rule ownership")
    end
    r.released[rule] = true
    write(path, json.stringify(r))
   else errors[#errors+1] = "cannot remove/verify " .. rule end
  end
 end
 if #errors > 0 then error(table.concat(errors, "; "), 0) end
 if not keep_config then fs.remove(r.config) end
 if r.link then fs.remove(r.link) end
 assert(fs.remove(path), "cannot remove Hysteria instance record")
end
local function locked(fn)
 assert(call("mkdir -p " .. quote(registry)), "cannot create Hysteria registry")
 -- A stable inode and kernel lock survive interrupted initialization and are
 -- released on process death. Never unlink it or steal it on timeout/PID reuse.
 local fd = assert(nixio.open(registry .. "/runtime.lock", "a", "600"), "cannot open Hysteria lock")
 local acquired = false
 for _=1,150 do
  if fd:lock("tlock") then acquired=true; break end
  nixio.nanosleep(0,100000000)
 end
 if not acquired then fd:close(); error("Hysteria registry is busy", 0) end
 local ok, result = pcall(fn)
 fd:close()
 if not ok then error(result, 0) end
 return result
end
local function listening(pid, proto, port)
	local inodes = {}
	local dir = "/proc/" .. pid .. "/fd"
	if not fs.access(dir) then return false end
	for fd in fs.dir(dir) do
		local inode = (fs.readlink(dir .. "/" .. fd) or ""):match("^socket:%[(%d+)%]$")
		if inode then inodes[inode] = true end
	end
	for _, suffix in ipairs({"", "6"}) do
		for line in (read("/proc/net/" .. proto .. suffix) or ""):gmatch("[^\n]+") do
			local f = {}; for v in line:gmatch("%S+") do f[#f+1]=v end
			local p = (f[2] or ""):match(":(%x+)$")
			if p and tonumber(p,16) == port and inodes[f[10]] and (proto == "udp" or f[4] == "0A") then return true end
		end
	end
	return false
end
local function port(s) return assert(tonumber(s:match(":(%d+)$")), "invalid listener") end
function start(var)
	return locked(function()
		assert(var.mode == "client" or var.mode == "server", "invalid Hysteria mode")
		assert(var.scope == "client" or var.scope == "server", "invalid Hysteria scope")
		if var.gid ~= nil then
			assert(var.mode == "client" and var.scope == "client" and tonumber(var.gid) == api.DIRECT_GID,
				"invalid Hysteria client GID")
		end
		if var.bound_endpoint ~= nil then
			assert(var.bound_endpoint == true and var.gid ~= nil, "bound endpoint requires explicit client identity")
		end
		local path = registry .. "/" .. api.md5_string(var.config) .. ".json"
		local previous = json.parse(read(path) or "")
		if previous then release(path, previous, true) end
		local r = {config=var.config, scope=var.scope, rules={}}
		write(path,json.stringify(r))
		local ok, err = pcall(function()
			local version = api.sys.exec(quote(var.bin) .. " --version 2>/dev/null") or ""
			assert(version:match("%f[%d]1%.3%.5%f[^%d%.]"), "Hysteria 1: binary must be v1.3.5")
			local c = assert(json.parse(read(var.config) or ""), "invalid Hysteria JSON")
			local expected = {}
			if var.mode == "server" then
				expected[#expected+1] = {c.protocol == "faketcp" and "tcp" or "udp", port(c.listen)}
			else
				for _, k in ipairs({"socks5","http","redirect_tcp","tproxy_tcp","tproxy_udp"}) do
					if c[k] then expected[#expected+1]={k == "tproxy_udp" and "udp" or "tcp", port(c[k].listen)} end
				end
				-- v1 SOCKS UDP uses a random port created on UDP ASSOCIATE,
				-- not a permanent UDP listener on the SOCKS TCP port.
			end
			assert(#expected > 0, "missing Hysteria listeners")
			if c.protocol == "faketcp" then
				local endpoint
				if var.mode == "client" then
					local host, p = c.server:match("^(.*):(%d+)$")
					host = host:gsub("^%[", ""):gsub("%]$", "")
					if var.bound_endpoint then assert(host:match("^[%x%.:]+$"), "bound endpoint must be literal") end
					local addresses = var.bound_endpoint and {{address=host}} or nixio.getaddrinfo(host, "any")
					assert(addresses and addresses[1], "cannot resolve faketcp server")
					local ip = addresses[1].address
					assert(ip and ip:match("^[%x%.:]+$"), "invalid resolved IP")
					if not c.server_name and not api.is_ipv6(host) and not host:match("^%d+%.%d+%.%d+%.%d+$") then c.server_name=host end
					c.server=(ip:find(":",1,true) and "["..ip.."]" or ip)..":"..p
					endpoint = " -d " .. quote(ip) .. " --dport " .. p
				else endpoint = " --sport " .. port(c.listen) end
				-- Same rules as v1.3.5 tcp_linux.go. Install before the core so it
				-- does not own/delete a rule shared by another Passwall instance.
				for _, v in ipairs({{"iptables","ttl","--ttl-eq"},{"ip6tables","hl","--hl-eq"}}) do
					local rule=v[1].." -t filter -A OUTPUT -m "..v[2].." "..v[3].." 1 -p tcp"..endpoint.." -j DROP"
					-- Client needs only the destination address family.
					if var.mode == "server" or (c.server:sub(1,1)=="[") == (v[1]=="ip6tables") then
						local available = true
						if var.mode == "client" then
							local status = api.sys.call("command -v " .. quote(v[1]) .. " >/dev/null 2>&1")
							-- ash returns 127, bash returns 1 for an absent command.
							assert(status == 0 or status == 1 or status == 127, "cannot probe " .. v[1])
							available = status == 0
						end
						if not available then
							local warning = "Hysteria 1: WARNING: " .. v[1] .. " unavailable for FakeTCP client " .. var.config ..
								"; continuing with native core handling, without a managed TTL/HL rule"
							io.stderr:write(warning .. "\n")
							call("logger -t passwall " .. quote(warning) .. " 2>/dev/null")
						else
							r.rules[#r.rules+1]=rule
							write(path,json.stringify(r))
							local status=api.sys.call(rule:gsub(" %-A OUTPUT "," -C OUTPUT ",1).." 2>/dev/null")
							assert(status == 0 or status == 1, "cannot query faketcp rule")
							if status == 1 then
								write(registry.."/rule_"..api.md5_string(rule), rule)
								assert(call(rule), "faketcp requires iptables TTL/ip6tables HL support")
							end
						end
					end
				end
				if not var.bound_endpoint then write(var.config,json.stringify(c,1)) end
			end
			-- Use a unique argv[0] symlink under the existing runtime directory.
			local link=(var.bin_dir or var.config:match("^(.*)/")).."/hysteria1_"..api.md5_string(var.config)
			fs.remove(link); assert(fs.symlink(var.bin,link), "cannot link Hysteria")
			r.link=link
			local command=quote(link).." --no-check --log-level "..quote(var.loglevel or "warn").." -c "..quote(var.config).." "..quote(var.mode).." >"..quote(var.log or "/dev/null").." 2>&1 & echo $!"
			if var.gid ~= nil then
				local status, output = api.exec_call_as_gid(command, api.DIRECT_GID)
				assert(status == 0 and output:match("^%d+$"), "cannot launch Hysteria with client GID")
				r.pid=tonumber(output); r.gid=api.DIRECT_GID
			else r.pid=tonumber(api.sys.exec(command)) end
			r.birth=identity(r.pid)
			write(path,json.stringify(r))
			local ready=false
			for _=1,100 do
				if not alive(r) then break end
				ready=true
				for _, v in ipairs(expected) do if not listening(r.pid,v[1],v[2]) then ready=false end end
				if ready then break end
				nixio.nanosleep(0,100000000)
			end
			assert(ready and alive(r), "Hysteria 1: process exited or listeners not ready within 10 seconds")
			nixio.nanosleep(0,100000000)
			assert(alive(r), "Hysteria 1: process exited during startup")
		end)
		if not ok then
            local cleaned, cleanup_error = pcall(release,path,r)
            if not cleaned then err=tostring(err).."; cleanup pending: "..tostring(cleanup_error) end
            error(err,0)
        end
		return true
	end)
end
-- Read-only capability check for the inactive split-global caller. Existing
-- launch/stop paths keep their behavior; readiness is never inferred from PID alone.
function ready(scope, config, tcp, udp)
	return locked(function()
		local r = json.parse(read(registry .. "/" .. api.md5_string(config) .. ".json") or "")
		if not r or r.scope ~= scope or r.config ~= config or not alive(r) then return false end
		local c = json.parse(read(config) or "")
		if not c then return false end
		-- B2 supplies the capabilities recorded in its instance metadata. A
		-- changed JSON must not validate a different port/protocol than cached.
		if tcp ~= nil or udp ~= nil then
			if scope ~= "client" then return false end
			local function matches(expected, listener)
				if expected == "" then return listener == nil end
				local n = tonumber(expected)
				return n and n >= 1 and n <= 65535 and n % 1 == 0 and
					listener and port(listener.listen) == n
			end
			if not matches(tcp, c.redirect_tcp or c.tproxy_tcp) or not matches(udp, c.tproxy_udp) then return false end
		end
		local found = false
		for _, k in ipairs({"socks5", "http", "redirect_tcp", "tproxy_tcp", "tproxy_udp"}) do
			if c[k] then
				found = true
				if not listening(r.pid, k == "tproxy_udp" and "udp" or "tcp", port(c[k].listen)) then return false end
			end
		end
		return found and alive(r)
	end)
end

function stop(scope, config)
	return locked(function()
		local errors = {}
        for _, e in ipairs(entries()) do
            if e.value.scope == scope and (not config or e.value.config == config) then
                local ok, err=pcall(release,e.path,e.value)
                if not ok then errors[#errors+1]=tostring(err) end
            end
        end
        if #errors > 0 then error(table.concat(errors,"; "),0) end
	end)
end
if arg and arg[0] and arg[0]:match("hysteria_runtime%.lua$") and (arg[1] == "start" or arg[1] == "stop" or arg[1] == "ready") then
	local ok, err=pcall(function()
		if arg[1]=="start" then start(assert(json.parse(arg[2])))
		elseif arg[1]=="ready" then assert(ready(arg[2], arg[3], arg[4], arg[5]), "Hysteria listeners are not ready")
		else stop(arg[2], arg[3]) end
	end)
	if not ok then io.stderr:write(tostring(err).."\n"); os.exit(1) end
end
