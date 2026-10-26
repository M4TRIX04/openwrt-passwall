-- B3.3-3C-A read-only diagnostics. No file writes, signals or ready state.
-- candidate OLD_JSON FRESH_3B_JSON: exact validated candidate equality.
-- observe CANDIDATE_JSON PID BIRTH DNS2SOCKS_ABSOLUTE_PATH PORT:
--   verifies an explicitly supplied helper against candidate-derived argv and
--   its exact IPv4 loopback UDP listener. Output is an observation, never an
--   ownership receipt, runtime binding or dep_ready proof. Caller must retain
--   dns_helper.sh's fresh 3B checks; standalone observation cannot replace them.
-- check CANDIDATE_JSON PID BIRTH DNS2SOCKS_ABSOLUTE_PATH PORT OBSERVATION_JSON:
--   repeats observation and rejects any identity/listener/binding change.
local api = require "luci.passwall.api"
local fs, json = api.fs, api.jsonc
local M = {}
local function need(value) assert(value, "DNS helper identity unavailable or changed"); return value end
local function read(path) return need(fs.readfile(path)) end
local function digest(value)
	need(type(value) == "string" and #value == 32 and value:match("^%x+$"))
	return value
end
local function equal(a, b)
	if type(a) ~= type(b) then return false end
	if type(a) ~= "table" then return a == b end
	for k, v in pairs(a) do if not equal(v, b[k]) then return false end end
	for k in pairs(b) do if a[k] == nil then return false end end
	return true
end
local function port(value)
	local n = tonumber(value)
	need(n and n >= 1 and n <= 65535 and n % 1 == 0)
	return n
end
local function candidate(value)
	local c = need(json.parse(value))
	need(type(c) == "table" and c.state == "dep_validated" and c.reason == nil)
	need(type(c.scope) == "string" and (c.scope == "global" or c.scope:match("^acl:[%w_]+$")))
	need(type(c.generation) == "string" and c.generation:match("^generation%.[%w_]+$"))
	need(type(c.instance_dir) == "string" and fs.realpath(c.instance_dir) == c.instance_dir)
	need(c.socks_addr == "127.0.0.1" and type(c.socks_port) == "number")
	port(c.socks_port); digest(c.identity_md5); digest(c.config_md5)
	if c.socks_identity_md5 then digest(c.socks_identity_md5); digest(c.socks_config_md5) end
	need(c.node_type == "SS" or c.node_type == "Hysteria")
	need(c.dns_cache == 0 or c.dns_cache == 1)
	need(type(c.remote_dns) == "string" and c.remote_dns:match("^.+#%d+$"))
	return c
end
function M.candidate(old, fresh)
	local c = candidate(fresh)
	need(equal(candidate(old), c))
	return c
end

local function identity(pid, birth, bin, command)
	need(type(pid) == "string" and pid:match("^%d+$") and tonumber(pid) > 0)
	need(type(birth) == "string" and birth:match("^%d+$"))
	local proc = "/proc/" .. pid
	-- Match the existing stop observer's greedy comm-field handling. Unknown or
	-- unreadable /proc data is failure, never proof that a process has exited.
	local actual, rest = read(proc .. "/stat"):match("^(%d+) .*%) (.*)$")
	local fields = {}; for v in (rest or ""):gmatch("%S+") do fields[#fields + 1] = v end
	need(actual == pid and fields[1] and fields[1] ~= "Z" and fields[20] == birth)
	local namespace = need(fs.readlink(proc .. "/ns/net"))
	need(namespace == need(fs.readlink("/proc/self/ns/net")))
	need(fs.realpath(proc .. "/exe") == bin)
	local executable, expected = need(fs.stat(proc .. "/exe")), need(fs.stat(bin))
	need(executable.type == "reg" and type(executable.dev) == "number" and type(executable.ino) == "number" and
		executable.dev == expected.dev and executable.ino == expected.ino)
	need(read(proc .. "/cmdline") == command)
	local tasks = 0
	for task in need(fs.dir(proc .. "/task")) do
		tasks = tasks + 1
		local groups = need(read(proc .. "/task/" .. task .. "/status"):match("\nGid:%s*([^\n]+)"))
		local count = 0
		for gid in groups:gmatch("%d+") do count = count + 1; need(tonumber(gid) == api.DIRECT_GID) end
		need(count == 4 and api.DIRECT_GID == 9911)
	end
	need(tasks > 0)
	local md5 = digest(api.md5_file(proc .. "/exe"))
	need(md5 == digest(api.md5_file(bin)))
	return {pid = pid, birth = birth, executable = bin, executable_md5 = md5,
		executable_dev = executable.dev, executable_ino = executable.ino,
		cmdline_md5 = digest(api.md5_file(proc .. "/cmdline")), gid = api.DIRECT_GID,
		network_namespace = namespace}
end
local function listener(pid, p)
	local owned, found = {}, nil
	for fd in need(fs.dir("/proc/" .. pid .. "/fd")) do
		local path = "/proc/" .. pid .. "/fd/" .. fd
		local inode = (fs.readlink(path) or ""):match("^socket:%[(%d+)%]$")
		local st = inode and fs.stat(path)
		if st and st.gid == api.DIRECT_GID then owned[inode] = true end
	end
	for row in read("/proc/net/udp"):gmatch("[^\n]+") do
		local f = {}; for word in row:gmatch("%S+") do f[#f + 1] = word end
		local address, lp = (f[2] or ""):match("^(%x+):(%x+)$")
		if (address == "0100007F" or address == "7F000001") and tonumber(lp, 16) == p and
			f[3] == "00000000:0000" and f[4] == "07" and owned[f[10]] then
			need(not found or found == f[10]); found = f[10]
		end
	end
	return need(found)
end
function M.observe(value, pid, birth, bin, listen_port)
	local c, p = candidate(value), port(listen_port)
	need(type(bin) == "string" and bin:sub(1, 1) == "/" and fs.realpath(bin) == bin)
	-- Same no-auth argv form as run_dns2socks; sole SOCKS source is the candidate.
	local argv = {bin}
	if c.dns_cache == 0 then argv[#argv + 1] = "/d" end
	argv[#argv + 1] = c.socks_addr .. ":" .. c.socks_port
	argv[#argv + 1] = c.remote_dns:gsub("#", ":")
	argv[#argv + 1] = "127.0.0.1:" .. p
	local command = table.concat(argv, "\0") .. "\0"
	local before = identity(pid, birth, bin, command)
	local inode = listener(pid, p)
	need(equal(before, identity(pid, birth, bin, command)) and inode == listener(pid, p))
	return {scope = c.scope, generation = c.generation, instance_dir = c.instance_dir,
		socks_addr = c.socks_addr, socks_port = c.socks_port,
		identity_md5 = c.identity_md5, socks_identity_md5 = c.socks_identity_md5 or c.identity_md5,
		helper_identity = before, helper_listener = {address = "127.0.0.1", port = p,
			family = "4", protocol = "udp", inode = inode}}
end
function M.check(value, pid, birth, bin, listen_port, expected)
	local observation = M.observe(value, pid, birth, bin, listen_port)
	need(equal(observation, need(json.parse(expected))))
	return observation
end
if arg and arg[0] and arg[0]:match("dns_helper_probe%.lua$") then
	local ok, result = pcall(function()
		if arg[1] == "candidate" and #arg == 3 then return M.candidate(arg[2], arg[3]) end
		if arg[1] == "observe" and #arg == 6 then return M.observe(unpack(arg, 2)) end
		if arg[1] == "check" and #arg == 7 then return M.check(unpack(arg, 2)) end
		error("invalid DNS helper diagnostic arguments")
	end)
	if not ok then io.stderr:write("dns_dep_helper_identity\n"); os.exit(1) end
	print(json.stringify(result))
end
return M
