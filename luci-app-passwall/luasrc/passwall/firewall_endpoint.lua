-- B3.2: inspect the actual running client configuration. No UCI/DNS reads.
local api = require("luci.passwall.api")
local json = api.jsonc
local function owner()
	local dir = assert(arg[1]:match("^(.*)/config%.json$"))
	local f = assert(io.open(dir .. "/meta")); local core = f:read("*l"); f:close()
	if core == "Hysteria" then
		f = assert(io.open("/tmp/etc/passwall_hysteria1/" .. api.md5_string(arg[1]) .. ".json"))
		local r = assert(json.parse(f:read("*a"))); f:close()
		assert(r.scope == "client" and r.config == arg[1])
		return tostring(r.pid) .. " " .. tostring(r.birth)
	end
	assert(core == "SS", "unsupported instance core")
	-- The transparent owner in an ACL is the relay, never SS's SOCKS TCP
	-- control socket. Global SS uses ss-redir directly.
	f = io.open(dir .. "/relay/process") or assert(io.open(dir .. "/process"))
	local pid, birth = f:read("*l"), f:read("*l"); f:close()
	assert(pid and birth); return pid .. " " .. birth
end
local function endpoint()
	assert(arg[2] == "tcp" or arg[2] == "udp", "invalid business protocol")
	local dir = assert(arg[1]:match("^(.*)/config%.json$"))
	if api.fs.access(dir .. "/binding.json") then
		return require("luci.passwall.runtime_binding").remote(dir, arg[2])
	end
	local f = assert(io.open(arg[1], "rb"))
	local c = assert(json.parse(f:read("*a"))); f:close()
	local host, port, stream
	if c.method then
		host, port, stream = c.server, c.server_port, arg[2]
	else
		assert(c.protocol == "udp" or c.protocol == "faketcp" or c.protocol == "wechat-video", "not a Hysteria 1 transport")
		assert(type(c.server) == "string", "missing server")
		host, port = c.server:match("^%[([^%]]+)%]:(%d+)$")
		if not host then host, port = c.server:match("^([^:]+):(%d+)$") end
		stream = c.protocol == "faketcp" and "tcp" or "udp"
	end
	assert(type(host) == "string" and host:match("^[%w%.:%-]+$"), "invalid endpoint host")
	port = tonumber(port)
	assert(port and port == math.floor(port) and port >= 1 and port <= 65535, "invalid endpoint port")
	return host .. " " .. port .. " " .. stream
end
local ok, value = pcall(arg[2] == "owner" and owner or endpoint)
if not ok then io.stderr:write("Split firewall endpoint: " .. tostring(value) .. "\n"); os.exit(1) end
print(value)
