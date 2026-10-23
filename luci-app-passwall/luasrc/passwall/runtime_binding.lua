-- B3.3-2: explicit, inactive B2/B3.1 adapter. No service/hook/DNS entry.
local api = require "luci.passwall.api"
local nixio = require "nixio"
local fs, json = api.fs, api.jsonc
local endpoint = require "luci.passwall.endpoint_contract"
local quote = require("luci.util").shellquote
local M = {}
local function need(v, why) assert(v, "Bound runtime: " .. why); return v end
local function read(p) return need(fs.readfile(p), "cannot read " .. p) end
local function decode(p) return need(json.parse(read(p)), "invalid JSON: " .. p) end
local function line(p) return read(p):gsub("\n$", "") end
local function digest(p)
	local d = api.md5_file(p)
	need(type(d) == "string" and #d == 32 and d:match("^%x+$"), "cannot hash " .. p)
	return d
end
local function write(p, value)
	local data = json.stringify(value)
	local fd = need(nixio.open(p .. ".new", "w", "600"), "cannot create record")
	local ok = fd:writeall(data); local closed = fd:close()
	need(ok and closed, "cannot write record")
	need(fs.rename(p .. ".new", p), "cannot publish record")
end
local function snapshot(dir)
	need(type(dir) == "string" and dir:match("^/[%w_./-]+/contracts/generation%.[%w_]+$"), "invalid snapshot path")
	local package = line(dir .. "/package")
	need(package == "passwall_contract_" .. dir:match("%.([%w_]+)$"), "snapshot package mismatch")
	need(digest(dir .. "/source") == line(dir .. "/source.md5") and
		digest(dir .. "/config/" .. package) == line(dir .. "/config.md5"), "snapshot content changed")
	return package, line(dir .. "/source.md5"), dir:match("([^/]+)$")
end
local function frozen(dir, id)
	need(type(id) == "string" and id:match("^[%w_]+$"), "invalid node ID")
	local package, source, generation = snapshot(dir)
	local cursor = require("uci").cursor(dir .. "/config", dir .. "/state")
	local node = cursor:get_all(package, id)
	cursor:unload(package)
	need(type(node) == "table" and node[".type"] == "nodes", "missing frozen node")
	return node, source, generation
end
-- Optional socket evidence only, owned by the existing primary process.
-- No auxiliary process identity or SOCKS protocol/forwarding claim is implied.
local function socks_declaration(value)
	if value == nil then return nil end
	need(type(value) == "table" and value.address == "127.0.0.1" and
		value.protocol == "tcp" and value.family == "4" and type(value.port) == "number" and
		value.port == math.floor(value.port) and value.port >= 1 and value.port <= 65535,
		"invalid SOCKS TCP socket declaration")
	for key in pairs(value) do
		need(key == "address" or key == "protocol" or key == "family" or key == "port", "unknown SOCKS socket field")
	end
	return value
end
local function socks_config(socks, core, config)
	if not socks then return end
	if core == "SS" then
		need(config.local_address == socks.address and config.local_port == socks.port and config.mode ~= "udp_only",
			"SOCKS declaration differs from configuration")
	else
		need(config.socks5 and config.socks5.listen == socks.address .. ":" .. socks.port,
			"SOCKS declaration differs from configuration")
	end
end
local function binding(dir)
	local b = decode(dir .. "/binding.json")
	local node, source, generation = frozen(b.snapshot, b.endpoint.node_id)
	endpoint.check(b.endpoint, generation, source, b.endpoint.node_id, node)
	local path = b.snapshot .. "/endpoints/" .. b.endpoint.node_id .. "." .. b.endpoint.preference .. ".json"
	need(digest(path) == b.endpoint_md5, "generation endpoint record changed")
	local selected = decode(path)
	need(selected.address == b.endpoint.address and selected.family == b.endpoint.family and selected.port == b.endpoint.port, "instance endpoint differs from generation record")
	need(digest(dir .. "/config.json") == b.config_md5, "generated configuration changed")
	local config = decode(dir .. "/config.json")
	endpoint.config(b.endpoint, config)
	socks_config(socks_declaration(b.socks_tcp_socket), node.type, config)
	return b
end

-- A single immutable resolution per node/preference in one private snapshot.
-- Caller holds lifecycle lock, verifies snapshot freshness before/after launch.
function M.prepare(snapshot_dir, id, preference, family, dir, parameters)
	need(family == "4" or family == "6" or family == "dual", "invalid listener family")
	need(not fs.access(dir .. "/binding.json"), "instance already prepared")
	local node, source, generation = frozen(snapshot_dir, id)
	local endpoints = snapshot_dir .. "/endpoints"
	need(fs.mkdirr(endpoints), "cannot create endpoint record directory")
	local path = endpoints .. "/" .. id .. "." .. preference .. ".json"
	need(preference == "ipv4" or preference == "ipv6" or preference == "ipv4-only" or preference == "ipv6-only", "invalid endpoint preference")
	local e
	if fs.access(path) then e = decode(path); endpoint.check(e, generation, source, id, node)
	else e = endpoint.bind(generation, source, id, node, preference); write(path, e) end
	local params = need(json.parse(parameters), "invalid generator parameters")
	local socks = socks_declaration(params.socks_tcp_socket)
	params.socks_tcp_socket = nil -- binding metadata, never a generator input
	params.node = id; params.frozen_node = e.generator_node
	params.server_host = nil; params.server_port = nil
	local module
	if node.type == "SS" then
		params.local_addr = params.local_addr == "127.0.0.1" and "127.0.0.1" or (family == "4" and "0.0.0.0" or "::")
		module = require "luci.passwall.util_shadowsocks"
	else
		params.proxy_ipv6 = family == "4" and "0" or "1"
		params.transparent_address = family == "4" and "0.0.0.0" or "::"
		module = require "luci.passwall.util_hysteria"
	end
	local config = need(json.parse(module.gen_config(params)), "generator rejected frozen node")
	endpoint.config(e, config)
	socks_config(socks, node.type, config)
	write(dir .. "/config.json", config)
	write(dir .. "/binding.json", {snapshot = snapshot_dir, endpoint = e, family = family,
		config_md5 = digest(dir .. "/config.json"), endpoint_md5 = digest(path), gid = api.DIRECT_GID,
		socks_tcp_socket = socks})
end

function M.spawn(log, argv)
	need(api.DIRECT_GID == 9911 and #argv > 0, "unexpected direct identity")
	local parts = {}; for _, value in ipairs(argv) do parts[#parts + 1] = quote(value) end
	local rc, out = api.exec_call_as_gid(table.concat(parts, " ") .. " >" .. quote(log) .. " 2>&1 & echo $!", api.DIRECT_GID)
	need(rc == 0 and out:match("^%d+$"), "GID launcher failed")
	return out
end
function M.start_hysteria(dir, bin, bin_dir, log, level)
	binding(dir)
	return require("luci.passwall.hysteria_runtime").start({config = dir .. "/config.json", bin = bin,
		bin_dir = bin_dir, scope = "client", mode = "client", log = log, loglevel = level, gid = api.DIRECT_GID, bound_endpoint = true})
end

local function process(dir, core)
	local pid, birth, executable
	if core == "Hysteria" then
		local r = decode("/tmp/etc/passwall_hysteria1/" .. api.md5_string(dir .. "/config.json") .. ".json")
		need(r.scope == "client" and r.config == dir .. "/config.json" and r.gid == api.DIRECT_GID, "Hysteria owner mismatch")
		pid, birth, executable = r.pid, r.birth, r.link
	else pid, birth = read(dir .. "/process"):match("^(%d+)\n(%d+)\n"); executable = dir .. "/core" end
	need(pid and birth, "missing process identity")
	return tostring(pid), tostring(birth), executable
end
local function alive(pid, birth)
	local data = read("/proc/" .. pid .. "/stat"):match("^%d+ %b() (.*)")
	local fields = {}; for v in (data or ""):gmatch("%S+") do fields[#fields + 1] = v end
	need(fields[1] ~= "Z" and fields[20] == birth, "process exited or PID reused")
end
local function identity(pid, birth, gid)
	alive(pid, birth)
	-- Per-thread checks matter for Go. This is corroboration, not a substitute
	-- for actual-core netfilter socket-credential experiments.
	for task in fs.dir("/proc/" .. pid .. "/task") do
		local groups = read("/proc/" .. pid .. "/task/" .. task .. "/status"):match("\nGid:%s*([^\n]+)")
		need(groups, "cannot read thread GIDs")
		local count = 0
		for value in groups:gmatch("%d+") do count = count + 1; need(tonumber(value) == gid, "core changed GID") end
		need(count == 4, "incomplete thread GIDs")
	end
end
local function diagnostics()
	local rc, text = api.exec_call("LC_ALL=C ss -H -n -a -e -t -u --inet-sockopt 2>/dev/null")
	need(rc == 0 and type(text) == "string", "ss/inet socket diagnostics unavailable (no capability published)")
	local records, current = {}, nil
	for row in text:gmatch("[^\n]+") do
		local inode = row:match("%f[%w]ino:(%d+)%f[%W]")
		if inode then current = inode; records[current] = row
		elseif row:match("^%s") and current then records[current] = records[current] .. " " .. row
		else current = nil end
	end
	return records
end
local function sockets(pid, proto, port, gid, transparent, diag, loopback)
	local owned, found = {}, {}
	for fd in fs.dir("/proc/" .. pid .. "/fd") do
		local path = "/proc/" .. pid .. "/fd/" .. fd
		local inode = (fs.readlink(path) or ""):match("^socket:%[(%d+)%]$")
		if inode then
			local st = fs.stat(path)
			if st and (gid == nil or st.gid == gid) then owned[inode] = true end
		end
	end
	for _, family in ipairs({4, 6}) do
		for row in (fs.readfile("/proc/net/" .. proto .. (family == 6 and "6" or "")) or ""):gmatch("[^\n]+") do
			local f = {}; for v in row:gmatch("%S+") do f[#f + 1] = v end
			local address, p = (f[2] or ""):match("^(%x+):(%x+)$")
			local detail = diag[f[10]]
			local local_bind = address and (address:match("^0+$") or (loopback and family == 4 and (address == "0100007F" or address == "7F000001")))
			if loopback == "127.0.0.1" then
				-- /proc encodes IPv4 in native byte order. Corroborate the
				-- exact numeric address in the SAME inode's ss record, so the
				-- opposite-endian 1.0.0.127 cannot masquerade as loopback.
				local_bind = family == 4 and (address == "0100007F" or address == "7F000001") and
					detail and detail:match("%s127%.0%.0%.1:" .. port .. "%s")
			end
			if local_bind and tonumber(p, 16) == port and owned[f[10]] and detail and
				((proto == "udp" and f[4] == "07") or (proto == "tcp" and f[4] == "0A")) then
				need(detail:find("inet%-sockopt:"), "missing socket option evidence")
				if family == 6 then need(detail:match("v6only:[01]%f[%W]"), "missing V6ONLY evidence") end
				if not transparent or detail:match("%f[%w]transparent%f[%W]") then
					found[tostring(family)] = true
					if family == 6 and detail:match("v6only:0%f[%W]") then found["4"] = true end
				end
			end
		end
	end
	return found
end

local function check_capabilities(dir, expected)
	local record = decode(dir .. "/bound.capabilities")
	need(type(record) == "table", "invalid sealed capabilities")
	for proto, families in pairs(record) do
		need(expected[proto] and type(families) == "table", "sealed capabilities changed")
		for family, value in pairs(families) do
			need(value == true and expected[proto][family] == value, "sealed capabilities changed")
		end
	end
	for proto, families in pairs(expected) do
		for family, value in pairs(families) do
			need(record[proto] and record[proto][family] == value, "sealed capabilities changed")
		end
	end
end
-- verify is live, never treats a persisted capability record as current ready.
-- seal is creation-only; references require the original, complete seal.
function M.verify(dir, seal, expected_family, expected_proto, expected_port, require_seal)
	if seal then
		for _, file in ipairs({"bound.identity", "bound.capabilities"}) do
			local st, errno = fs.lstat(dir .. "/" .. file)
			need(not st and errno == 2, "seal already exists or cannot establish absence")
		end
	end
	local b = binding(dir)
	local core = b.endpoint.original_node.type
	local pid, birth, executable = process(dir, core)
	identity(pid, birth, b.gid)
	need(executable and fs.realpath(executable) == fs.readlink("/proc/" .. pid .. "/exe"), "core executable changed")
	local owner = endpoint.instance(b.endpoint, dir .. "/config.json", b.config_md5, pid, birth)
	if require_seal or fs.access(dir .. "/bound.identity") then endpoint.check_instance(decode(dir .. "/bound.identity"), b.endpoint, dir .. "/config.json", b.config_md5, pid, birth) end
	local meta = read(dir .. "/meta"); local lines = {}; for v in (meta .. "\n"):gmatch("(.-)\n") do lines[#lines + 1] = v end
	need(lines[1] == core and lines[2] == b.endpoint.node_id, "instance metadata mismatch")
	local diag, capabilities = diagnostics(), {}
	local config = decode(dir .. "/config.json")
	if b.socks_tcp_socket then
		capabilities.socks_tcp_socket = sockets(pid, "tcp", b.socks_tcp_socket.port, b.gid, false, diag, "127.0.0.1")
		need(capabilities.socks_tcp_socket["4"], "SOCKS TCP socket unavailable at exact loopback")
		need(line(dir .. "/socks_port") == tostring(b.socks_tcp_socket.port), "sealed SOCKS port changed")
	end
	local listener_pid, listener_gid = pid, b.gid
	if core == "SS" and fs.access(dir .. "/relay/process") then
		-- The SOCKS TCP control listener is an auxiliary dependency. It is
		-- deliberately NOT added to the transparent TCP capability below.
		need(sockets(pid, "tcp", config.local_port, b.gid, false, diag, true)["4"], "missing SS SOCKS control listener")
		if lines[4] ~= "" then need(sockets(pid, "udp", config.local_port, b.gid, false, diag, true)["4"], "missing SS SOCKS UDP listener") end
		local relay_birth, relay_exe
		listener_pid, relay_birth, relay_exe = process(dir .. "/relay", "SS"); listener_gid = nil
		alive(listener_pid, relay_birth)
		need(fs.realpath(relay_exe) == fs.readlink("/proc/" .. listener_pid .. "/exe"), "relay executable changed")
	end
	for i, proto in ipairs({"tcp", "udp"}) do
		local port = tonumber(lines[i + 2])
		if port then
			local transparent = proto == "udp" or (core == "Hysteria" and config.tproxy_tcp ~= nil) or (core == "SS" and config.tcp_tproxy == true)
			if listener_gid == nil then transparent = proto == "udp" or read(dir .. "/context"):match("^tproxy\n") ~= nil end
			capabilities[proto] = sockets(listener_pid, proto, port, listener_gid, transparent, diag)
			for _, family in ipairs(b.family == "dual" and {"4", "6"} or {b.family}) do
				need(capabilities[proto][family], proto .. "/IPv" .. family .. " listener/options unavailable")
			end
			if b.family ~= "dual" then capabilities[proto][b.family == "4" and "6" or "4"] = nil end
		end
	end
	if expected_proto then
		need(expected_proto == "tcp" or expected_proto == "udp", "invalid transparent protocol")
		need(capabilities[expected_proto], "requested protocol unavailable")
		if expected_port then
			local index = expected_proto == "tcp" and 3 or 4
			need(tonumber(expected_port) == tonumber(lines[index]), "requested port differs from owned listener")
		end
	end
	if expected_family then need(capabilities[expected_proto] and capabilities[expected_proto][expected_family], "requested protocol/family unavailable") end
	if require_seal then
		check_capabilities(dir, capabilities)
		if core == "SS" and fs.access(dir .. "/relay/process") then
			need(line(dir .. "/socks_port") == tostring(config.local_port), "sealed SOCKS port changed")
		elseif core == "Hysteria" and config.socks5 then
			need(config.socks5.listen == "127.0.0.1:" .. line(dir .. "/socks_port"), "sealed SOCKS port changed")
		end
	end
	identity(pid, birth, b.gid)
	if seal then write(dir .. "/bound.identity", owner); write(dir .. "/bound.capabilities", capabilities) end
	return true
end
function M.remote(dir, proto)
	need(proto == "tcp" or proto == "udp", "invalid business protocol")
	M.verify(dir, false, nil, proto)
	local b = binding(dir)
	local streams = endpoint.config(b.endpoint, decode(dir .. "/config.json"))
	local stream = b.endpoint.original_node.type == "SS" and proto or streams[1]
	return b.endpoint.address .. " " .. b.endpoint.port .. " " .. stream
end
function M.compatible(dir, snapshot_dir, preference, family, require_seal)
	local b = binding(dir)
	need(b.snapshot == snapshot_dir and b.endpoint.preference == preference and
		(b.family == family or (b.family == "dual" and (family == "4" or family == "6"))), "instance belongs to another binding/generation")
	return M.verify(dir, false, nil, nil, nil, require_seal)
end
function M.owner(dir)
	local b = decode(dir .. "/binding.json")
	if fs.access(dir .. "/bound.identity") then
		local record = decode(dir .. "/bound.identity")
		local ok, pid, birth = pcall(process, dir, b.endpoint.original_node.type)
		if not ok then
			-- Only the Hysteria manager may already have removed its record in a
			-- successful stop followed by a failed directory cleanup. Read/parse
			-- errors are not proof of absence, nor of an exited owned process.
			need(b.endpoint.original_node.type == "Hysteria", "unreadable process ownership; cleanup retained")
			local manager = "/tmp/etc/passwall_hysteria1/" .. api.md5_string(dir .. "/config.json") .. ".json"
			local st, errno = fs.stat(manager)
			need(not st and errno == 2, "invalid/unreadable manager record; cleanup retained")
			local proc = "/proc/" .. tostring(record.pid)
			st, errno = fs.stat(proc)
			if st then
				local fields = {}; local rest = read(proc .. "/stat"):match("^%d+ %b() (.*)")
				for value in (rest or ""):gmatch("%S+") do fields[#fields + 1] = value end
				need(fields[1] and fields[20] and fields[20]:match("^%d+$"), "unreadable process identity; cleanup retained")
				need(fields[1] == "Z" or fields[20] ~= tostring(record.birth), "live instance lost its ownership record; cleanup retained")
			else need(errno == 2, "cannot establish process absence; cleanup retained") end
			pid, birth = record.pid, record.birth
		end
		endpoint.check_instance(decode(dir .. "/bound.identity"), b.endpoint, dir .. "/config.json", b.config_md5, pid, birth)
	end
	return true
end

if arg and arg[0] and arg[0]:match("runtime_binding%.lua$") then
	local ok, result = pcall(function()
		local action = arg[1]
		if action == "prepare" then return M.prepare(arg[2], arg[3], arg[4], arg[5], arg[6], arg[7])
		elseif action == "spawn" then local args = {}; for i=3,#arg do args[#args+1]=arg[i] end; return M.spawn(arg[2],args)
		elseif action == "hysteria" then return M.start_hysteria(arg[2],arg[3],arg[4],arg[5],arg[6])
		elseif action == "verify" or action == "seal" then return M.verify(arg[2],action == "seal",arg[3],arg[4],arg[5])
		elseif action == "compatible" then return M.compatible(arg[2],arg[3],arg[4],arg[5])
		elseif action == "reference" then return M.compatible(arg[2],arg[3],arg[4],arg[5],true)
		elseif action == "owner" then return M.owner(arg[2]) end
		error("invalid bound runtime action")
	end)
	if not ok then io.stderr:write(tostring(result) .. "\n"); os.exit(1) end
	if type(result) == "string" then print(result) end
end
return M
