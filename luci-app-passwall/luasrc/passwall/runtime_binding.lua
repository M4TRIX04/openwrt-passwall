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
-- Global SS keeps ss-redir as its primary process. Its private ss-local uses
-- the same endpoint/identity format, with no independent resource reference.
local function ss_socks_config(dir, b)
	local s = b.ss_socks
	if s == nil then return end
	local runtime = b.snapshot:match("^(.*)/contracts/generation%.[%w_]+$")
	need(type(s) == "table" and b.endpoint.original_node.type == "SS" and not b.socks_tcp_socket and
		runtime and dir:match("^(.*)/acl/default/split/instance%.[%w_]+$") == runtime,
		"invalid Global SS SOCKS binding")
	for key in pairs(s) do need(key == "socket" or key == "config_md5", "unknown SS SOCKS field") end
	local socket = need(socks_declaration(s.socket), "missing SS SOCKS socket declaration")
	need(fs.realpath(dir .. "/socks") == dir .. "/socks", "invalid SS SOCKS directory")
	need(digest(dir .. "/socks/config.json") == s.config_md5, "SS SOCKS configuration changed")
	local config = decode(dir .. "/socks/config.json")
	endpoint.config(b.endpoint, config)
	socks_config(socket, "SS", config)
	need(config.mode == "tcp_only" and not config.tcp_tproxy, "invalid SS SOCKS listener mode")
	local tcp = read(dir .. "/meta"):match("^[^\n]+\n[^\n]+\n([^\n]*)\n")
	local relay, errno = fs.lstat(dir .. "/relay")
	need(tcp and tcp ~= "" and not relay and errno == 2, "invalid SS SOCKS transparent role")
	return s
end
local function ss_socks_identity(dir, b, pid, birth)
	local s = need(ss_socks_config(dir, b), "missing SS SOCKS binding")
	local path = dir .. "/socks/bound.identity"
	local st = fs.lstat(path)
	need(st and st.type == "reg", "missing/invalid SS SOCKS identity")
	local record = decode(path)
	endpoint.check_instance(record, b.endpoint, dir .. "/socks/config.json", s.config_md5,
		pid or record.pid, birth or record.birth)
	return record
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
	ss_socks_config(dir, b)
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
	local ss_socks = socks_declaration(params.ss_socks_tcp_socket)
	params.socks_tcp_socket = nil -- binding metadata, never a generator input
	params.ss_socks_tcp_socket = nil
	need(not ss_socks or (node.type == "SS" and not socks), "invalid auxiliary SOCKS request")
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
	local auxiliary
	if ss_socks then
		local runtime = snapshot_dir:match("^(.*)/contracts/generation%.[%w_]+$")
		need(runtime and dir:match("^(.*)/acl/default/split/instance%.[%w_]+$") == runtime,
			"SS auxiliary SOCKS requires a Global instance")
		local tcp = read(dir .. "/meta"):match("^[^\n]+\n[^\n]+\n([^\n]*)\n")
		need(tcp and tcp ~= "", "SS auxiliary SOCKS requires transparent TCP")
		local local_config = need(json.parse(module.gen_config({node = id, frozen_node = e.generator_node,
			local_addr = ss_socks.address, local_port = ss_socks.port, mode = "tcp_only"})),
			"generator rejected frozen SOCKS node")
		endpoint.config(e, local_config)
		socks_config(ss_socks, "SS", local_config)
		need(fs.mkdir(dir .. "/socks"), "cannot create private SS SOCKS directory")
		write(dir .. "/socks/config.json", local_config)
		auxiliary = {socket = ss_socks, config_md5 = digest(dir .. "/socks/config.json")}
	end
	write(dir .. "/binding.json", {snapshot = snapshot_dir, endpoint = e, family = family,
		config_md5 = digest(dir .. "/config.json"), endpoint_md5 = digest(path), gid = api.DIRECT_GID,
		socks_tcp_socket = socks, ss_socks = auxiliary})
end

function M.spawn(log, argv)
	need(api.DIRECT_GID == 9911 and #argv > 0, "unexpected direct identity")
	local parts = {}; for _, value in ipairs(argv) do parts[#parts + 1] = quote(value) end
	local rc, out = api.exec_call_as_gid(table.concat(parts, " ") .. " >" .. quote(log) .. " 2>&1 & echo $!", api.DIRECT_GID)
	need(rc == 0 and out:match("^%d+$"), "GID launcher failed")
	return out
end
function M.start_hysteria(dir, bin, bin_dir, log, level, creation, directory)
	if creation ~= nil or directory ~= nil then
		return M.private_start_hysteria(dir, bin, bin_dir, log, level, creation, directory)
	end
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
	local socks_pid, socks_birth, socks_owner = pid, birth, nil
	if b.ss_socks then
		if seal then
			local st, errno = fs.lstat(dir .. "/socks/bound.identity")
			need(not st and errno == 2, "SS SOCKS seal already exists or cannot establish absence")
		end
		local executable
		socks_pid, socks_birth, executable = process(dir .. "/socks", "SS")
		need(socks_pid ~= pid, "SS SOCKS must have its own process")
		identity(socks_pid, socks_birth, b.gid)
		need(fs.realpath(executable) == fs.readlink("/proc/" .. socks_pid .. "/exe"), "SS SOCKS executable changed")
		socks_owner = endpoint.instance(b.endpoint, dir .. "/socks/config.json", b.ss_socks.config_md5, socks_pid, socks_birth)
		if require_seal or fs.access(dir .. "/socks/bound.identity") then ss_socks_identity(dir, b, socks_pid, socks_birth) end
	end
	local diag, capabilities = diagnostics(), {}
	local config = decode(dir .. "/config.json")
	local socks = b.ss_socks and b.ss_socks.socket or b.socks_tcp_socket
	if socks then
		capabilities.socks_tcp_socket = sockets(socks_pid, "tcp", socks.port, b.gid, false, diag, "127.0.0.1")
		need(capabilities.socks_tcp_socket["4"], "SOCKS TCP socket unavailable at exact loopback")
		need(line(dir .. "/socks_port") == tostring(socks.port), "sealed SOCKS port changed")
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
	if b.ss_socks then identity(socks_pid, socks_birth, b.gid) end
	if seal then
		if socks_owner then write(dir .. "/socks/bound.identity", socks_owner) end
		write(dir .. "/bound.identity", owner); write(dir .. "/bound.capabilities", capabilities)
	end
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
local function owned_process(dir, b, record)
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
	return pid, birth
end
function M.owner(dir)
	local b = decode(dir .. "/binding.json")
	if fs.access(dir .. "/bound.identity") then
		local record = decode(dir .. "/bound.identity")
		local pid, birth = owned_process(dir, b, record)
		endpoint.check_instance(decode(dir .. "/bound.identity"), b.endpoint, dir .. "/config.json", b.config_md5, pid, birth)
		if b.ss_socks then
			local socks_pid, socks_birth = process(dir .. "/socks", "SS")
			ss_socks_identity(dir, b, socks_pid, socks_birth)
		end
	end
	return true
end

-- Public stop only: require sealed ownership under the caller's runtime root.
-- This is not a private unsealed rollback exception. A complete empty SS birth
-- line may reach the stop observer, but never authorizes a signal or reclamation.
function M.stop_owner(dir, runtime)
	need(type(runtime) == "string" and runtime:match("^/[%w_./-]+$") and
		fs.realpath(runtime) == runtime, "invalid expected stop runtime root")
	local parent = dir:match("^(.*)/instance%.[%w_]+$")
	need((parent == runtime .. "/acl/default/split" or parent == runtime .. "/acl/split-acl") and
		fs.realpath(dir) == dir, "invalid stop responsibility directory")
	local path = dir .. "/bound.identity"
	local st, errno = fs.lstat(path)
	if not st then
		need(errno == 2, "cannot inspect stop identity; cleanup retained")
		need(false, "missing stop identity; cleanup retained")
	end
	need(st.type == "reg", "invalid stop identity file type; cleanup retained")
	local fd, _, open_errno = io.open(path, "r")
	need(fd, "cannot open stop identity (errno " .. tostring(open_errno) .. "); cleanup retained")
	local data = fd:read("*a"); local closed = fd:close()
	need(type(data) == "string" and closed, "cannot read stop identity; cleanup retained")
	local record = json.parse(data)
	need(type(record) == "table", "invalid stop identity JSON; cleanup retained")
	local b = binding(dir)
	need(b.snapshot:match("^(.*)/contracts/generation%.[%w_]+$") == runtime, "stop snapshot runtime mismatch")
	local core = b.endpoint.original_node.type
	local meta_core, node = read(dir .. "/meta"):match("^([^\n]+)\n([^\n]+)\n")
	need(b.gid == api.DIRECT_GID and meta_core == core and node == b.endpoint.node_id,
		"stop instance metadata mismatch")
	endpoint.check_instance(record, b.endpoint, dir .. "/config.json", b.config_md5, record.pid, record.birth)
	local pid, birth
	if core == "SS" then
		local command
		pid, birth, command = read(dir .. "/process"):match("^(%d+)\n(%d*)\n([^\n]+)\n$")
		need(pid, "invalid stop process record")
		local executable, config = quote(dir .. "/core"), quote(dir .. "/config.json")
		need(command == executable .. " -c " .. config .. " -v" or
			command == executable .. " " .. quote("-c") .. " " .. config .. " " .. quote("-v"), "invalid stop process command")
		if birth == "" then birth = record.birth end -- comparison only; never write or signal with this birth
	else
		pid, birth = owned_process(dir, b, record)
	end
	endpoint.check_instance(record, b.endpoint, dir .. "/config.json", b.config_md5, pid, birth)
	if b.ss_socks then
		local socks_record = ss_socks_identity(dir, b)
		local socks_pid, socks_birth, command = read(dir .. "/socks/process"):match("^(%d+)\n(%d*)\n([^\n]+)\n$")
		need(socks_pid, "invalid SS SOCKS stop process record")
		local executable, config = quote(dir .. "/socks/core"), quote(dir .. "/socks/config.json")
		need(command == executable .. " -c " .. config .. " -v" or
			command == executable .. " " .. quote("-c") .. " " .. config .. " " .. quote("-v"),
			"invalid SS SOCKS stop process command")
		if socks_birth == "" then socks_birth = socks_record.birth end -- comparison only, as for the primary
		endpoint.check_instance(socks_record, b.endpoint, dir .. "/socks/config.json", b.ss_socks.config_md5, socks_pid, socks_birth)
	else
		local socks_dir, errno = fs.lstat(dir .. "/socks")
		need(not socks_dir and errno == 2, "undeclared SS SOCKS directory; cleanup retained")
	end
	return true
end

-- F1: creation-local receipts only. These checks never authorize public stop,
-- repair a seal, publish a capability, or require a failed listener to be ready.
local function private_location(dir, runtime)
	need(type(runtime) == "string" and fs.realpath(runtime) == runtime and
		dir:match("^(.*)/instance%.[%w_]+$") == runtime .. "/acl/default/split" and
		fs.realpath(dir) == dir, "invalid private rollback directory")
end
local function private_absent(path)
	local st, errno = fs.lstat(path)
	need(not st and errno == 2, "cannot establish private absence: " .. path)
end
local function private_file(path, optional)
	local st, errno = fs.lstat(path)
	if not st then need(optional and errno == 2, "cannot inspect private record: " .. path); return false end
	need(st.type == "reg", "invalid private record type: " .. path)
	return true
end
function M.private_directory(dir, runtime, expected_snapshot)
	private_location(dir, runtime)
	need(type(expected_snapshot) == "string" and
		expected_snapshot:match("^(.*)/contracts/generation%.[%w_]+$") == runtime, "invalid private directory snapshot")
	private_file(dir .. "/meta")
	local st = fs.lstat(dir)
	need(st and st.type == "dir" and type(st.dev) == "number" and type(st.ino) == "number" and
		type(st.uid) == "number", "cannot establish private directory identity")
	return json.stringify({dir = dir, runtime = runtime, snapshot = expected_snapshot,
		dev = st.dev, ino = st.ino, uid = st.uid, meta_md5 = digest(dir .. "/meta")})
end
function M.private_discard_owner(dir, runtime, creation, expected_snapshot)
	private_location(dir, runtime)
	local receipt = need(json.parse(creation or ""), "missing private directory receipt")
	local st = fs.lstat(dir)
	need(receipt.dir == dir and receipt.runtime == runtime and receipt.snapshot == expected_snapshot and
		st and st.type == "dir" and type(receipt.dev) == "number" and type(receipt.ino) == "number" and
		type(receipt.uid) == "number" and st.dev == receipt.dev and st.ino == receipt.ino and st.uid == receipt.uid,
		"private directory identity changed")
	private_file(dir .. "/meta")
	need(digest(dir .. "/meta") == receipt.meta_md5, "private directory metadata changed")
	-- The caller has not invoked a launcher. Reject contradictory canonical
	-- or pending process/seal records rather than treating their absence as proof.
	local forbidden = {"core", "process", "process.new", "bound.identity", "bound.identity.new",
		"bound.capabilities", "bound.capabilities.new"}
	for _, file in ipairs(forbidden) do private_absent(dir .. "/" .. file) end
	private_absent(dir .. "/relay")
	local child, errno = fs.lstat(dir .. "/socks")
	if child then
		need(child.type == "dir" and child.dev == st.dev and child.uid == st.uid and
			fs.realpath(dir .. "/socks") == dir .. "/socks", "invalid private child directory")
		for _, file in ipairs(forbidden) do private_absent(dir .. "/socks/" .. file) end
	else need(errno == 2, "cannot inspect private child directory") end
	local id = api.md5_string(dir .. "/config.json")
	private_absent("/tmp/etc/passwall_hysteria1/" .. id .. ".json")
	private_absent("/tmp/etc/passwall_hysteria1/" .. id .. ".json.new")
	private_absent(runtime .. "/bin/hysteria1_" .. id)
	return true
end
function M.private_receipt(dir, runtime, expected_snapshot)
	private_location(dir, runtime)
	for _, file in ipairs({"binding.json", "meta", "config.json"}) do private_file(dir .. "/" .. file) end
	local b = binding(dir)
	need(b.snapshot == expected_snapshot and b.snapshot:match("^(.*)/contracts/generation%.[%w_]+$") == runtime and
		b.gid == api.DIRECT_GID, "private creation binding mismatch")
	local core = b.endpoint.original_node.type
	need(core == "SS" or core == "Hysteria", "invalid private core")
	for _, file in ipairs({"process", "core", "bound.identity", "bound.capabilities"}) do private_absent(dir .. "/" .. file) end
	if b.ss_socks then
		private_file(dir .. "/socks/config.json")
		for _, file in ipairs({"process", "core", "bound.identity"}) do private_absent(dir .. "/socks/" .. file) end
	else private_absent(dir .. "/socks") end
	if core == "Hysteria" then private_absent("/tmp/etc/passwall_hysteria1/" .. api.md5_string(dir .. "/config.json") .. ".json") end
	return json.stringify({dir = dir, runtime = runtime, snapshot = b.snapshot,
		binding_md5 = digest(dir .. "/binding.json"), meta_md5 = digest(dir .. "/meta")})
end
function M.private_hysteria_receipt(dir)
	local b = binding(dir)
	need(b.endpoint.original_node.type == "Hysteria", "invalid private Hysteria receipt")
	local path = "/tmp/etc/passwall_hysteria1/" .. api.md5_string(dir .. "/config.json") .. ".json"
	private_file(path)
	local pid, birth = process(dir, "Hysteria")
	return json.stringify({pid = pid, birth = birth, manager_md5 = digest(path)})
end
-- This receipt exists only in the creating call. It is not a public stop
-- exception and cannot be reconstructed from missing configuration/records.
function M.private_hysteria_released_owner(dir, runtime, creation, directory, released)
	local c = need(json.parse(creation or ""), "missing private creation receipt")
	local d = need(json.parse(directory or ""), "missing private directory receipt")
	local result = need(json.parse(released or ""), "missing Hysteria release receipt")
	need(result.kind == "private_hysteria_released" and type(result.creation) == "table" and
		type(result.directory) == "table" and type(result.release) == "table", "invalid Hysteria release receipt")
	for _, key in ipairs({"dir", "runtime", "snapshot", "binding_md5", "meta_md5"}) do
		need(c[key] ~= nil and result.creation[key] == c[key], "Hysteria creation context changed")
	end
	for _, key in ipairs({"dir", "runtime", "snapshot", "dev", "ino", "uid", "meta_md5"}) do
		need(d[key] ~= nil and result.directory[key] == d[key], "Hysteria directory context changed")
	end
	need(c.dir == dir and c.runtime == runtime and c.snapshot == d.snapshot and
		digest(dir .. "/binding.json") == c.binding_md5 and digest(dir .. "/meta") == c.meta_md5,
		"Hysteria private binding changed")
	-- Reuse the directory/boundary and contradictory-record checks only. The
	-- positive release receipt below, not absence, authorizes this path.
	M.private_discard_owner(dir, runtime, directory, c.snapshot)
	private_file(dir .. "/binding.json")
	private_absent(dir .. "/config.json"); private_absent(dir .. "/config.json.new")
	private_absent(dir .. "/socks")
	local b = decode(dir .. "/binding.json")
	local node, source, generation = frozen(b.snapshot, b.endpoint.node_id)
	endpoint.check(b.endpoint, generation, source, b.endpoint.node_id, node)
	need(b.snapshot == c.snapshot and node.type == "Hysteria" and b.gid == api.DIRECT_GID and
		digest(b.snapshot .. "/endpoints/" .. b.endpoint.node_id .. "." .. b.endpoint.preference .. ".json") == b.endpoint_md5,
		"Hysteria frozen endpoint changed")
	local r = result.release
	local id = api.md5_string(dir .. "/config.json")
	need(r.config == dir .. "/config.json" and r.config_md5 == b.config_md5 and
		r.manager == "/tmp/etc/passwall_hysteria1/" .. id .. ".json" and r.link == runtime .. "/bin/hysteria1_" .. id and
		r.config_removed == true and r.link_removed == true and r.manager_removed == true and type(r.rules) == "table",
		"incomplete Hysteria resource release")
	for _, rule in ipairs(r.rules) do
		need(type(rule) == "table" and type(rule.rule) == "string" and
			(rule.disposition == "shared" or rule.disposition == "removed" or rule.disposition == "unowned"),
			"incomplete Hysteria rule release")
	end
	if r.launch_attempted == false then
		need(r.process == "not_started" and r.pid == nil and r.birth == nil, "contradictory Hysteria no-launch receipt")
	else
		need(r.launch_attempted == true and type(r.pid) == "number" and r.pid > 0 and r.pid % 1 == 0 and
			(r.process == "absent" or r.process == "zombie"), "incomplete Hysteria process release")
		need(read("/proc/self/stat"):match("^%d+ "), "cannot establish Hysteria proc view")
		local f, _, errno = io.open("/proc/" .. r.pid .. "/stat", "r")
		if f then
			local data = f:read("*a"); local closed = f:close()
			need(data and closed, "cannot read released Hysteria process")
			local pid, rest = data:match("^(%d+) .*%) (.*)$")
			local fields = {}; for value in (rest or ""):gmatch("%S+") do fields[#fields+1] = value end
			need(pid == tostring(r.pid) and fields[1] == "Z" and type(r.birth) == "string" and fields[20] == r.birth,
				"released Hysteria process identity conflict")
		else need(errno == 2, "cannot inspect released Hysteria process") end
	end
	return true
end
function M.private_start_hysteria(dir, bin, bin_dir, log, level, creation, directory)
	local c = need(json.parse(creation or ""), "missing private Hysteria creation context")
	need(bin_dir == c.runtime .. "/bin", "private Hysteria link directory changed")
	M.private_discard_owner(dir, c.runtime, directory, c.snapshot)
	local current = need(json.parse(M.private_receipt(dir, c.runtime, c.snapshot)), "invalid private Hysteria context")
	for _, key in ipairs({"dir", "runtime", "snapshot", "binding_md5", "meta_md5"}) do
		need(current[key] == c[key], "private Hysteria creation context changed")
	end
	local b = binding(dir)
	local core, node, tcp, udp = read(dir .. "/meta"):match("^([^\n]+)\n([^\n]+)\n([^\n]*)\n([^\n]*)\n$")
	need(core == "Hysteria" and b.endpoint.original_node.type == core and node == b.endpoint.node_id and
		(tcp ~= "" or udp ~= ""), "invalid private Hysteria metadata")
	if b.socks_tcp_socket then need(line(dir .. "/socks_port") == tostring(b.socks_tcp_socket.port), "private SOCKS port changed") end
	local result = require("luci.passwall.hysteria_runtime").start({config=dir .. "/config.json", bin=bin,
		bin_dir=bin_dir, scope="client", mode="client", log=log, loglevel=level, gid=api.DIRECT_GID,
		bound_endpoint=true, private_release={config_md5=b.config_md5}})
	if result == true then return true end
	need(type(result) == "table" and result.started == false, "invalid private Hysteria start result")
	io.stderr:write(tostring(result.reason) .. "\n")
	need(result.release_complete == true, "private Hysteria release remains unproven")
	local receipt = json.stringify({kind="private_hysteria_released", creation=c,
		directory=need(json.parse(directory), "invalid private directory receipt"), release=result.receipt})
	M.private_hysteria_released_owner(dir, c.runtime, creation, directory, receipt)
	return {private_hysteria_released=receipt}
end
local function private_process(dir, b, core, config_md5, started, pid, birth, manager, memory, write_failed)
	need(started == "0" or started == "1", "unknown private launch attempt")
	local config = dir .. "/config.json"
	local manager_path = "/tmp/etc/passwall_hysteria1/" .. api.md5_string(config) .. ".json"
	if started == "0" then
		-- This is the caller's positive record of no launch attempt, not an
		-- inference from a missing process file or an empty reference cache.
		need(pid == "" and birth == "" and (manager or "") == "", "contradictory private no-launch receipt")
		if core == "SS" then need(memory == "" and write_failed == "0", "contradictory private SS write receipt") end
		private_absent(core == "SS" and (dir .. "/process") or manager_path)
		private_absent(dir .. "/bound.identity")
		return
	end
	local executable
	if core == "Hysteria" then
		local receipt = need(json.parse(manager or ""), "missing private Hysteria receipt")
		pid, birth = receipt.pid, receipt.birth
		private_file(manager_path)
		need(digest(manager_path) == receipt.manager_md5, "private Hysteria receipt changed")
		local actual_pid, actual_birth
		actual_pid, actual_birth, executable = process(dir, core)
		need(actual_pid == pid and actual_birth == birth, "private Hysteria process changed")
	else
		need(type(memory) == "string" and (write_failed == "0" or write_failed == "1"), "missing private SS write receipt")
		local actual_pid, actual_birth, command = memory:match("^(%d+)\n(%d+)\n([^\n]+)\n$")
		need(actual_pid and actual_pid == pid and actual_birth == birth, "private SS memory receipt changed or incomplete")
		executable = dir .. "/core"
		need(command == quote(executable) .. " -c " .. quote(config) .. " -v" or
			command == quote(executable) .. " " .. quote("-c") .. " " .. quote(config) .. " " .. quote("-v"),
			"private SS process command changed")
		if private_file(dir .. "/process", write_failed == "1") then
			local fd = need(io.open(dir .. "/process", "r"), "cannot open private SS disk receipt")
			local disk = fd:read("*a"); local closed = fd:close()
			need(type(disk) == "string" and closed, "cannot read private SS disk receipt")
			need(disk == memory or (write_failed == "1" and #disk < #memory and memory:sub(1, #disk) == disk),
				"private SS disk receipt conflicts with memory")
		end
	end
	need(type(pid) == "string" and pid:match("^%d+$") and tonumber(pid) > 0 and
		type(birth) == "string" and birth:match("^%d+$"), "incomplete private PID/birth")
	if private_file(dir .. "/bound.identity", true) then
		endpoint.check_instance(decode(dir .. "/bound.identity"), b.endpoint, config, config_md5, pid, birth)
	end
	-- Reuse the stop observer's distinction between a gone/replaced process
	-- and unreadable /proc. A reused PID is never checked or signalled as ours.
	need(read("/proc/self/stat"):match("^%d+ "), "cannot establish private proc view")
	local f, _, errno = io.open("/proc/" .. pid .. "/stat", "r")
	if not f then need(errno == 2, "cannot inspect private process"); return end
	local data = f:read("*a"); local closed = f:close()
	need(data and closed, "cannot read private process")
	local actual, rest = data:match("^(%d+) .*%) (.*)$")
	local fields = {}; for value in (rest or ""):gmatch("%S+") do fields[#fields + 1] = value end
	need(actual == pid and fields[1] and fields[1]:match("^[A-Za-z]$") and fields[20] and fields[20]:match("^%d+$"),
		"invalid private process stat")
	if fields[20] ~= birth or fields[1] == "Z" then return end
	identity(pid, birth, b.gid)
	need(fs.realpath(executable) == fs.readlink("/proc/" .. pid .. "/exe"), "private executable changed")
	local argv = {}; for value in read("/proc/" .. pid .. "/cmdline"):gmatch("([^%z]+)%z") do argv[#argv + 1] = value end
	if core == "SS" then
		need(#argv == 4 and argv[1] == executable and argv[2] == "-c" and argv[3] == config and argv[4] == "-v",
			"private SS live command changed")
	else
		need(#argv == 7 and argv[1] == executable and argv[2] == "--no-check" and argv[3] == "--log-level" and
			argv[5] == "-c" and argv[6] == config and argv[7] == "client", "private Hysteria live command changed")
	end
end
function M.private_owner(dir, runtime, creation, main_started, pid, birth, socks_started, socks_pid, socks_birth, manager,
	main_memory, main_write_failed, socks_memory, socks_write_failed)
	private_location(dir, runtime)
	local receipt = need(json.parse(creation or ""), "missing private creation receipt")
	need(receipt.dir == dir and receipt.runtime == runtime and
		digest(dir .. "/binding.json") == receipt.binding_md5 and digest(dir .. "/meta") == receipt.meta_md5,
		"private creation receipt changed")
	for _, file in ipairs({"binding.json", "meta", "config.json"}) do private_file(dir .. "/" .. file) end
	local b = binding(dir) -- frozen integrity only; never require live-UCI freshness or ready sockets
	need(b.snapshot == receipt.snapshot and b.snapshot:match("^(.*)/contracts/generation%.[%w_]+$") == runtime and
		b.gid == api.DIRECT_GID, "private rollback binding mismatch")
	local core, node, tcp, udp = read(dir .. "/meta"):match("^([^\n]+)\n([^\n]+)\n([^\n]*)\n([^\n]*)\n$")
	need(core == b.endpoint.original_node.type and node == b.endpoint.node_id and (tcp ~= "" or udp ~= ""),
		"private metadata mismatch")
	local socks = b.ss_socks and b.ss_socks.socket or b.socks_tcp_socket
	if socks then need(line(dir .. "/socks_port") == tostring(socks.port), "private SOCKS port changed") end
	private_process(dir, b, core, b.config_md5, main_started, pid, birth, manager, main_memory, main_write_failed)
	if b.ss_socks then
		private_file(dir .. "/socks/config.json")
		private_process(dir .. "/socks", b, "SS", b.ss_socks.config_md5, socks_started, socks_pid, socks_birth,
			nil, socks_memory, socks_write_failed)
	else
		need(socks_started == "0" and socks_pid == "" and socks_birth == "" and
			socks_memory == "" and socks_write_failed == "0", "unexpected private SOCKS receipt")
		private_absent(dir .. "/socks")
	end
	if private_file(dir .. "/bound.capabilities", true) then
		-- A canonical capabilities file follows the identity writes. Pending
		-- .new files are not seals; they are removed only with the owned directory.
		private_file(dir .. "/bound.identity")
		if b.ss_socks then private_file(dir .. "/socks/bound.identity") end
		local expected = {}
		for proto, port in pairs({tcp = tcp, udp = udp}) do
			if port ~= "" then
				expected[proto] = {}; for _, family in ipairs(b.family == "dual" and {"4", "6"} or {b.family}) do expected[proto][family] = true end
			end
		end
		if socks then expected.socks_tcp_socket = {["4"] = true} end
		check_capabilities(dir, expected)
	end
	return true
end

if arg and arg[0] and arg[0]:match("runtime_binding%.lua$") then
	local ok, result = pcall(function()
		local action = arg[1]
		if action == "prepare" then return M.prepare(arg[2], arg[3], arg[4], arg[5], arg[6], arg[7])
		elseif action == "spawn" then local args = {}; for i=3,#arg do args[#args+1]=arg[i] end; return M.spawn(arg[2],args)
		elseif action == "hysteria" then return M.start_hysteria(arg[2],arg[3],arg[4],arg[5],arg[6],
			os.getenv("PW_BOUND_PRIVATE_CREATION"),os.getenv("PW_BOUND_PRIVATE_DIRECTORY"))
		elseif action == "verify" or action == "seal" then return M.verify(arg[2],action == "seal",arg[3],arg[4],arg[5])
		elseif action == "compatible" then return M.compatible(arg[2],arg[3],arg[4],arg[5])
		elseif action == "reference" then return M.compatible(arg[2],arg[3],arg[4],arg[5],true)
		elseif action == "private-directory" then return M.private_directory(arg[2],arg[3],arg[4])
		elseif action == "private-discard-owner" then return M.private_discard_owner(arg[2],arg[3],arg[4],arg[5])
		elseif action == "private-receipt" then return M.private_receipt(arg[2],arg[3],arg[4])
		elseif action == "private-hysteria" then return M.private_hysteria_receipt(arg[2])
		elseif action == "private-hysteria-released-owner" then return M.private_hysteria_released_owner(arg[2],arg[3],arg[4],arg[5],arg[6])
		elseif action == "private-owner" then return M.private_owner(arg[2],arg[3],arg[4],arg[5],arg[6],arg[7],arg[8],arg[9],arg[10],arg[11],arg[12],arg[13],arg[14],arg[15])
		elseif action == "owner" then
			if arg[3] == "stop" then return M.stop_owner(arg[2], arg[4]) end
			need(arg[3] == nil, "invalid owner mode")
			return M.owner(arg[2])
		end
		error("invalid bound runtime action")
	end)
	if not ok then io.stderr:write(tostring(result) .. "\n"); os.exit(1) end
	if type(result) == "table" and result.private_hysteria_released then print(result.private_hysteria_released); os.exit(2) end
	if type(result) == "string" then print(result) end
end
return M
