-- B3.3-3B. Read-only candidate probe, not a lifecycle/ready provider.
-- CLI is used by dns_dependency.sh; callers must retain its snapshot/cache checks.
-- Only a SOCKS5 no-auth greeting is sent; no CONNECT, DNS or outer probe here.
local api = require "luci.passwall.api"
local nixio = require "nixio"
local bound = require "luci.passwall.runtime_binding"
local endpoint = require "luci.passwall.endpoint_contract"
local fs, json = api.fs, api.jsonc
local M = {}
local function reject(rc, reason) error({rc = rc, reason = reason}, 0) end
local function need(ok, rc, reason) if not ok then reject(rc, reason) end; return ok end
local function read(path) return need(fs.readfile(path), 1, "dns_dep_identity") end
local function decode(path) return need(json.parse(read(path)), 1, "dns_dep_identity") end
local function existing(fn, ...)
	local ok, value = pcall(fn, ...)
	if ok and value then return end
	-- Adapt only known diagnostics of the existing verifier. Do not duplicate
	-- its family/options/identity algorithms or expose raw errors/credentials.
	local reason = "dns_dep_identity"
	if type(value) == "string" then
		for _, marker in ipairs({"instance belongs to another binding/generation", "listener/options unavailable",
			"requested protocol/family unavailable", "requested protocol unavailable", "missing socket option evidence",
			"missing V6ONLY evidence", "ss/inet socket diagnostics unavailable"}) do
			if value:find(marker, 1, true) then reason = "dns_dep_capability"; break end
		end
	end
	reject(1, reason) -- diagnostic refinement never downgrades severity
end
local function port(v)
	local n = tonumber(v)
	return type(v) == "string" and v:match("^%d+$") and n and n >= 1 and n <= 65535 and n % 1 == 0 and n
end
local function remote(value)
	need(type(value) == "string", 1, "dns_dep_argument")
	local host, p = value:match("^%[([^%]]+)%][:#](%d+)$")
	if not host then host, p = value:match("^([^:#]+)[:#](%d+)$") end
	if not host then host = value:match("^%[([^%]]+)%]$") or value; p = "53" end
	local ip, family = endpoint.ip(host)
	if ip then host = ip
	else
		host = host:gsub("%.$", "")
		need(#host > 0 and #host <= 253 and not host:find("[^A-Za-z0-9.%-]") and not host:match("^[%d.]+$"), 2, "dns_dep_argument")
		for label in (host .. "."):gmatch("(.-)%.") do
			need(#label > 0 and #label <= 63 and not label:match("^%-") and not label:match("%-$"), 2, "dns_dep_argument")
		end
	end
	need(port(p), 2, "dns_dep_argument")
	return (family == 6 and ("[" .. host .. "]") or host) .. "#" .. tonumber(p)
end

-- This checks SOCKS socket ownership only. PID/birth/executable/GID identity
-- and all transparent/options evidence remain exclusively in bound.verify.
-- Current B3.1 listeners bind 127.0.0.1. Other SOCKS binds are explicitly
-- rejected until a caller has a supported, verified local endpoint contract.
local function socket_inode(pid, p, peer)
	local owned, found = {}, nil
	local function loopback(address) return address == "0100007F" or address == "7F000001" end
	for fd in fs.dir("/proc/" .. pid .. "/fd") do
		local path = "/proc/" .. pid .. "/fd/" .. fd
		local inode = (fs.readlink(path) or ""):match("^socket:%[(%d+)%]$")
		local st = inode and fs.stat(path)
		if st and st.gid == api.DIRECT_GID then owned[inode] = true end
	end
	for row in read("/proc/net/tcp"):gmatch("[^\n]+") do
		local f = {}; for word in row:gmatch("%S+") do f[#f + 1] = word end
		local addr, lp = (f[2] or ""):match("^(%x+):(%x+)$")
		local ra, rp = (f[3] or ""):match("^(%x+):(%x+)$")
		if loopback(addr) and tonumber(lp, 16) == p and owned[f[10]] and
			((not peer and f[4] == "0A") or (peer and f[4] == "01" and loopback(ra) and tonumber(rp, 16) == peer)) then
			need(not found or found == f[10], 1, "dns_dep_identity")
			found = f[10]
		end
	end
	return need(found, 2, "dns_dep_socks")
end

-- May also be called as an isolated capability probe. It does not establish
-- process identity; M.check always surrounds it with the existing verifier.
function M.probe_socks(pid, p)
	pid = tostring(pid)
	need(pid:match("^%d+$") and tonumber(pid) > 0 and type(p) == "number" and p >= 1 and p <= 65535 and p % 1 == 0, 1, "dns_dep_argument")
	local listener = socket_inode(pid, p)
	local sock = need(nixio.socket("inet", "stream"), 2, "dns_dep_socks")
	local ok, err = pcall(function()
		sock:setblocking(false)
		local connected, errno = sock:connect("127.0.0.1", p)
		need(connected or errno == 115 or errno == 11, 2, "dns_dep_socks")
		local function wait(event)
			local n = nixio.poll({{fd = sock, events = nixio.poll_flags(event)}}, 2000)
			need(n and n > 0, 2, "dns_dep_socks")
		end
		wait("out")
		local data = string.char(5, 1, 0)
		while #data > 0 do
			local sent = sock:send(data)
			need(sent and sent > 0, 2, "dns_dep_socks"); data = data:sub(sent + 1)
		end
		local response = ""
		while #response < 2 do
			wait("in")
			local part = sock:recv(2 - #response)
			need(part and #part > 0, 2, "dns_dep_socks"); response = response .. part
		end
		need(response == string.char(5, 0), 2, "dns_dep_socks")
		local addr, peer = sock:getsockname()
		need(addr == "127.0.0.1" and peer, 2, "dns_dep_socks")
		-- Bind the negotiated connection itself to the expected PID as well
		-- as its listener; a foreign/reused port cannot satisfy this probe.
		socket_inode(pid, p, peer)
		need(socket_inode(pid, p) == listener, 1, "dns_dep_identity")
	end)
	sock:close()
	if not ok then error(err, 0) end
end

function M.check(action, snapshot, node, dir, transparent_port, preference, family, scope, shunt, mode, dns, cache)
	local candidate
	local ok, err = pcall(function()
		need(action == "resolve" or action == "validate", 1, "dns_dep_argument")
		need(family == "4" or family == "6" or family == "dual", 1, "dns_dep_argument")
		need(preference == "ipv4" or preference == "ipv6" or preference == "ipv4-only" or preference == "ipv6-only", 1, "dns_dep_argument")
		need(shunt == "dnsmasq" and mode == "dns2socks", 2, "dns_dep_backend_unsupported")
		need(port(transparent_port) and (cache == "0" or cache == "1"), 2, "dns_dep_argument")
		local normalized_dns = remote(dns)
		local stat, errno = fs.stat(dir)
		if not stat and errno == 2 then reject(1, "dns_dep_no_instance") end
		need(stat and fs.realpath(dir) == dir, 1, "dns_dep_identity")
		for _, file in ipairs({"binding.json", "bound.identity"}) do
			stat, errno = fs.stat(dir .. "/" .. file)
			if not stat and errno == 2 then reject(1, "dns_dep_unbound_instance") end
			need(stat, 1, "dns_dep_identity")
		end
		local b, identity = decode(dir .. "/binding.json"), decode(dir .. "/bound.identity")
		need(b.snapshot == snapshot and b.endpoint.generation == snapshot:match("([^/]+)$"), 1, "dns_dep_stale_generation")
		need(b.endpoint.node_id == node and identity.generation == b.endpoint.generation, 1, "dns_dep_identity")
		existing(bound.owner, dir)
		existing(bound.compatible, dir, snapshot, preference, family)
		for _, f in ipairs(family == "dual" and {"4", "6"} or {family}) do
			existing(bound.verify, dir, false, f, "tcp", transparent_port)
		end
		local c, n = decode(dir .. "/config.json"), b.endpoint.original_node
		if n.type == "SS" then existing(require("luci.passwall.util_shadowsocks").validate_method, n.method)
		else need(n.type == "Hysteria", 1, "dns_dep_identity") end
		local socks_port = fs.readfile(dir .. "/socks_port")
		need(socks_port, 2, "dns_dep_socks")
		socks_port = port(socks_port:gsub("\n$", ""))
		need(socks_port, 2, "dns_dep_socks")
		if n.type == "SS" then
			need(fs.access(dir .. "/relay/process") and c.local_address == "127.0.0.1" and c.local_port == socks_port and c.mode ~= "udp_only", 2, "dns_dep_socks")
		else
			need(c.socks5 and c.socks5.listen == "127.0.0.1:" .. socks_port and not c.socks5.user and not c.socks5.password, 2, "dns_dep_socks")
		end
		candidate = {scope = scope, generation = b.endpoint.generation, node_id = node,
			node_type = n.type, node_method = n.method, instance_dir = dir,
			socks_addr = "127.0.0.1", socks_port = socks_port, family = family,
			remote_dns = normalized_dns, dns_cache = tonumber(cache), endpoint_addr = b.endpoint.address,
			endpoint_port = b.endpoint.port, config_md5 = b.config_md5,
			identity_md5 = api.md5_file(dir .. "/bound.identity"), state = "dep_resolved"}
		need(type(candidate.identity_md5) == "string" and #candidate.identity_md5 == 32 and candidate.identity_md5:match("^%x+$"), 1, "dns_dep_identity")
		if action == "validate" then
			M.probe_socks(identity.pid, socks_port)
			existing(bound.owner, dir)
			existing(bound.compatible, dir, snapshot, preference, family)
			need(api.md5_file(dir .. "/bound.identity") == candidate.identity_md5, 1, "dns_dep_identity")
			candidate.state = "dep_validated"
		end
	end)
	if ok then return 0, "", candidate end
	local rc, reason = 1, "dns_dep_identity"
	if type(err) == "table" then rc, reason = err.rc, err.reason end
	if candidate then candidate.state = nil; candidate.reason = reason end
	return rc, reason, candidate
end

if arg and arg[0] and arg[0]:match("dependency_probe%.lua$") then
	local rc, reason, candidate = M.check(unpack(arg))
	print(reason); print(candidate and candidate.state or ""); print(candidate and json.stringify(candidate) or "")
	os.exit(rc)
end
return M
