-- B3.3-1 pure preparation. No launch, cache publication, UCI writes or rules.
local M = {}
local function need(ok, message) if not ok then error("Endpoint contract: " .. message, 0) end end
local function copy(v)
	if type(v) ~= "table" then return v end
	local out = {}; for k, value in pairs(v) do out[k] = copy(value) end; return out
end
local function equal(a, b)
	if type(a) ~= type(b) then return false end
	if type(a) ~= "table" then return a == b end
	for k, v in pairs(a) do if not equal(v, b[k]) then return false end end
	for k in pairs(b) do if a[k] == nil then return false end end
	return true
end
local function ipv4(s)
	local out = {}
	for part in s:gmatch("[^.]+") do
		if not part:match("^%d+$") or #part > 3 or tonumber(part) > 255 or (#part > 1 and part:sub(1, 1) == "0") then return nil end
		out[#out + 1] = part
	end
	if #out == 4 and table.concat(out, ".") == s then return s end
end
function M.ip(s)
	if type(s) ~= "string" then return nil end
	local v4 = ipv4(s); if v4 then return v4, 4 end
	if not s:find(":", 1, true) or s:find("[^%x:%.]") then return nil end
	-- Expand mapped IPv4 before counting IPv6 groups.
	if s:find("%.") then
		local prefix, tail = s:match("^(.*:)([^:]+)$")
		if not prefix or not ipv4(tail) then return nil end
		local a, b, c, d = tail:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
		s = prefix .. string.format("%x:%x", a * 256 + b, c * 256 + d)
	end
	local left, right = s:match("^(.-)::(.-)$")
	if left and right:find("::", 1, true) then return nil end
	local function groups(text)
		local result = {}
		if text == "" then return result end
		if text:sub(1, 1) == ":" or text:sub(-1) == ":" then return nil end
		for item in text:gmatch("[^:]+") do
			if #item > 4 or not item:match("^%x+$") then return nil end
			result[#result + 1] = string.format("%x", tonumber(item, 16))
		end
		return result
	end
	local a, b = groups(left or s), groups(right or "")
	if not a or not b then return nil end
	local n = #a + #b
	if (left and n >= 8) or (not left and n ~= 8) then return nil end
	if left then for _ = n + 1, 8 do a[#a + 1] = "0" end end
	for _, item in ipairs(b) do a[#a + 1] = item end
	return table.concat(a, ":"), 6
end
local function host(s)
	need(type(s) == "string" and s ~= "", "missing host")
	local bracketed = s:match("^%[([^%]]+)%]$")
	if bracketed then
		local ip, family = M.ip(bracketed)
		need(family == 6, "invalid bracketed IPv6 host")
		return ip, family
	end
	local ip, family = M.ip(s)
	if ip then return ip, family end
	need(#s <= 253 and not s:find("[^A-Za-z0-9%.%-]") and not s:match("^[%d.]+$"), "invalid host")
	local name = s:gsub("%.$", "")
	for label in (name .. "."):gmatch("(.-)%.") do
		need(#label >= 1 and #label <= 63 and not label:match("^%-") and not label:match("%-$"), "invalid DNS label")
	end
	return name:lower()
end
local function port(v)
	need((type(v) == "string" and v:match("^%d+$")) or type(v) == "number", "invalid port")
	local n = tonumber(v); need(n and n >= 1 and n <= 65535 and n % 1 == 0, "invalid port"); return n
end

-- resolver is called ONCE for a domain, returning the complete A/AAAA answer
-- set. Default: nixio.getaddrinfo. Preference is explicit; no background retry.
function M.bind(generation, source_md5, id, node, preference, resolver)
	need(type(generation) == "string" and generation:match("^generation%.[A-Za-z0-9_]+$"), "invalid generation")
	need(type(source_md5) == "string" and #source_md5 == 32 and source_md5:match("^%x+$"), "invalid source digest")
	need(type(id) == "string" and id:match("^[A-Za-z0-9_-]+$"), "invalid node ID")
	need(type(node) == "table" and (node.type == "SS" or node.type == "Hysteria"), "unsupported node")
	need(preference == "ipv4" or preference == "ipv6" or preference == "ipv4-only" or preference == "ipv6-only", "explicit address preference required")
	local original, literal_family = host(node.address)
	local answers
	if literal_family then answers = {{address = original}}
	else
		resolver = resolver or function(name) return require("nixio").getaddrinfo(name, "any") end
		answers = resolver(original)
	end
	need(type(answers) == "table" and #answers > 0, "resolution failed")
	local addresses, seen = {}, {}
	for _, answer in ipairs(answers) do
		need(type(answer) == "table", "invalid resolver answer")
		local ip, family = M.ip(answer.address)
		need(ip ~= nil, "resolver returned non-literal address")
		need(not ip:match("^0:0:0:0:0:ffff:"), "mapped IPv6 endpoint requires actual egress-family verification")
		if not seen[ip] then addresses[#addresses + 1] = {address = ip, family = family}; seen[ip] = true end
	end
	-- Stable preference and numeric-address spelling; no DNS order dependency.
	local preferred = preference:sub(1, 4) == "ipv6" and 6 or 4
	table.sort(addresses, function(a, b)
		if a.family ~= b.family then return a.family == preferred end
		return a.address < b.address
	end)
	local chosen = addresses[1]
	need(not preference:find("only", 1, true) or chosen.family == preferred, "requested address family unavailable")
	local bound = copy(node); bound.address = chosen.address
	if node.type == "Hysteria" and not literal_family and (bound.tls_serverName == nil or bound.tls_serverName == "") then bound.tls_serverName = original end
	return {generation = generation, source_md5 = source_md5, node_id = id,
		original_node = copy(node), generator_node = bound, addresses = addresses,
		address = chosen.address, family = chosen.family, port = port(node.port), preference = preference}
end

-- Revalidate against the caller's frozen node, not against edited live UCI.
-- No new resolution: an address change requires a new binding/generation.
function M.check(binding, generation, source_md5, id, frozen_node)
	need(type(binding) == "table", "missing binding")
	local expected = M.bind(generation, source_md5, id, frozen_node, binding.preference, function() return binding.addresses end)
	need(equal(expected, binding), "binding changed or belongs to another snapshot")
	return true
end

-- Validate the actual generated JSON endpoint/security fields; return outer
-- protocols from that JSON, not from the transparent business role.
function M.config(binding, config)
	need(type(config) == "table", "missing generated JSON")
	local n = binding.generator_node
	local result = {}
	if n.type == "SS" then
		need(config.server == binding.address and config.server_port == binding.port, "SS endpoint mismatch")
		need(config.method == n.method and config.password == n.password, "SS credentials mismatch")
		need(config.mode == "tcp_only" or config.mode == "udp_only" or config.mode == "tcp_and_udp", "missing SS mode")
		if config.mode ~= "udp_only" then result[#result + 1] = "tcp" end
		if config.mode ~= "tcp_only" then result[#result + 1] = "udp" end
	else
		local address = binding.family == 6 and ("[" .. binding.address .. "]") or binding.address
		need(config.server == address .. ":" .. binding.port, "Hysteria endpoint mismatch")
		need(config.protocol == (n.protocol or "udp"), "Hysteria transport mismatch")
		need(config.server_name == (n.tls_serverName ~= "" and n.tls_serverName or nil) and
			config.ca == (n.hysteria_ca ~= "" and n.hysteria_ca or nil) and
			config.insecure == (n.tls_allowInsecure == "1") and
			config.obfs == (n.hysteria_obfs ~= "" and n.hysteria_obfs or nil), "Hysteria TLS/obfs mismatch")
		local auth = n.hysteria_auth_type or "disable"
		need((auth == "string" and config.auth_str == n.hysteria_auth_password and config.auth == nil) or
			(auth == "base64" and config.auth == n.hysteria_auth_password and config.auth_str == nil) or
			(auth == "disable" and config.auth == nil and config.auth_str == nil), "Hysteria auth mismatch")
		need(config.protocol == "udp" or config.protocol == "wechat-video" or config.protocol == "faketcp", "invalid Hysteria transport")
		result[1] = config.protocol == "faketcp" and "tcp" or "udp"
	end
	return result
end

-- A future caller must also run B2/B3.1 readiness and verify the generation's
-- config digest. This record alone NEVER proves a running socket or GID.
function M.instance(binding, config_path, config_md5, pid, birth)
	need(type(config_path) == "string" and config_path:sub(1, 1) == "/" and not config_path:find("[%c%s]"), "invalid instance path")
	need(type(config_md5) == "string" and #config_md5 == 32 and config_md5:match("^%x+$"), "invalid config digest")
	need(tonumber(pid) and tonumber(pid) > 0 and tostring(pid):match("^%d+$") and tostring(birth):match("^%d+$"), "invalid process identity")
	return {generation = binding.generation, source_md5 = binding.source_md5, node_id = binding.node_id,
		config = config_path, config_md5 = config_md5, pid = tostring(pid), birth = tostring(birth), state = "unverified"}
end
function M.check_instance(record, binding, config_path, config_md5, pid, birth)
	need(equal(record, M.instance(binding, config_path, config_md5, pid, birth)), "instance expectation changed or belongs to another generation")
	return true
end
return M
