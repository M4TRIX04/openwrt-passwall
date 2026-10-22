-- Hysteria 1.3.5. Field design derived from P455W4LL cd892e83.
module("luci.passwall.util_hysteria", package.seeall)
local api = require "luci.passwall.api"
local jsonc = api.jsonc

local function reject(s) error("Hysteria 1: " .. s, 0) end
local function text(v, name, required)
	if v == nil or v == "" then
		if required then reject("missing " .. name) end
		return nil
	end
	if type(v) ~= "string" or v:find("%c") then reject("invalid " .. name) end
	return v
end
local function number(v, name, min, max, required)
	if v == nil or v == "" then
		if required then reject("missing " .. name) end
		return nil
	end
	local n = tonumber(v)
	if (type(v) == "string" and not v:match("^%d+$")) or not n or n ~= math.floor(n) or n < min or n > max then reject("invalid " .. name) end
	return n
end
local function flag(v, name, default)
	if v == nil or v == "" then return default or false end
	if v ~= "0" and v ~= "1" then reject("invalid flag " .. name) end
	return v == "1"
end
local function address(v, name)
	v = text(v, name, true)
	if v:find("[%s/,]") then reject("invalid " .. name) end
	if api.is_ipv6(v) then return "[" .. v:gsub("^%[", ""):gsub("%]$", "") .. "]" end
	if v:find(":", 1, true) or not v:match("^[%w%.%-]+$") then reject("invalid " .. name) end
	return v
end
local function common(node, server)
	if type(node) ~= "table" then reject("missing node") end
	local protocol = node.protocol or "udp"
	if protocol ~= "udp" and protocol ~= "faketcp" and protocol ~= "wechat-video" then reject("unsupported protocol") end
	for _, k in ipairs({"hysteria_hop", "hysteria_hop_interval"}) do
		if node[k] and node[k] ~= "" then reject(k .. " is deferred") end
	end
	if flag(node.custom, "custom") then reject("custom JSON is not supported for Hysteria 1") end
	local c = {
		protocol = protocol,
		obfs = text(node.hysteria_obfs, "obfs"),
		alpn = text(node.hysteria_alpn, "alpn"),
		up_mbps = number(node.hysteria_up_mbps, "up_mbps", server and 0 or 1, 1000000, not server),
		down_mbps = number(node.hysteria_down_mbps, "down_mbps", server and 0 or 1, 1000000, not server),
		recv_window_conn = number(node.hysteria_recv_window_conn, "stream window", 65536, 4294967295),
		disable_mtu_discovery = flag(node.hysteria_disable_mtu_discovery, "disable_mtu_discovery")
	}
	local mode = node.hysteria_auth_type or "disable"
	if mode ~= "disable" and mode ~= "string" and (server or mode ~= "base64") then reject("invalid auth type") end
	local password = text(node.hysteria_auth_password, "auth password", mode ~= "disable")
	if mode == "string" then
		if server then c.auth = {mode = "password", config = {password = password}} else c.auth_str = password end
	elseif mode == "base64" then
		if #password % 4 ~= 0 or not password:match("^[A-Za-z0-9+/]*=?=?$") or
			require("nixio").bin.b64encode(require("nixio").bin.b64decode(password) or "") ~= password then reject("invalid Base64 authentication") end
		c.auth = password
	end
	return c
end

function gen_config_server(node)
	local c = common(node, true)
	c.listen = ":" .. number(node.port, "port", 1, 65535, true)
	c.cert = text(node.tls_certificateFile, "certificate", true)
	c.key = text(node.tls_keyFile, "private key", true)
	if not api.fs.access(c.cert) or not api.fs.access(c.key) then reject("certificate/key file does not exist") end
	c.recv_window_client = number(node.hysteria_recv_window, "connection window", 65536, 4294967295)
	c.disable_udp = not flag(node.hysteria_udp, "udp", true)
	flag(node.firewall_allow, "firewall_allow")
	flag(node.log, "log", true)
	return c
end

function gen_config(var)
	if type(var) ~= "table" then reject("invalid parameters") end
	local id = text(var.node, "node", true)
	local node = var.frozen_node
	if node ~= nil then
		if type(node) ~= "table" or node.type ~= "Hysteria" then reject("invalid frozen node") end
	else node = api.uci_get_c(id) end
	local c = common(node, false)
	c.server = address(var.server_host or node.address, "server") .. ":" .. number(var.server_port or node.port, "port", 1, 65535, true)
	c.server_name = text(node.tls_serverName, "server_name")
	c.insecure = flag(node.tls_allowInsecure, "insecure")
	c.ca = text(node.hysteria_ca, "CA")
	if c.ca and not api.fs.access(c.ca) then reject("CA file does not exist") end
	c.recv_window = number(node.hysteria_recv_window, "connection window", 65536, 4294967295)
	c.handshake_timeout = number(node.hysteria_handshake_timeout, "handshake timeout", 2, 3600)
	c.idle_timeout = number(node.hysteria_idle_timeout, "idle timeout", 4, 3600)
	c.fast_open = flag(node.fast_open, "fast_open")
	c.lazy_start = flag(node.hysteria_lazy_start, "lazy_start")
	c.retry = -1
	c.retry_interval = 5
	local enabled = false
	for _, kind in ipairs({"socks", "http"}) do
		local p = var["local_" .. kind .. "_port"]
		if p and p ~= "0" and p ~= 0 then
			local username = text(var["local_" .. kind .. "_username"], "local user")
			local password = text(var["local_" .. kind .. "_password"], "local password")
			if (username and not password) or (password and not username) then reject("incomplete local authentication") end
			local v = {listen = address(var["local_" .. kind .. "_address"] or "127.0.0.1", "bind") .. ":" .. number(p, "local port", 1, 65535, true), timeout = 300, user = username, password = password}
			if kind == "socks" then v.disable_udp = false end
			c[kind == "socks" and "socks5" or "http"] = v
			enabled = true
		end
	end
	local tcp_port, udp_port = var.local_tcp_redir_port, var.local_udp_redir_port
	if var.local_redir_port ~= nil and (tcp_port ~= nil or udp_port ~= nil) then
		reject("cannot mix local_redir_port with separate TCP/UDP ports")
	end
	-- Keep the merged-node callers unchanged until the runtime migration.
	if var.local_redir_port then
		tcp_port = number(var.local_redir_port, "redirect port", 1, 65535, true)
		udp_port = tcp_port
	end
	if tcp_port ~= nil or udp_port ~= nil then
		local ipv6 = flag(var.proxy_ipv6, "proxy_ipv6")
		local bind = ipv6 and "[::]" or "0.0.0.0"
		if var.transparent_address ~= nil then
			if var.local_redir_port ~= nil then reject("explicit bind requires separate TCP/UDP parameters") end
			if var.transparent_address ~= (ipv6 and "::" or "0.0.0.0") then reject("transparent address/family mismatch") end
		end
		if tcp_port ~= nil then
			local port = number(tcp_port, "TCP redirect port", 1, 65535, true)
			local way = var.tcp_proxy_way
			if way ~= "redirect" and way ~= "tproxy" then reject("invalid TCP proxy mode") end
			if ipv6 and way ~= "tproxy" then reject("IPv6 transparent proxy requires TCP TPROXY") end
			c[way == "redirect" and "redirect_tcp" or "tproxy_tcp"] = {listen = bind .. ":" .. port, timeout = 300}
		end
		if udp_port ~= nil then
			local port = number(udp_port, "UDP redirect port", 1, 65535, true)
			c.tproxy_udp = {listen = bind .. ":" .. port, timeout = 60}
		end
		enabled = true
	end
	if not enabled then reject("no local listener requested") end
	return jsonc.stringify(c, 1)
end

if arg and arg[1] == "gen_config" then
	local ok, result = pcall(function() return gen_config(jsonc.parse(arg[2] or "")) end)
	if not ok then io.stderr:write(tostring(result) .. "\n"); os.exit(1) end
	print(result)
end
