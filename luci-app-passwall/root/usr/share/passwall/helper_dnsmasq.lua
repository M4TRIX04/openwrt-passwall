local api = require "luci.passwall.api"
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes
local TMP = {}

-- DNS-H3: these helpers are local to this generator. Never replace api's UCI
-- cursor, cache root or process-wide functions. Production callers use none of
-- this path unless they explicitly select isolated_capture/isolated_generate.
local quote = require("luci.util").shellquote
local function isolated_need(v, why)
	assert(v, "DNS isolated configuration: " .. why)
	return v
end
local function isolated_read(path) return isolated_need(fs.readfile(path), "unreadable input " .. path) end
local function isolated_type(path) return (fs.lstat(path) or {}).type end
local function isolated_md5(path)
	local d = api.md5_file(path)
	isolated_need(type(d) == "string" and #d == 32 and d:match("^%x+$"), "cannot hash input")
	return d
end
local function isolated_write(path, text)
	local f = isolated_need(io.open(path, "w"), "cannot create private file")
	isolated_need(f:write(text), "private write failed")
	isolated_need(f:close(), "private close failed")
end
local function isolated_snapshot(path)
	isolated_need(type(path) == "string" and path:match("^/[%w_./-]+/contracts/generation%.[%w_]+$") and
		fs.realpath(path) == path, "invalid snapshot directory")
	local package = isolated_read(path .. "/package"):gsub("\n$", "")
	isolated_need(package == "passwall_contract_" .. path:match("%.([%w_]+)$"), "snapshot package mismatch")
	local manifest = {}
	for _, name in ipairs({"source", "package", "view", "global", "acls", "source.md5", "config.md5", "config/" .. package}) do
		isolated_need(isolated_type(path .. "/" .. name) == "reg", "invalid snapshot file")
		manifest[#manifest + 1] = isolated_md5(path .. "/" .. name) .. "  " .. name .. "\n"
	end
	isolated_need(table.concat(manifest) == isolated_read(path .. "/sealed"), "incomplete/changed snapshot seal")
	-- runtime_snapshot.sh writes bare digests; accept one optional trailing LF.
	isolated_need(isolated_md5(path .. "/source") == isolated_read(path .. "/source.md5"):gsub("\n$", "") and
		isolated_md5(path .. "/config/" .. package) == isolated_read(path .. "/config.md5"):gsub("\n$", ""), "snapshot digest mismatch")
	for _, dir in ipairs({"config", "state"}) do
		isolated_need(fs.realpath(path .. "/" .. dir) == path .. "/" .. dir, "invalid snapshot cursor directory")
	end
	-- The generation state directory is empty by contract. Refuse unsealed UCI
	-- deltas rather than consuming them or falling back to /etc/config.
	for _ in isolated_need(fs.dir(path .. "/state"), "missing snapshot state") do
		isolated_need(false, "snapshot contains unsealed UCI state")
	end
	local cursor = require("uci").cursor(path .. "/config", path .. "/state")
	isolated_need(cursor:load(package), "cannot load frozen package")
	local function section_id(section)
		local kind, index = section:match("^@([%w_]+)%[(%d+)%]$")
		if not kind then return section end
		local found, n = nil, 0
		cursor:foreach(package, kind, function(s)
			if n == tonumber(index) then found = s[".name"] end
			n = n + 1
		end)
		return found
	end
	return {
		get = function(section, option)
			section = section_id(section)
			if not section then return nil end
			if option then return cursor:get(package, section, option) end
			return cursor:get_all(package, section)
		end,
		foreach = function(kind, fn) cursor:foreach(package, kind, fn) end,
		package = package, seal = isolated_md5(path .. "/sealed")
	}
end

local isolated_rule_sources = {
	["/etc/passwall/rules/block_host"] = "-USE_BLOCK_LIST",
	["/etc/passwall/rules/direct_host"] = "-USE_DIRECT_LIST",
	["/etc/passwall/rules/proxy_host"] = "-USE_PROXY_LIST",
	["/usr/share/passwall/rules/gfwlist"] = "-USE_GFW_LIST",
	["/usr/share/passwall/rules/chnlist"] = "-CHN_LIST"
}
local function isolated_context(var)
	local root, snapshot = var["-ISOLATED_ROOT"], var["-SNAPSHOT"]
	local frozen = isolated_snapshot(snapshot)
	isolated_need(type(root) == "string" and root:match("^(.*)/dns%-helper%.[%w_]+$") ==
		snapshot:match("^(.*)/contracts/generation%.[%w_]+$") and fs.realpath(root) == root,
		"private directory is outside generation runtime")
	for _, dir in ipairs({"input", "cache"}) do
		isolated_need(fs.realpath(root .. "/" .. dir) == root .. "/" .. dir, "missing private input/cache directory")
	end
	local request_md5 = isolated_md5(root .. "/request.json")
	local args = isolated_need(api.jsonc.parse(isolated_read(root .. "/request.json")), "invalid generation request")
	isolated_need(isolated_md5(root .. "/request.json") == request_md5, "request changed while reading")
	local keys = {"FLAG", "NODE", "LISTEN_PORT", "DEFAULT_DNS", "LOCAL_DNS", "TUN_DNS", "USE_DEFAULT_DNS",
		"CHINADNS_DNS", "USE_DIRECT_LIST", "USE_PROXY_LIST", "USE_BLOCK_LIST", "USE_GFW_LIST", "CHN_LIST",
		"DEFAULT_PROXY_MODE", "NO_PROXY_IPV6", "NFTFLAG", "NO_LOGIC_LOG"}
	local allowed = {}; for _, key in ipairs(keys) do allowed["-" .. key] = true end
	isolated_need(type(args) == "table", "request must be an object")
	for k, v in pairs(args) do
		isolated_need(allowed[k] and type(v) == "string" and not v:find("[%z\r\n]"), "invalid generation argument")
	end
	for _, key in ipairs(keys) do isolated_need(args["-" .. key] ~= nil, "missing generation argument " .. key) end
	local flag = args["-FLAG"]
	isolated_need(flag == "default" or flag:match("^[%w_]+$"), "invalid scope")
	local source = flag == "default" and isolated_read(snapshot .. "/global"):gsub("\n$", "") or flag
	local section = isolated_need(frozen.get(source), "scope missing from snapshot")
	isolated_need(section[".type"] == (flag == "default" and "global" or "acl_rule"), "invalid scope section")
	if flag ~= "default" and section.use_global_config == "1" then
		source = isolated_read(snapshot .. "/global"):gsub("\n$", "")
		section = isolated_need(frozen.get(source), "missing inherited scope")
	end
	isolated_need((section.dns_shunt or "dnsmasq") == "dnsmasq" and
		(section.dns_mode or (section[".type"] == "global" and "tcp" or "dns2socks")) == "dns2socks",
		"unsupported frozen DNS combination")
	local node = frozen.get(args["-NODE"])
	isolated_need(args["-NODE"] == section.tcp_node and node and node[".type"] == "nodes" and
		(node.type == "SS" or node.type == "Hysteria") and node.protocol ~= "_shunt", "node differs from supported frozen TCP scope")
	for _, key in ipairs({"-USE_DIRECT_LIST", "-USE_PROXY_LIST", "-USE_BLOCK_LIST", "-USE_GFW_LIST", "-NO_PROXY_IPV6", "-NFTFLAG"}) do
		isolated_need(args[key] == "0" or args[key] == "1", "invalid switch")
	end
	isolated_need(args["-CHN_LIST"] == "0" or args["-CHN_LIST"] == "direct" or args["-CHN_LIST"] == "proxy", "invalid China list mode")
	for key, option in pairs({["-USE_DIRECT_LIST"] = "use_direct_list", ["-USE_PROXY_LIST"] = "use_proxy_list",
		["-USE_BLOCK_LIST"] = "use_block_list", ["-USE_GFW_LIST"] = "use_gfw_list"}) do
		isolated_need(args[key] == (section[option] or "1"), "rule switch differs from frozen scope")
	end
	isolated_need(args["-CHN_LIST"] == (section.chn_list or "direct") and
		args["-USE_DEFAULT_DNS"] == (section.use_default_dns or "direct") and
		args["-NO_PROXY_IPV6"] == (section.filter_proxy_ipv6 or "0"), "DNS policy differs from frozen scope")
	isolated_need(args["-DEFAULT_PROXY_MODE"] == (section.tcp_proxy_mode == "disable" and "disable" or "proxy"), "proxy mode differs from frozen scope")
	isolated_need(args["-USE_DEFAULT_DNS"] == "direct" or args["-USE_DEFAULT_DNS"] == "remote", "unsupported default DNS mode")
	isolated_need(args["-CHINADNS_DNS"] == "0", "ChinaDNS is outside isolated DNS-H3")
	local function port(p) return p and p:match("^%d+$") and tonumber(p) >= 1 and tonumber(p) <= 65535 end
	isolated_need(port(args["-LISTEN_PORT"]) and port(args["-TUN_DNS"]:match("^127%.0%.0%.1#(%d+)$")), "explicit prospective ports required")
	isolated_need(tonumber(args["-LISTEN_PORT"]) ~= tonumber(args["-TUN_DNS"]:match("#(%d+)$")), "DNS/helper port collision")
	-- LOCAL_DNS/DEFAULT_DNS are explicit, captured derived inputs, never read
	-- from live cache here. Their runtime selection remains the caller's job.
	local endpoint = require "luci.passwall.endpoint_contract"
	for _, key in ipairs({"-LOCAL_DNS", "-DEFAULT_DNS"}) do
		isolated_need(#args[key] > 0, "missing explicit DNS input")
		for entry in (args[key] .. ","):gmatch("(.-),") do
			local host, p = entry:match("^(.-)#(%d+)$")
			host = host and (host:match("^%[([^%]]+)%]$") or host)
			isolated_need(host and endpoint.ip(host) and port(p), "DNS inputs must be literal IP#port endpoints")
		end
	end
	args["-NO_LOGIC_LOG"] = "1"
	args["-TMP_DNSMASQ_PATH"] = root .. "/cache/dnsmasq_" .. flag
	args["-DNSMASQ_CONF_FILE"] = root .. "/dnsmasq.conf"
	return {root = root, snapshot = snapshot, frozen = frozen, args = args, request_md5 = request_md5}
end

-- Capture is deliberately DNS-specific. Includes are flattened BEFORE rule
-- generation, hosts are copied, resolver/PID/log/DHCP paths are removed. Unknown
-- directives and include filters fail explicitly instead of retaining live IO.
local function isolated_capture(var)
	local ctx = isolated_context(var)
	local root, args = ctx.root, ctx.args
	isolated_need(not fs.lstat(root .. "/inputs.json"), "inputs already captured")
	local inputs = {snapshot = ctx.snapshot, snapshot_seal = ctx.frozen.seal, files = {}, rules = {}, sources = {}}
	local count, copied = 0, {}
	local function capture(source, optional)
		local st, errno = fs.stat(source)
		if not st and errno == 2 and not fs.lstat(source) and optional then return false end
		isolated_need(st and st.type == "reg", "required/invalid input " .. source)
		local real, before = fs.realpath(source), isolated_md5(source)
		if copied[real] then
			isolated_need(inputs.files[copied[real]] == before, "source changed between references")
			return copied[real]
		end
		count = count + 1
		local dest = root .. "/input/asset." .. count
		isolated_need(not fs.lstat(dest), "private asset already exists")
		local rc = api.exec_call("cp " .. quote(isolated_need(real, "unresolved source")) .. " " .. quote(dest))
		isolated_need(rc == 0 and isolated_type(dest) == "reg" and fs.realpath(source) == real and
			isolated_md5(source) == before and isolated_md5(dest) == before, "asset copy/digest failed")
		inputs.files[dest] = before
		inputs.sources[dest] = real
		copied[real] = dest
		return dest
	end
	local safe = {}
	for word in ([[domain-needed bogus-priv filterwin2k localise-queries expand-hosts no-negcache strict-order
		all-servers stop-dns-rebind rebind-localhost-ok clear-on-reload no-poll no-resolv no-hosts
		cache-size neg-ttl local-ttl max-ttl max-cache-ttl min-cache-ttl edns-packet-max dns-forward-max
		local-service domain local server rev-server address bogus-nxdomain rebind-domain-ok host-record
		cname srv-host mx-host txt-record ptr-record naptr-record dns-rr mx-target filter-AAAA filter-A
		filter-rr log-async dns-loop-detect dnssec dnssec-check-unsigned dnssec-no-timecheck trust-anchor]]):gmatch("%S+") do safe[word] = true end
	local lines, stack, no_hosts = {}, {}, false
	local parse
	local function hosts(source)
		isolated_need(source:sub(1, 1) == "/" and not source:find("[%z\r\n]"), "absolute hosts path required")
		local st = isolated_need(fs.stat(source), "missing hosts input")
		if st.type == "dir" then
			local names = {}; for name in isolated_need(fs.dir(source), "unreadable hosts directory") do names[#names + 1] = name end
			table.sort(names)
			for _, name in ipairs(names) do
				isolated_need(fs.stat(source .. "/" .. name, "type") == "reg", "unsupported hosts directory entry")
				lines[#lines + 1] = "addn-hosts=" .. capture(source .. "/" .. name)
			end
		else lines[#lines + 1] = "addn-hosts=" .. capture(source) end
	end
	parse = function(source, depth)
		isolated_need(depth <= 8, "include nesting limit")
		isolated_need(source:sub(1, 1) == "/" and not source:find("[%z\r\n]"), "absolute base/include path required")
		local real = isolated_need(fs.realpath(source), "missing base/include")
		isolated_need(not stack[real], "recursive DNS include")
		stack[real] = true
		local copy = capture(source)
		for raw in (isolated_read(copy) .. "\n"):gmatch("([^\n]*)\n") do
			local line = raw:match("^%s*(.-)%s*$")
			if line ~= "" and line:sub(1, 1) ~= "#" then
				local key, value = line:match("^([%w_-]+)%s*=%s*(.-)%s*$")
				key = key or line
				isolated_need(key:match("^[%w_-]+$"), "malformed base directive")
				if key == "conf-file" or key == "servers-file" then parse(isolated_need(value, "missing include path"), depth + 1)
				elseif key == "conf-dir" then
					isolated_need(value and not value:find(",", 1, true), "conf-dir filters need explicit adaptation")
					local names = {}; for name in isolated_need(fs.dir(value), "missing conf-dir") do names[#names + 1] = name end
					table.sort(names)
					for _, name in ipairs(names) do
						if name:sub(1, 1) ~= "." and not name:find("passwall", 1, true) and not name:match("~$") then
							isolated_need(fs.stat(value .. "/" .. name, "type") == "reg", "unsupported conf-dir entry")
							parse(value .. "/" .. name, depth + 1)
						end
					end
				elseif key == "addn-hosts" or key == "hostsdir" then hosts(isolated_need(value, "missing hosts path"))
				elseif key == "no-hosts" then no_hosts = true
				elseif key:match("^dhcp") or key:match("^ra%-") or key:match("tftp") or key:match("ubus") or
					key == "enable-dbus" or key == "pid-file" or key == "log-facility" or key == "log-queries" or
					key == "resolv-file" or key == "port" or key == "interface" or key == "except-interface" or
					key == "listen-address" or key == "bind-interfaces" or key == "bind-dynamic" or
					key == "user" or key == "group" or key == "min-cache-ttl" then
					-- Process/service settings are supplied by the future isolated runner.
				elseif key == "server" and not (value or ""):find("/", 1, true) then
					-- Default upstream is supplied by the captured generation request.
				else
					isolated_need(safe[key], "unsupported base directive " .. key)
					lines[#lines + 1] = line
				end
			end
		end
		stack[real] = nil
	end
	parse(isolated_need(var["-BASE_CONF"], "explicit dnsmasq base required"), 1)
	if not no_hosts then hosts("/etc/hosts") end
	local dhcp_hosts = capture(api.CACHE_PATH .. "/dhcp-hosts", true)
	if dhcp_hosts then lines[#lines + 1] = "addn-hosts=" .. dhcp_hosts end
	lines[#lines + 1] = "no-hosts"
	lines[#lines + 1] = "no-resolv"
	lines[#lines + 1] = "listen-address=127.0.0.1"
	lines[#lines + 1] = "bind-interfaces"
	lines[#lines + 1] = "pid-file=" .. root .. "/dnsmasq.pid"
	lines[#lines + 1] = "log-facility=" .. root .. "/dnsmasq.log"
	isolated_write(root .. "/input/base.conf", table.concat(lines, "\n") .. "\n")
	inputs.files[root .. "/input/base.conf"] = isolated_md5(root .. "/input/base.conf")
	local needs_geo = false
	for source, option in pairs(isolated_rule_sources) do
		local active = option == "-CHN_LIST" and args[option] ~= "0" or args[option] == "1"
		local copy = active and capture(source, true) or false
		inputs.rules[source] = copy
		if copy and source:match("_host$") then
			for line in isolated_read(copy):gmatch("[^\r\n]+") do
				if not line:find("#", 1, true) and line:find("geosite:", 1, true) then needs_geo = true end
			end
		end
	end
	inputs.geosite, inputs.geoview = false, false
	if needs_geo and ctx.frozen.get("@global_rules[0]", "enable_geoview") == "1" then
		local location = ctx.frozen.get("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
		inputs.geosite = capture(isolated_need(location:match("^(.*)/"), "invalid geosite directory") .. "/geosite.dat")
		inputs.geoview = capture(ctx.frozen.get("@global_app[0]", "geoview_file") or "/usr/bin/geoview")
		local rc = api.exec_call("chmod 700 " .. quote(inputs.geoview))
		isolated_need(rc == 0, "cannot make private geoview executable")
	end
	isolated_need(isolated_md5(root .. "/request.json") == ctx.request_md5, "request changed during capture")
	inputs.files[root .. "/request.json"] = ctx.request_md5
	isolated_need(isolated_snapshot(ctx.snapshot).seal == ctx.frozen.seal, "snapshot changed while capturing")
	isolated_write(root .. "/inputs.json", api.jsonc.stringify(inputs))
end

local function isolated_inputs(ctx)
	local inputs = isolated_need(api.jsonc.parse(isolated_read(ctx.root .. "/inputs.json")), "missing capture manifest")
	isolated_need(inputs.snapshot == ctx.snapshot and inputs.snapshot_seal == ctx.frozen.seal and
		type(inputs.files) == "table" and type(inputs.rules) == "table", "capture generation mismatch")
	for path, md5 in pairs(inputs.files) do
		isolated_need((path == ctx.root .. "/request.json" or path:sub(1, #ctx.root + 7) == ctx.root .. "/input/") and
			fs.realpath(path) == path and isolated_type(path) == "reg" and isolated_md5(path) == md5, "private input digest mismatch")
	end
	isolated_need(inputs.files[ctx.root .. "/request.json"] and inputs.files[ctx.root .. "/input/base.conf"], "incomplete capture manifest")
	for source in pairs(isolated_rule_sources) do
		local path = inputs.rules[source]
		isolated_need(path == false or type(path) == "string" and inputs.files[path], "missing captured rule/absence")
	end
	for _, key in ipairs({"geosite", "geoview"}) do
		isolated_need(inputs[key] == false or type(inputs[key]) == "string" and inputs.files[inputs[key]], "incomplete geosite capture")
	end
	return inputs
end

local function tinsert(table_name, val)
	if table_name and type(table_name) == "table" then
		if not TMP[table_name] then
			TMP[table_name] = {}
		end
		if TMP[table_name][val] then
			return false
		end
		table.insert(table_name, val)
		TMP[table_name][val] = true
		return true
	end
	return false
end

local function backup_servers()
	local DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		api.uci_set_c("@global[0]", "dnsmasq_servers", DNSMASQ_DNS)
		api.uci_save_c(true)
	end
end

local function restore_servers()
	local dns_table = {}
	local DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		for k, v in ipairs(DNSMASQ_DNS) do
			tinsert(dns_table, v)
		end
	end
	local OLD_SERVER = api.uci_get(api.c_config, "@global[0]", "dnsmasq_servers")
	if OLD_SERVER and #OLD_SERVER > 0 then
		for k, v in ipairs(OLD_SERVER) do
			tinsert(dns_table, v)
		end
		api.uci_del_c("@global[0]", "dnsmasq_servers")
		api.uci_save_c(true)
	end
	if dns_table and #dns_table > 0 then
		api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table)
		api.uci_save(nil, "dhcp", true)
	end
end

function stretch()
	local dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	local dnsmasq_noresolv = api.uci_get("dhcp", "@dnsmasq[0]", "noresolv")
	local _flag
	if dnsmasq_server and #dnsmasq_server > 0 then
		for k, v in ipairs(dnsmasq_server) do
			if not v:find("/") then
				_flag = true
			end
		end
	end
	if not _flag and dnsmasq_noresolv == "1" then
		api.uci_del("dhcp", "@dnsmasq[0]", "noresolv")
		local RESOLVFILE = "/tmp/resolv.conf.d/resolv.conf.auto"
		local file = io.open(RESOLVFILE, "r")
		if not file then
			RESOLVFILE = "/tmp/resolv.conf.auto"
		else
			local size = file:seek("end")
			file:close()
			if size == 0 then
				RESOLVFILE = "/tmp/resolv.conf.auto"
			end
		end
		api.uci_set("dhcp", "@dnsmasq[0]", "resolvfile", RESOLVFILE)
		api.uci_save(nil, "dhcp", true)
	end
end

function restart(var)
	local LOG = var["-LOG"]
	sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	if LOG == "1" then
		api.log("重启 dnsmasq 服务")
	end
end

function logic_restart(var)
	local LOG = var["-LOG"]
	local DEFAULT_DNS = api.get_cache_var("DEFAULT_DNS")
	if DEFAULT_DNS then
		backup_servers()
		--sys.call("sed -i '/list server/d' /etc/config/dhcp >/dev/null 2>&1")
		local dns_table = {}
		local dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server")
		if dnsmasq_server and #dnsmasq_server > 0 then
			for k, v in ipairs(dnsmasq_server) do
				if v:find("/") then
					tinsert(dns_table, v)
				end
			end
			api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table)
			api.uci_save(nil, "dhcp", true)
		end
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
		restore_servers()
	else
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	end
	if LOG == "1" then
		api.log("重启 dnsmasq 服务")
	end
end

function copy_instance(var)
	local LISTEN_PORT = var["-LISTEN_PORT"]
	local TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"]
	local conf_lines = {}
	if var._isolated then
		-- Includes/hosts were captured before add_rule, so there is no late
		-- live conf-dir copy capable of overwriting generated files.
		for line in io.lines(var._isolated.root .. "/input/base.conf") do tinsert(conf_lines, line) end
		tinsert(conf_lines, "port=" .. LISTEN_PORT)
		return conf_lines
	end
	local DEFAULT_DNSMASQ_CFGID = sys.exec("echo -n $(uci -q show dhcp.@dnsmasq[0] | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')")
	local conf_file = "/var/etc/dnsmasq.conf." .. DEFAULT_DNSMASQ_CFGID

	local retry = 5
	while not fs.access(conf_file) and retry > 0 do
		api.nixio.nanosleep(1, 0)
		retry = retry - 1
	end

	if fs.access(conf_file) then
		for line in io.lines(conf_file) do
			local filter
			if line:find("passwall") then filter = true end
			if line:find("ubus") then filter = true end
			if line:find("dhcp") then filter = true end
			if line:find("server=") == 1 then filter = true end
			if line:find("port=") == 1 then filter = true end
			if line:find("min%-cache%-ttl") == 1 then filter = true end
			if line:find("conf%-dir=") == 1 then
				filter = true
				if TMP_DNSMASQ_PATH then
					local tmp_path = line:sub(1 + #"conf-dir=")
					sys.call(string.format("cp -r %s/* %s/ 2>/dev/null", tmp_path, TMP_DNSMASQ_PATH))
				end
			end
			if line:find("address=") == 1 or (line:find("server=") == 1 and line:find("/")) then filter = nil end
			if not filter then
				tinsert(conf_lines, line)
			end
		end
	else
		sys.call("logger -t passwall 'ERROR: dnsmasq config " .. conf_file .. " not found after 5s wait! DNS hijacking will fail.'")
	end

	tinsert(conf_lines, "port=" .. LISTEN_PORT)
	if TMP_DNSMASQ_PATH then
		api.remove(TMP_DNSMASQ_PATH .. "/*passwall*")
	end
	if var["-return"] == "1" then
		return conf_lines
	end
	if #conf_lines > 0 then
		local DNSMASQ_CONF = var["-DNSMASQ_CONF"]
		local conf_out = io.open(DNSMASQ_CONF, "a")
		conf_out:write(table.concat(conf_lines, "\n"))
		conf_out:write("\n")
		conf_out:close()
	end
end

function add_rule(var)
	local iso = var._isolated
	local get = iso and iso.frozen.get or api.uci_get_c
	local foreach = iso and iso.frozen.foreach or api.uci_foreach_c
	local function open_rule(path)
		if not iso then return io.open(path) end
		local copy = iso.inputs.rules[path]
		if copy == false then return nil end
		return isolated_need(io.open(isolated_need(copy, "uncaptured rule")), "unreadable captured rule")
	end
	local function output(path, mode)
		local file = io.open(path, mode)
		if not iso then return file end
		isolated_need(file, "cannot open generated output")
		return {
			write = function(_, ...) isolated_need(file:write(...), "generated write failed") end,
			close = function() isolated_need(file:close(), "generated close failed") end
		}
	end
	local FLAG = var["-FLAG"]
	local TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"]
	local DNSMASQ_CONF_FILE = var["-DNSMASQ_CONF_FILE"]
	local LISTEN_PORT = var["-LISTEN_PORT"]
	local DEFAULT_DNS = var["-DEFAULT_DNS"]
	local LOCAL_DNS = var["-LOCAL_DNS"]
	local TUN_DNS = var["-TUN_DNS"]
	local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
	local CHINADNS_DNS = var["-CHINADNS_DNS"]
	local NODE = var["-NODE"]
	local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
	local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
	local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
	local USE_GFW_LIST = var["-USE_GFW_LIST"]
	local CHN_LIST = var["-CHN_LIST"]
	local DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"]
	local NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"]
	local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
	local NFTFLAG = var["-NFTFLAG"]
	local CACHE_PATH = iso and (iso.root .. "/cache") or api.CACHE_PATH
	local CACHE_FLAG = "dnsmasq_" .. FLAG
	local CACHE_DNS_PATH = CACHE_PATH .. "/" .. CACHE_FLAG
	local CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"
	local USE_CHINADNS_NG = "0"
	local IS_SHUNT_NODE = get(NODE, "protocol") == "_shunt"
	local USE_GEOVIEW = get("@global_rules[0]", "enable_geoview")

	local list1 = {}
	local excluded_domain = {}

	if iso then
		USE_GEOVIEW = iso.inputs.geoview and "1" or "0"
	elseif not api.is_finded("geoview") then
		USE_GEOVIEW = "0"
	end

	local function log(...)
		if NO_LOGIC_LOG == "1" then
			return
		end
		api.log(...)
	end

	local function check_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return false
		end
		if not dns then
			return
		end
		for k,v in ipairs(list1[domain].dns) do
			if dns == v then
				return true
			end
		end
		return false
	end

	local function check_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return false
		end
		if not ipset then
			return
		end
		for k,v in ipairs(list1[domain].ipsets) do
			if ipset == v then
				return true
			end
		end
		return false
	end

	local function set_domain_address(domain, address)
		if domain == "" or domain:find("#") then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		if not list1[domain].address then
			list1[domain].address = address
		end
	end

	local function set_domain_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return
		end
		if not dns then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(dns, '[^' .. "," .. ']+') do
			if not check_dns(domain, line) then
				table.insert(list1[domain].dns, line)
			end
		end
	end

	local function set_domain_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return
		end
		if not ipset then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(ipset, '[^' .. "," .. ']+') do
			if not check_ipset(domain, line) then
				table.insert(list1[domain].ipsets, line)
			end
		end
	end

	local function add_excluded_domain(domain)
		if domain == "" or domain:find("#") then
			return
		end
		excluded_domain[domain] = true
	end

	local function check_excluded_domain(domain)
		if domain == "" or domain:find("#") then
			return false
		end
		if excluded_domain[domain] then
			return true
		end
		local pos = domain:find(".", 1, true)
		while pos do
			if excluded_domain[domain:sub(pos + 1)] then
				return true
			end
			pos = domain:find(".", pos + 1, true)
		end
		return false
	end

	local function foreach_geosite(list_arg, callback)
		local geosite_path
		if iso then geosite_path = isolated_need(iso.inputs.geosite, "geosite was not captured")
		else
			geosite_path = get("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
			geosite_path = geosite_path:match("^(.*)/") .. "/geosite.dat"
		end
		if not fs.access(geosite_path) then return 1, "File geosite.dat not found" end
		if not list_arg or list_arg == "" then return 1, "Site list cannot be empty" end
		local bin
		if iso then bin = isolated_need(iso.inputs.geoview, "geoview was not captured")
		else bin = api.finded_com("geoview") end
		local cmd = string.format("%q -type geosite -action extract -input %q -list %q -lowmem=true", bin, geosite_path, list_arg)
		if iso then cmd = quote(bin) .. " -type geosite -action extract -input " .. quote(geosite_path) .. " -list " .. quote(list_arg) .. " -lowmem=true" end
		local code, out = api.exec_call(cmd)
		if code ~= 0 then return code, out end
		for line in out:gmatch("[^\r\n]+") do
			callback(line)
		end
		return 0
	end

	local function get_dns_config_key()
		if iso then return isolated_md5(iso.root .. "/inputs.json") end
		local address_md5 = api.md5_string(sys.exec([[uci show passwall | grep -E '\.(address|download_address)=' | cut -d "'" -f 2 | sort -u]]))
		local new_rules = sys.exec([[
		for f in \
			/usr/share/passwall/rules/chnlist \
			/usr/share/passwall/rules/gfwlist \
			/etc/passwall/rules/direct_host \
			/etc/passwall/rules/proxy_host \
			/etc/passwall/rules/block_host
		do
			[ -f "$f" ] && md5sum "$f" | awk '{printf "%s", $1}'
		done
		]])
		local SHUNT_LIST = ""
		if IS_SHUNT_NODE then
			local t = get(NODE)
			foreach("shunt_rules", function(s)
				local _node_id = t[s[".name"]]
				if _node_id and t["shunt_group"] == s.group then
					SHUNT_LIST = SHUNT_LIST .. (s.domain_list or "") .. (_node_id:sub(1, 1) == "_" and "not-node" or "node")
				end
			end)
		end
		new_rules = new_rules .. api.md5_string(SHUNT_LIST)
		return TMP_DNSMASQ_PATH .. DNSMASQ_CONF_FILE .. DEFAULT_DNS .. LOCAL_DNS .. TUN_DNS .. USE_DEFAULT_DNS .. CHINADNS_DNS .. USE_DIRECT_LIST .. USE_PROXY_LIST .. USE_BLOCK_LIST .. USE_GFW_LIST .. CHN_LIST .. DEFAULT_PROXY_MODE .. NO_PROXY_IPV6 .. address_md5 .. new_rules .. NFTFLAG
	end

	local dnsmasq_default_dns
	if USE_DEFAULT_DNS ~= "nil" then
		if USE_DEFAULT_DNS == "direct" then
			dnsmasq_default_dns = LOCAL_DNS
		end
		if USE_DEFAULT_DNS == "remote" then
			dnsmasq_default_dns = TUN_DNS
		end
		if USE_DEFAULT_DNS == "remote" and CHN_LIST == "direct" then
			dnsmasq_default_dns = TUN_DNS
		end
	end

	local only_global
	if DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0" then
		--没有启用中国列表和GFW列表时
		dnsmasq_default_dns = TUN_DNS
		only_global = 1
	end
	if USE_DEFAULT_DNS == "chinadns_ng" and CHINADNS_DNS ~= "0" then
		dnsmasq_default_dns = CHINADNS_DNS
		USE_CHINADNS_NG = "1"
	end

	local setflag_4= (NFTFLAG == "1") and "4#inet#passwall#" or ""
	local setflag_6= (NFTFLAG == "1") and "6#inet#passwall#" or ""

	local new_text = ""
	if USE_CHINADNS_NG == "0" then
		local cache_text = ""
		if fs.access(CACHE_TEXT_FILE) then
			for line in io.lines(CACHE_TEXT_FILE) do
				cache_text = line
			end
		end
		new_text = get_dns_config_key()
		if cache_text == "" or new_text == "" or cache_text ~= new_text then
			if not iso then api.remove(CACHE_DNS_PATH .. "*") end
		end
	else
		if not iso then api.remove(CACHE_DNS_PATH .. "*") end
	end

	if not fs.access(CACHE_DNS_PATH) then
		local made = fs.mkdir(CACHE_DNS_PATH)
		if iso then isolated_need(made, "cannot create private rule directory") end
		local GEO_SUCCESS = true

		--屏蔽列表
		if USE_CHINADNS_NG == "0" and USE_BLOCK_LIST == "1" then
			local geosite_arg = ""
			local f = open_rule("/etc/passwall/rules/block_host")
			if f then
				for line in f:lines() do
					if not line:find("#") and line:find("geosite:") then
						line = string.match(line, ":([^:]+)$")
						geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
					else
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") and not line:find(":") then
							set_domain_address(line, "")
						end
					end
				end
				f:close()
			end
			if USE_GEOVIEW == "1" and geosite_arg ~= "" then
				local code, out = foreach_geosite(geosite_arg, function(line)
					set_domain_address(line, "")
				end)
				if code == 0 then
					log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成")
				else
					log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！[" .. out .. "]")
					GEO_SUCCESS = false
				end
			end
		end

		local fwd_dns
		local no_ipv6

		--始终用国内DNS解析节点域名
		if true then
			fwd_dns = LOCAL_DNS
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			else
				local sets = {
					setflag_4 .. "psw_vps",
					setflag_6 .. "psw_vps6"
				}
				local function process_address(address)
					address = (address or ""):lower()
					if api.vps_domain_exclude(address) then return end
					if datatypes.hostname(address) then
						set_domain_dns(address, fwd_dns)
						set_domain_ipset(address, table.concat(sets, ","))
					end
				end
				foreach("nodes", function(t)
					process_address(t.address)
					process_address(t.download_address)
				end)
				log(string.format("  - 节点列表中的域名(vpslist)：%s", fwd_dns or "默认"))
			end
		end

		--直连（白名单）列表
		if USE_DIRECT_LIST == "1" then
			fwd_dns = LOCAL_DNS
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			end
			if fwd_dns then
				local sets = {
					setflag_4 .. "psw_white",
					setflag_6 .. "psw_white6"
				}
				--始终用国内DNS解析直连（白名单）列表
				local geosite_arg = ""
				local f = open_rule("/etc/passwall/rules/direct_host")
				if f then
					for line in f:lines() do
						if not line:find("#") and line:find("geosite:") then
							line = string.match(line, ":([^:]+)$")
							geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
						else
							line = api.get_std_domain(line)
							if line ~= "" and not line:find("#") and not line:find(":") then
								add_excluded_domain(line)
								set_domain_dns(line, fwd_dns)
								set_domain_ipset(line, table.concat(sets, ","))
							end
						end
					end
					f:close()
					log(string.format("  - 域名白名单(whitelist)：%s", fwd_dns or "默认"))
				end
				if USE_GEOVIEW == "1" and geosite_arg ~= "" then
					local code, out = foreach_geosite(geosite_arg, function(line)
						add_excluded_domain(line)
						set_domain_dns(line, fwd_dns)
						set_domain_ipset(line, table.concat(sets, ","))
					end)
					if code == 0 then
						log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)完成")
					else
						log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)失败！[" .. out .. "]")
						GEO_SUCCESS = false
					end
				end
			end
		end

		--代理（黑名单）列表
		if USE_PROXY_LIST == "1" then
			fwd_dns = TUN_DNS
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			end
			if fwd_dns then
				local set_name = "psw_black"
				local set6_name = "psw_black6"
				if FLAG ~= "default" then
					set_name = "psw_" .. FLAG .. "_black"
					set6_name = "psw_" .. FLAG .. "_black6"
				end
				local sets = {
					setflag_4 .. set_name
				}
				if NO_PROXY_IPV6 ~= "1" then
					table.insert(sets, setflag_6 .. set6_name)
				end
				--始终使用远程DNS解析代理（黑名单）列表
				local geosite_arg = ""
				local f = open_rule("/etc/passwall/rules/proxy_host")
				if f then
					for line in f:lines() do
						if not line:find("#") and line:find("geosite:") then
							line = string.match(line, ":([^:]+)$")
							geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
						else
							line = api.get_std_domain(line)
							if line ~= "" and not line:find("#") and not line:find(":") then
								add_excluded_domain(line)
								if NO_PROXY_IPV6 == "1" then
									set_domain_address(line, "::")
								end
								set_domain_dns(line, fwd_dns)
								set_domain_ipset(line, table.concat(sets, ","))
							end
						end
					end
					f:close()
					log(string.format("  - 代理域名表(blacklist)：%s", fwd_dns or "默认"))
				end
				if USE_GEOVIEW == "1" and geosite_arg ~= "" then
					local code, out = foreach_geosite(geosite_arg, function(line)
						add_excluded_domain(line)
						if NO_PROXY_IPV6 == "1" then
							set_domain_address(line, "::")
						end
						set_domain_dns(line, fwd_dns)
						set_domain_ipset(line, table.concat(sets, ","))
					end)
					if code == 0 then
						log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)完成")
					else
						log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)失败！[" .. out .. "]")
						GEO_SUCCESS = false
					end
				end
			end
		end

		--GFW列表
		if USE_GFW_LIST == "1" then
			fwd_dns = TUN_DNS
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			end
			if fwd_dns then
				local set_name = "psw_gfw"
				local set6_name = "psw_gfw6"
				if FLAG ~= "default" then
					set_name = "psw_" .. FLAG .. "_gfw"
					set6_name = "psw_" .. FLAG .. "_gfw6"
				end
				local sets = {
					setflag_4 .. set_name
				}
				if NO_PROXY_IPV6 ~= "1" then
					table.insert(sets, setflag_6 .. set6_name)
				end
				local f = open_rule("/usr/share/passwall/rules/gfwlist")
				if f then
					for line in f:lines() do
						if line ~= "" and not line:find("#") and not check_excluded_domain(line) then
							if NO_PROXY_IPV6 == "1" then
								set_domain_address(line, "::")
							end
							if dnsmasq_default_dns == fwd_dns then
								fwd_dns = nil
							else
								set_domain_dns(line, fwd_dns)
							end
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					f:close()
					log(string.format("  - 防火墙域名表(gfwlist)：%s", fwd_dns or "默认"))
				end
			end
		end

		--中国列表
		if CHN_LIST ~= "0" then
			fwd_dns = nil
			if CHN_LIST == "direct" then
				fwd_dns = LOCAL_DNS
			end
			if CHN_LIST == "proxy" then
				fwd_dns = TUN_DNS
			end
			if USE_CHINADNS_NG == "1" then
				fwd_dns = nil
			end
			if fwd_dns then
				local sets = {
					setflag_4 .. "psw_chn",
					setflag_6 .. "psw_chn6"
				}
				if CHN_LIST == "proxy" then
					if NO_PROXY_IPV6 == "1" then
						sets = {
							setflag_4 .. "psw_chn"
						}
					end
				end
				local f = open_rule("/usr/share/passwall/rules/chnlist")
				if f then
					for line in f:lines() do
						if line ~= "" and not line:find("#") and not check_excluded_domain(line) then
							if CHN_LIST == "proxy" and NO_PROXY_IPV6 == "1" then
								set_domain_address(line, "::")
							end
							if dnsmasq_default_dns == fwd_dns then
								fwd_dns = nil
							else
								set_domain_dns(line, fwd_dns)
							end
							set_domain_ipset(line, table.concat(sets, ","))
						end
					end
					f:close()
					log(string.format("  - 中国域名表(chnlist)：%s", fwd_dns or "默认"))
				end
			end
		end

		--分流规则
		if IS_SHUNT_NODE and USE_CHINADNS_NG == "0" and only_global ~= 1 then
			local t = get(NODE)
			local default_node_id = t["default_node"] or "_direct"
			foreach("shunt_rules", function(s)
				local _node_id = t[s[".name"]]
				if _node_id and t["shunt_group"] == s.group then
					if _node_id == "_default" then
						_node_id = default_node_id
					end

					fwd_dns = TUN_DNS

					local sets = {
						setflag_4 .. "psw_shunt",
						setflag_6 .. "psw_shunt6"
					}
					if FLAG ~= "default" then
						sets = {
							setflag_4 .. "psw_" .. FLAG .. "_shunt",
							setflag_6 .. "psw_" .. FLAG .. "_shunt6"
						}
					end

					local domain_list = s.domain_list or ""
					local geosite_arg = ""
					for line in string.gmatch(domain_list, "[^\r\n]+") do
						if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("ext:") and not line:find("rule-set:") and not line:find("rs:") then
							if line:find("geosite:") then
								line = string.match(line, ":([^:]+)$")
								geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
							else
								if line:find("domain:") or line:find("full:") then
									line = string.match(line, ":([^:]+)$")
								end
								line = api.get_std_domain(line)
								add_excluded_domain(line)
								set_domain_dns(line, fwd_dns)
								set_domain_ipset(line, table.concat(sets, ","))
							end
						end
					end

					if USE_GFW_LIST == "1" and CHN_LIST == "0" and USE_GEOVIEW == "1" and geosite_arg ~= "" then  --仅GFW模式解析geosite
						local code, out = foreach_geosite(geosite_arg, function(line)
							add_excluded_domain(line)
							set_domain_dns(line, fwd_dns)
							set_domain_ipset(line, table.concat(sets, ","))
						end)
						if code == 0 then
							log(string.format("  - 解析分流规则(%s) Geosite 完成", s.remarks))
						else
							log(string.format("  - 解析分流规则(%s) Geosite 失败！[" .. out .. "]", s.remarks))
							GEO_SUCCESS = false
						end
					end

					if _node_id ~= "_direct" and _node_id ~= "_blackhole" then
						log(string.format("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, fwd_dns or "默认"))
					end
				end
			end)
		elseif only_global == 1 and NO_PROXY_IPV6 == "1" then
			--节点：固定节点
			--代理模式：全局模式
			--过滤代理域名 IPv6：启用
			--禁止解析所有IPv6记录
			list1["#"] = {
				dns = {},
				ipsets = {},
				address = "::"
			}
		end

		if list1 and next(list1) then
			local address_out = output(CACHE_DNS_PATH .. "/000-address.conf", "a")
			local server_out = output(CACHE_DNS_PATH .. "/001-server.conf", "a")
			local ipset_out = output(CACHE_DNS_PATH .. "/ipset.conf", "a")
			local set_name = "ipset"
			if NFTFLAG == "1" then
				set_name = "nftset"
			end
			for key, value in pairs(list1) do
				if value.address then
					local domain = "." .. key
					if key == "#" then
						domain = key
					end
					address_out:write(string.format("address=/%s/%s", domain, value.address) .. "\n")
				end
				if value.dns and #value.dns > 0 then
					for i, dns in ipairs(value.dns) do
						server_out:write(string.format("server=/.%s/%s", key, dns) .. "\n")
					end
				end
				if value.ipsets and #value.ipsets > 0 then
					local ipsets_str = ""
					for i, ipset in ipairs(value.ipsets) do
						ipsets_str = ipsets_str .. ipset .. ","
					end
					ipsets_str = ipsets_str:sub(1, #ipsets_str - 1)
					ipset_out:write(string.format("%s=/.%s/%s", set_name, key, ipsets_str) .. "\n")
				end
			end
			address_out:close()
			server_out:close()
			ipset_out:close()
		end
		
		if iso then isolated_need(GEO_SUCCESS, "geosite generation failed") end
		if not GEO_SUCCESS then new_text = "" end
		local f_out = output(CACHE_TEXT_FILE, "a")
		f_out:write(new_text)
		f_out:close()
	else
		log("  - 从缓存加载 Dnsmasq 域名分流规则。")
	end

	if USE_CHINADNS_NG == "0" and not iso then
		api.remove(TMP_DNSMASQ_PATH)
		fs.symlink(CACHE_DNS_PATH, TMP_DNSMASQ_PATH)
	end

	if DNSMASQ_CONF_FILE ~= "nil" then
		local conf_lines = {}
		if LISTEN_PORT then
			--Copy dnsmasq instance
			conf_lines = copy_instance({["-LISTEN_PORT"] = LISTEN_PORT, ["-TMP_DNSMASQ_PATH"] = TMP_DNSMASQ_PATH, ["-return"] = "1", _isolated = iso})
			--dhcp.leases to hosts
			if not iso then
				local hosts = api.CACHE_PATH .. "/dhcp-hosts"
				sys.call("touch " .. hosts)
				tinsert(conf_lines, "addn-hosts=" .. hosts)
			end
		else
			--Modify the default dnsmasq service
		end
		if USE_CHINADNS_NG == "0" then
			tinsert(conf_lines, string.format("conf-dir=%s", TMP_DNSMASQ_PATH))
		end
		if dnsmasq_default_dns then
			for s in string.gmatch(dnsmasq_default_dns, '[^' .. "," .. ']+') do
				tinsert(conf_lines, string.format("server=%s", s))
			end
			tinsert(conf_lines, "all-servers")
			tinsert(conf_lines, "no-poll")
			tinsert(conf_lines, "no-resolv")
			if USE_CHINADNS_NG == "0" then
				log(string.format("  - 默认：%s", dnsmasq_default_dns))
			end

			if FLAG == "default" and not iso then
				api.set_cache_var("DEFAULT_DNS", DEFAULT_DNS)
			end
		end
		if #conf_lines > 0 then
			local conf_out = output(DNSMASQ_CONF_FILE, iso and "w" or "a")
			if conf_out then
				conf_out:write(table.concat(conf_lines, "\n"))
				conf_out:write("\n")
				conf_out:close()
			end
		end
	end

	if USE_CHINADNS_NG == "0" then
		log("  - PassWall必须依赖于Dnsmasq，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理)分流失效！！！")
	end
end

_G.stretch = stretch
_G.restart = restart
_G.logic_restart = logic_restart
_G.copy_instance = copy_instance
_G.add_rule = add_rule

local function isolated_generate(var)
	local ctx = isolated_context(var)
	ctx.inputs = isolated_inputs(ctx)
	isolated_need(not fs.lstat(ctx.args["-DNSMASQ_CONF_FILE"]) and
		not fs.lstat(ctx.args["-TMP_DNSMASQ_PATH"]), "private generation already exists")
	ctx.args._isolated = ctx
	add_rule(ctx.args)
	-- Recheck captured inputs and generation after all reads and geoview calls.
	isolated_inputs(ctx)
	isolated_need(isolated_snapshot(ctx.snapshot).seal == ctx.frozen.seal, "generation changed during generation")
end

local function isolated_config_manifest(ctx)
	local paths = {"dnsmasq.conf"}
	local rules = "cache/dnsmasq_" .. ctx.args["-FLAG"]
	isolated_need(fs.realpath(ctx.root .. "/" .. rules) == ctx.root .. "/" .. rules and
		isolated_type(ctx.root .. "/cache/dnsmasq_" .. ctx.args["-FLAG"] .. ".txt") == "reg", "incomplete generated cache")
	for name in isolated_need(fs.dir(ctx.root .. "/cache"), "missing generated cache") do
		isolated_need(name == "dnsmasq_" .. ctx.args["-FLAG"] or name == "dnsmasq_" .. ctx.args["-FLAG"] .. ".txt", "unexpected cache entry")
		if name:match("%.txt$") then paths[#paths + 1] = "cache/" .. name end
	end
	for name in isolated_need(fs.dir(ctx.root .. "/" .. rules), "missing generated rules") do
		isolated_need(name == "000-address.conf" or name == "001-server.conf" or name == "ipset.conf", "unexpected generated rule")
		paths[#paths + 1] = rules .. "/" .. name
	end
	table.sort(paths)
	local manifest = {}
	for _, path in ipairs(paths) do
		local full = ctx.root .. "/" .. path
		isolated_need(fs.realpath(full) == full and isolated_type(full) == "reg", "invalid generated file")
		manifest[#manifest + 1] = isolated_md5(full) .. "  " .. path .. "\n"
	end
	return table.concat(manifest)
end

local function isolated_verify(var)
	local ctx = isolated_context(var)
	isolated_inputs(ctx)
	local manifest = isolated_config_manifest(ctx)
	if var["-SEAL_CONFIG"] == "1" then
		isolated_need(not fs.lstat(ctx.root .. "/config.md5"), "configuration manifest already exists")
		isolated_write(ctx.root .. "/config.md5", manifest)
	else isolated_need(isolated_read(ctx.root .. "/config.md5") == manifest, "generated configuration changed") end
end

if arg[1] then
	local var = api.get_function_args(arg)
	local actions = {isolated_capture = isolated_capture, isolated_generate = isolated_generate, isolated_verify = isolated_verify}
	if actions[arg[1]] then
		local ok, err = pcall(actions[arg[1]], var or {})
		if not ok then
			local detail = type(err) == "string" and err:match("DNS isolated configuration: (.+)") or nil
			io.stderr:write("dns_dep_config_invalid: " .. (detail or "isolated generator failed") .. "\n"); os.exit(1)
		end
	elseif var and (var["-ISOLATED_ROOT"] or var["-SNAPSHOT"]) then
		io.stderr:write("dns_dep_config_invalid: isolated action required\n"); os.exit(1)
	else
		local func = _G[arg[1]]
		if func then func(var) end
	end
end
