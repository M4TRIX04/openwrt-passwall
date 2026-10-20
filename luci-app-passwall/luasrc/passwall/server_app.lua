#!/usr/bin/lua

local action = arg[1]
local api = require "luci.passwall.api"
local sys = api.sys
local uci = api.uci
local jsonc = api.jsonc

local CONFIG = api.s_config
local CONFIG_PATH = api.S_TMP_PATH
local LOG_APP_FILE = "/tmp/log/" .. CONFIG .. ".log"
local TMP_BIN_PATH = CONFIG_PATH .. "/bin"
local require_dir = "luci.passwall."

local function log(...)
	local f, err = io.open(LOG_APP_FILE, "a")
	if f and err == nil then
		local str = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		f:write(str .. "\n")
		f:close()
	end
end

local function cmd(cmd)
	sys.call(cmd)
end

local function ln_run(s, d, command, output)
	if not output then
		output = "/dev/null"
	end
	d = TMP_BIN_PATH .. "/" .. d
	cmd(string.format('[ ! -f "%s" ] && ln -s %s %s 2>/dev/null', d, s, d))
	return string.format("%s >%s 2>&1 &", d .. " " .. command, output)
end

local function remove_firewall_rules(defer_commit)
	local to_delete = {}
	uci:foreach("firewall", "rule", function(rule)
		local name = rule[".name"]
		if name and name:find(CONFIG, 1, true) == 1 then
			table.insert(to_delete, name)
		end
	end)
	if #to_delete > 0 then
		for _, name in ipairs(to_delete) do
			uci:delete("firewall", name)
		end
		if not defer_commit then
			api.uci_save(uci, "firewall", true, true)
		end
		return true
	end
	return false
end

local function start()
	local enabled = tonumber(api.uci_get_s("@global[0]", "enable") or 0)
	if enabled == nil or enabled == 0 then
		return
	end

	-- 启动前清理所有旧防火墙规则
	local fw_changed = remove_firewall_rules(true)

	cmd(string.format("mkdir -p %s %s", CONFIG_PATH, TMP_BIN_PATH))
	cmd(string.format("touch %s", LOG_APP_FILE))
	local firewall_num = 0
	api.uci_foreach_s("server", function(server)
		local id = server[".name"]
		local enable = server.enable
		if enable and tonumber(enable) == 1 then
			local enable_log = server.log
			local log_path = nil
			if enable_log and enable_log == "1" then
				log_path = CONFIG_PATH .. "/" .. id .. ".log"
			else
				log_path = nil
			end
			local remarks = server.remarks
			local port = tonumber(server.port)
			local bin
			local config = {}
			local config_file = CONFIG_PATH .. "/" .. id .. ".json"
			local udp_forward = 1
			local type = server.type or ""
			if type == "Hysteria2" or type == "Xray" or type == "sing-box" then
				log("Server " .. id .. " rejected: " .. type .. " support has been removed.")
				return
			end
			if type == "Socks" then
				local auth = ""
				if server.auth and server.auth == "1" then
					local user = nil
					if server.user then
						user = api.uci_get_s(server.user)
					end
					local username = user and user.username or ""
					local password = user and user.password or ""
					if username ~= "" and password ~= "" then
						username = "-u " .. username
						password = "-P " .. password
						auth = username .. " " .. password
					end
				end
				bin = ln_run("/usr/bin/microsocks", "microsocks_" .. id, string.format("-i :: -p %s %s", port, auth), log_path)
			elseif type == "SS" or type == "SSR" then
				if type == "SS" then
					local ss = require(require_dir .. "util_shadowsocks")
					local ok, result = pcall(function()
						local value
						if server.custom == "1" and server.config_str then
							value = jsonc.parse(api.base64Decode(server.config_str))
							if _G.type(value) ~= "table" then error("Shadowsocks-libev: invalid server JSON", 0) end
							ss.validate_method(value.method)
						else
							value = ss.gen_config_server(server)
						end
						return value
					end)
					if not ok then
						log("SS server " .. id .. " rejected: " .. tostring(result))
						return
					end
					config = result
				elseif server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
				else
					config = require(require_dir .. "util_shadowsocks").gen_config_server(server)
				end
				local udp_param = ""
				udp_forward = tonumber(server.udp_forward) or 1
				if udp_forward == 1 then
					udp_param = "-u"
				end
				type = type:lower()
				bin = ln_run("/usr/bin/" .. type .. "-server", type .. "-server", "-c " .. config_file .. " " .. udp_param, log_path)
			elseif type == "SS-Rust" then
				if server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
				else
					config = require(require_dir .. "util_shadowsocks").gen_config_server(server)
				end
				bin = ln_run("/usr/bin/ssserver", "ssserver", "-c " .. config_file, log_path)
			elseif type == "Hysteria" then
				local ok, result = pcall(function()
					local c = require(require_dir .. "util_hysteria").gen_config_server(server)
					local f = assert(io.open(config_file, "w"))
					local written, err = f:write(jsonc.stringify(c, 1))
					local closed = f:close()
					assert(written and closed, err or "cannot write Hysteria config")
					require(require_dir .. "hysteria_runtime").start({
						config=config_file, bin=api.get_app_path("hysteria"), bin_dir=TMP_BIN_PATH,
						scope="server", mode="server", log=log_path or "/dev/null"
					})
					return c
				end)
				if not ok then
					api.fs.remove(config_file)
					log("Hysteria 1 server " .. id .. " rejected: " .. tostring(result))
					return
				end
				-- Already written and started by the checked v1 launcher.
			end

			-- Ignore legacy SIP003 options, including custom SS server JSON.
			if server.type == "SS" then
				config.plugin = nil
				config.plugin_opts = nil
			end

			if next(config) then
				local f, err = io.open(config_file, "w")
				if f and err == nil then
					f:write(jsonc.stringify(config, 1))
					f:close()
				end
				log(string.format("%s 生成配置文件并运行 - %s", remarks, config_file))
			end

			if bin then
				cmd(bin)
			end

			local firewall_allow = server.firewall_allow
			if firewall_allow == "1" then
				firewall_num = firewall_num + 1
				local uid = CONFIG .. "_" .. id
				uci:section("firewall", "rule", uid)
				uci:set("firewall", uid, "name", uid)
				uci:set("firewall", uid, "src", server.firewall_allow_src or "wan")
				uci:set("firewall", uid, "dest_port", port)
				uci:set("firewall", uid, "target", "ACCEPT")
				if server.type == "Hysteria" then
					uci:set("firewall", uid, "proto", server.protocol == "faketcp" and "tcp" or "udp")
				end
			end
		end
	end)
	if firewall_num > 0 or fw_changed then
		api.uci_save(uci, "firewall", true, true)
	end
end

local function stop()
	local cleanup_ok, cleanup_error = true, nil
	-- Reclaim v1 processes and core-required faketcp rules before generic kill.
	if api.fs and api.fs.access("/tmp/etc/passwall_hysteria1") then
		cleanup_ok, cleanup_error = pcall(function() require(require_dir .. "hysteria_runtime").stop("server") end)
		if not cleanup_ok then io.stderr:write("Hysteria cleanup pending: " .. tostring(cleanup_error) .. "\n") end
	end
	cmd(string.format("/bin/busybox top -bn1 | grep -v 'grep' | grep '%s/' | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1", CONFIG_PATH))
	remove_firewall_rules()
	api.remove(CONFIG_PATH, LOG_APP_FILE)
	if not cleanup_ok then error(cleanup_error, 0) end
end

if action then
	if action == "start" then
		start()
	elseif action == "stop" then
		stop()
	end
end
