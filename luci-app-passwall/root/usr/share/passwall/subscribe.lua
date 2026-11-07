#!/usr/bin/lua

------------------------------------------------
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require 'luci.util'
require 'luci.jsonc'
require 'luci.sys'
local appname = 'passwall'
local api = require ("luci.passwall.api")
local datatypes = require "luci.cbi.datatypes"


-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local split = api.split
local jsonParse, jsonStringify = luci.jsonc.parse, luci.jsonc.stringify
local base64Decode = api.base64Decode
local UrlEncode = api.UrlEncode
local UrlDecode = api.UrlDecode
local uci = api.uci
local fs = api.fs

local has_ss = api.is_finded("ss-redir")
local DEFAULT_ALLOWINSECURE = true
-- SS 只接受 AEAD 加密，与服务端/客户端 UI 的白名单保持一致
local SS_AEAD_METHODS = {
	["aes-128-gcm"] = true,
	["aes-192-gcm"] = true,
	["aes-256-gcm"] = true,
	["chacha20-ietf-poly1305"] = true,
	["xchacha20-ietf-poly1305"] = true,
}
local nodeResult = {} -- update result
local isDebug = false

local log = function(...)
	if isDebug == true then
		local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		print(result)
	else
		api.log(...)
	end
end

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = e
	end
end

-- 获取各项动态配置的当前服务器，可以用 get 和 set， get必须要获取到节点表
local CONFIG = {}
do
	local function import_config(protocol)
		local name = string.upper(protocol)
		local szType = "@global[0]"
		local option = protocol .. "_node"
		
		local node_id = uci:get(appname, szType, option)
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = name .. "节点",
			currentNode = node_id and uci:get_all(appname, node_id) or nil,
			set = function(o, server)
				uci:set(appname, szType, option, server)
				o.newNodeId = server
			end
		}
	end
	import_config("tcp")
	import_config("udp")

	if true then
		local i = 0
		local option = "node"
		uci:foreach(appname, "socks", function(t)
			i = i + 1
			local id = t[".name"]
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = id,
				remarks = "Socks节点列表[" .. i .. "]",
				currentNode = node_id and uci:get_all(appname, node_id) or nil,
				set = function(o, server)
					if not server or server == "" then
						if #nodes_table > 0 then
							server = nodes_table[1][".name"]
						end
					end
					uci:set(appname, t[".name"], option, server)
					o.newNodeId = server
				end
			}
			if t.autoswitch_backup_node and #t.autoswitch_backup_node > 0 then
				local flag = "Socks节点列表[" .. i .. "]备用节点的列表"
				local currentNodes = {}
				local newNodes = {}
				for k, node_id in ipairs(t.autoswitch_backup_node) do
					if node_id then
						local currentNode = uci:get_all(appname, node_id) or nil
						if currentNode then
							currentNodes[#currentNodes + 1] = {
								log = true,
								remarks = flag .. "[" .. k .. "]",
								currentNode = currentNode,
								set = function(o, server)
									if server and server ~= "nil" then
										table.insert(o.newNodes, server)
									end
								end
							}
						end
					end
				end
				CONFIG[#CONFIG + 1] = {
					remarks = flag,
					currentNodes = currentNodes,
					newNodes = newNodes,
					set = function(o, newNodes)
						if o then
							if not newNodes then newNodes = o.newNodes end
							uci:set_list(appname, id, "autoswitch_backup_node", newNodes or {})
						end
					end
				}
			end
		end)
	end

	if true then
		local i = 0
		local options = {"tcp", "udp"}
		uci:foreach(appname, "acl_rule", function(t)
			i = i + 1
			for index, value in ipairs(options) do
				local option = value .. "_node"
				local node_id = t[option]
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = t[".name"],
					remarks = "访问控制列表[" .. i .. "]",
					currentNode = node_id and uci:get_all(appname, node_id) or nil,
					set = function(o, server)
						uci:set(appname, t[".name"], option, server)
						o.newNodeId = server
					end
				}
			end
		end)
	end


	for k, v in pairs(CONFIG) do
		if v.currentNodes and type(v.currentNodes) == "table" then
			for kk, vv in pairs(v.currentNodes) do
				if vv.currentNode == nil then
					CONFIG[k].currentNodes[kk] = nil
				end
			end
		else
			if v.currentNode == nil then
				if v.delete then
					v.delete()
				end
				CONFIG[k] = nil
			end
		end
	end
end

-- 设置 ss 协议实现类型
local function set_ss_implementation(result)
	if has_ss then
		result.type = 'SS'
	else
		log("跳过 SS 节点，因未安装 shadowsocks-libev 核心。")
		return nil
	end
	return result
end

-- 处理数据
local function processData(szType, content, add_mode, group)
	--log(2, content, add_mode, group)
	local sub_allowinsecure = DEFAULT_ALLOWINSECURE
	local sub_hy_up_mbps, sub_hy_down_mbps = 1000, 1000
	local result = {
		timeout = 60,
		add_mode = add_mode, --0为手动配置,1为导入,2为订阅
		group = group
	}
	if szType == "ss" then
		result = set_ss_implementation(result)
		if not result then return nil end

		--SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
		--userinfo = websafe-base64-encode-utf8(method  ":" password)
		--ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1
		--ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver#Example3
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp4eHh4eHhAeHh4eC54eHh4eC5jb206NTYwMDE#Hong%20Kong-01

		local idx_sp = content:find("#") or 0
		local alias = ""
		if idx_sp > 0 then
			alias = content:sub(idx_sp + 1, -1)
		end
		result.remarks = UrlDecode(alias)
		local info = content:sub(1, idx_sp - 1):gsub("/%?", "?")
		local params = {}
		if info:find("%?") then
			local find_index = info:find("%?")
			local query = split(info, "%?")
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
				end
			end
			if params.plugin then
				local plugin_info = params.plugin
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
			info = info:sub(1, find_index - 1)
		end

		local hostInfo = split(base64Decode(UrlDecode(info)), "@")
		if hostInfo and #hostInfo > 0 then
			local host_port = hostInfo[#hostInfo]
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local userinfo = nil
			if #hostInfo > 2 then
				userinfo = {}
				for i = 1, #hostInfo - 1 do
					tinsert(userinfo, hostInfo[i])
				end
				userinfo = table.concat(userinfo, '@')
			else
				userinfo = base64Decode(hostInfo[1])
			end
			local method, password
			if userinfo:find(":") then
				method = userinfo:sub(1, userinfo:find(":") - 1)
				password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
			else
				password = hostInfo[1]  --一些链接用明文uuid做密码
			end

			-- 判断密码是否经过url编码
			local function isURLEncodedPassword(pwd)
				if not pwd:find("%%[0-9A-Fa-f][0-9A-Fa-f]") then
					return false
				end
				local ok, decoded = pcall(UrlDecode, pwd)
				return ok and UrlEncode(decoded) == pwd
			end

			local decoded = UrlDecode(password)
			if isURLEncodedPassword(password) and decoded then
				password = decoded
			end

			local _method = (method or "none"):lower()
			method = (_method == "chacha20-poly1305" and "chacha20-ietf-poly1305") or
				(_method == "xchacha20-poly1305" and "xchacha20-ietf-poly1305") or _method

			result.method = method
			result.password = password
			result.tcp_fast_open = params.tfo
			result.use_finalmask = (params.fm and params.fm ~= "") and "1" or nil
			result.finalmask = (params.fm and params.fm ~= "") and api.base64Encode(params.fm) or nil

			if result.plugin then
				result.plugin_enabled = "1"
			end

			if params.type then
				params.type = string.lower(params.type)
				if params.type == "h2" or params.type == "http" then
					params.type = "http"
					result.transport = "http"
				else
					result.transport = params.type
				end
				if params.type == 'ws' then
					result.ws_host = params.host
					result.ws_path = params.path
				end
				if params.type == "http" then
					result.transport = "http"
					result.http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.http_path = params.path
				end
				if params.type == 'raw' or params.type == 'tcp' then
					result.tcp_guise = params.headerType or "none"
					result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
				end
				if params.type == 'kcp' or params.type == 'mkcp' then
					result.transport = "mkcp"
					result.mkcp_guise = params.headerType or "none"
					result.mkcp_seed = params.seed
				end
				if params.type == 'quic' then
					result.quic_guise = params.headerType or "none"
					result.quic_key = params.key
					result.quic_security = params.quicSecurity or "none"
				end
				if params.type == 'grpc' then
					if params.path then result.grpc_serviceName = params.path end
					if params.serviceName then result.grpc_serviceName = params.serviceName end
					result.grpc_mode = params.mode or "gun"
				end
				if params.type == 'xhttp' then
					result.error_msg = "不支持 xhttp 传输方式。"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
					result.xhttp_mode = params.mode or "auto"
					result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
					result.xhttp_extra = (params.extra and params.extra ~= "") and api.base64Encode(params.extra) or nil
					local success, Data = pcall(jsonParse, params.extra)
					if success and Data then
						local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
								or (Data.downloadSettings and Data.downloadSettings.address)
						result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "") or nil
					end
				end
				result.tls = "0"
				if params.security == "tls" or params.security == "reality" then
					result.tls = "1"
					result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
					result.alpn = params.alpn
					if params.fp and params.fp ~= "" then
						result.utls = "1"
						result.fingerprint = params.fp
					end
					if params.ech and params.ech ~= "" then
						result.ech = "1"
						result.ech_config = params.ech
					end
					result.tls_pinSHA256 = params.pcs
					result.tls_CertByName = params.vcn
					if params.security == "reality" then
						result.reality = "1"
						result.reality_publicKey = params.pbk or nil
						result.reality_shortId = params.sid or nil
						result.reality_spiderX = params.spx or nil
						result.use_mldsa65Verify = (params.pqv and params.pqv ~= "") and "1" or nil
						result.reality_mldsa65Verify = params.pqv or nil
					end
				end
				local insecure = params.allowinsecure or params.allowInsecure or params.insecure
				result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
				result.uot = params.udp
			end

			if params["shadow-tls"] then
				result.error_msg = "Shadowsocks 不支持 shadow-tls 插件。"
			end
		end
	elseif szType == "ssd" then
		result = set_ss_implementation(result)
		if not result then return nil end
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	elseif szType == 'hysteria' then
		result.type = "Hysteria"

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		
		local query = split(content:gsub("/%?", "?"), '%?')
		local host_port = query[1]
		local params = {}
		if query[2] then
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1)] = v:sub(s + 1)
				end
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.hysteria_obfs = params.obfsParam
		result.hysteria_auth_type = (params.auth and params.auth ~= "") and "string" or "disable"
		result.hysteria_auth_password = params.auth
		result.tls_serverName = params.peer or params.sni or ""
		local insecure = params.allowinsecure or params.allowInsecure or params.insecure
		result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
		-- 原生 hysteria 的 alpn 存带前缀的字段，protocol 是 udp/faketcp
		result.protocol = params.protocol
		result.hysteria_alpn = params.alpn
		result.hysteria_up_mbps = params.upmbps or sub_hy_up_mbps
		result.hysteria_down_mbps = params.downmbps or sub_hy_down_mbps
		result.hysteria_hop = params.mport

	else
		log("暂时不支持 " .. szType .. " 类型的节点订阅，跳过此节点。")
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	-- SS 节点只接受 AEAD 加密，其余跳过（订阅里常见的 rc4-md5 / aes-*-cfb 等）
	if result.type == "SS" or result.protocol == "shadowsocks" then
		local _m = result.method and tostring(result.method):lower() or ""
		if not SS_AEAD_METHODS[_m] then
			log("跳过节点：" .. tostring(result.remarks) .. "，加密方式 " .. (_m ~= "" and _m or "空") .. " 不是 AEAD。")
			return nil
		end
	end
	return result
end

local function select_node(nodes, config, parentConfig)
	if config.currentNode then
		local server
		-- 负载均衡、urltest中的 Socks [端口] 节点保持原id
		if config.currentNode["Socks"] then
			server = config.currentNode.Socks
		end
		-- 特别优先级 cfgid
		if config.currentNode[".name"] then
			for index, node in pairs(nodes) do
				if node[".name"] == config.currentNode[".name"] then
					if config.log == nil or config.log == true then
						log('更新【' .. config.remarks .. '】匹配节点：' .. node.remarks)
					end
					server = node[".name"]
					break
				end
			end
		end
		-- 第一优先级 类型 + 备注 + IP + 端口 + 分组
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.remarks and config.currentNode.address and config.currentNode.port then
					if node.type and node.remarks and node.address and node.port then
						if node.type == config.currentNode.type and node.remarks == config.currentNode.remarks and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第一匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第二优先级 类型 + IP + 端口 + 分组
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.address and config.currentNode.port then
					if node.type and node.address and node.port then
						if node.type == config.currentNode.type and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第二匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第三优先级 IP + 端口 + 分组
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address and config.currentNode.port then
					if node.address and node.port then
						if node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第三匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第四优先级 IP + 分组
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address then
					if node.address then
						if node.address == config.currentNode.address and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第四匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第五优先级备注 + 分组
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.remarks then
					if node.remarks then
						if node.remarks == config.currentNode.remarks and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第五匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		if not parentConfig then
			-- 还不行 随便找一个
			if not server then
				if #nodes_table > 0 then
					if config.log == nil or config.log == true then
						log('【' .. config.remarks .. '】' .. '无法找到最匹配的节点，当前已更换为：' .. nodes_table[1].remarks)
					end
					server = nodes_table[1][".name"]
				end
			end
		end
		if server then
			if parentConfig then
				config.set(parentConfig, server)
			else
				config.set(config, server)
			end
		end
	else
		if not parentConfig then
			config.set(config, "")
		end
	end
end

local function update_node(manual)
	if next(nodeResult) == nil then
		log("没有可用的节点信息更新。")
		return
	end

	local group = {}
	for _, v in ipairs(nodeResult) do
		group[v["remark"]:lower()] = true
	end

	if manual == 0 and next(group) then
		uci:foreach(appname, "nodes", function(node)
			-- 如果未发现新节点或手动导入的节点就不要删除了...
			if node.add_mode == "2" and (node.group and group[node.group:lower()] == true) then
				uci:delete(appname, node['.name'])
			end
		end)
	end
	for _, v in ipairs(nodeResult) do
		local remark = v["remark"]
		local list = v["list"]
		for _, vv in ipairs(list) do
			local cfgid = uci:section(appname, "nodes", api.gen_short_uuid())
			for kkk, vvv in pairs(vv) do
				if type(vvv) == "table" and next(vvv) ~= nil then
					uci:set_list(appname, cfgid, kkk, vvv)
				else
					if kkk ~= "group" or vvv ~= "default" then
						uci:set(appname, cfgid, kkk, vvv)
					end
				end
			end
		end
	end
	if next(CONFIG) then
		local nodes = {}
		uci:foreach(appname, "nodes", function(node)
			nodes[#nodes + 1] = node
		end)

		for _, config in pairs(CONFIG) do
			if config.currentNodes and #config.currentNodes > 0 then
				if config.remarks and config.currentNodes[1].log ~= false then
					log('----【' .. config.remarks .. '】----')
				end
				for kk, vv in pairs(config.currentNodes) do
					select_node(nodes, vv, config)
				end
				config.set(config)
			else
				select_node(nodes, config)
			end
		end
	end

	api.uci_save(uci, appname, true)

	if arg[3] == "cron" then
		if not fs.access("/var/lock/" .. appname .. ".lock") then
			luci.sys.call("touch /tmp/lock/" .. appname .. "_cron.lock")
		end
	end

	if manual ~= 1 then
		luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
	end
end

local function parse_link(raw, add_mode, group)
	if raw and #raw > 0 then
		local nodes, szType
		local node_list = {}
		-- SSD 似乎是这种格式 ssd:// 开头的
		if raw:find('ssd://') then
			szType = 'ssd'
			local nEnd = select(2, raw:find('ssd://'))
			nodes = base64Decode(raw:sub(nEnd + 1, #raw))
			nodes = jsonParse(nodes)
			local extra = {
				airport = nodes.airport,
				port = nodes.port,
				encryption = nodes.encryption,
				password = nodes.password
			}
			local servers = {}
			-- SS里面包着 干脆直接这样
			for _, server in ipairs(nodes.servers) do
				tinsert(servers, setmetatable(server, { __index = extra }))
			end
			nodes = servers
		else
			-- ssd 外的格式
			if add_mode == "1" then
				nodes = split(raw, "\n")
			else
				nodes = split(base64Decode(raw):gsub("\r\n", "\n"), "\n")
			end
		end

		for _, v in ipairs(nodes) do
			if v and (szType == 'ssd' or not string.match(v, "^%s*$")) then
				xpcall(function ()
					local result
					if szType == 'ssd' then
						result = processData(szType, v, add_mode, group)
					elseif not szType then
						local node = api.trim(v)
						local dat = split(node, "://")
						if dat and dat[1] and dat[2] then
							if dat[1] == 'vmess' then
								local link = api.trim(dat[2]:gsub("#.*$", ""))
								result = processData(dat[1], base64Decode(link), add_mode, group)
							else
								local link = dat[2]:gsub("&amp;", "&"):gsub("%s*#%s*", "#")  -- 一些奇葩的链接用"&amp;"当做"&"，"#"前后带空格
								result = processData(dat[1], link, add_mode, group)
							end
						end
					else
						log('跳过未知类型：' .. szType)
					end
					-- log(result)
					if result then
						if result.error_msg then
							log('丢弃节点：' .. result.remarks .. " ，原因：" .. result.error_msg)
						elseif not result.type then
							log('丢弃节点：' .. result.remarks .. " ，找不到可使用二进制。")
						elseif not result.address or result.remarks == "NULL" or result.address == "127.0.0.1" or
								(not datatypes.hostname(result.address) and not (api.is_ip(result.address))) then
							log('丢弃过滤节点：' .. result.type .. ' 节点，' .. result.remarks)
						else
							tinsert(node_list, result)
						end
					end
				end, function (err)
					--log(err)
					log(v, "解析错误，跳过此节点。")
				end
			)
			end
		end
		if #node_list > 0 then
			nodeResult[#nodeResult + 1] = {
				remark = group,
				list = node_list,
			}
		end
		log('成功解析【' .. group .. '】节点数量：' .. #node_list)
	else
		if add_mode == "2" then
			log('获取到的【' .. group .. '】订阅内容为空，可能是订阅地址无效，或是网络问题，请诊断！')
		end
	end
end

local function check_instance(action)
	local sub_lock = "/var/lock/" .. appname .. "_subscribe.lock"
	local rule_lock = "/var/lock/" .. appname .. "_rule_update.lock"

	if action == "start" then
		math.randomseed(os.time() + math.floor(os.clock() * 1000))
		api.nixio.nanosleep(0, math.random(100, 1000) * 1000000)
		if fs.access(sub_lock) then
			log("有[订阅]实例正在运行，请稍后再试...\n")
			os.exit(0)
		else
			luci.sys.call("touch " .. sub_lock)
			uci:revert(appname)
		end
	elseif action == "end" then
		luci.sys.call("rm -f " .. sub_lock)
		return
	end

	if fs.access(rule_lock) then
		log("[规则更新]实例正在运行，导入节点进入队列等待...\n")
	end
	while fs.access(rule_lock) do
		api.nixio.nanosleep(2, 0)
	end
end

if arg[1] == "add" then
	check_instance("start")
	local f = assert(io.open("/tmp/links.conf", 'r'))
	local raw = f:read('*all')
	f:close()
	parse_link(raw, "1", arg[2])
	update_node(1)
	luci.sys.call("rm -f /tmp/links.conf")
	check_instance("end")
end
