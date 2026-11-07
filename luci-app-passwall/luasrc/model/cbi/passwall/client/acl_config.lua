local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname)
m.redirect = api.url("acl")
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

local fs = api.fs
local sys = api.sys
local has_gfwlist = fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = fs.access("/usr/share/passwall/rules/chnroute")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

local nodes_table = {}
for _, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local normal_list = {}
for _, v in pairs(nodes_table) do
	if v.node_type == "normal" then
		normal_list[#normal_list + 1] = v
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port")),
			group = "Socks"
		}
	end
end)

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
end

-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))
s.addremove = false
s.dynamic = false

-- 旧配置没有 acl_mode 字段，这里按底层字段反推后写进内存态，
-- 让 depends 在首次渲染时就能正确求值（GET 请求不会落盘，保存时才写入）。
local valid_mode = function(v)
	return v == "direct" or v == "custom"
end

if not valid_mode(m:get(arg[1], "acl_mode")) then
	m:set(arg[1], "acl_mode", api.get_acl_mode(arg[1]))
end

---- Proxy Mode
-- direct = 完全直连（TCP/UDP 与 DNS 都不进入 PassWall 的处理链）
-- custom = 自定义节点（独立节点、独立 DNS、独立端口设置）
-- 注意：早期版本还有一档 proxy（跟随主设置），它和不加这条 ACL 完全等价
-- （nft 规则、节点、DNS 端口都一样），已移除。旧配置由 get_acl_mode() 归到 custom。
o = s:option(ListValue, "acl_mode", translate("Proxy Mode"))
o.default = "direct"
o.rmempty = false
o:value("direct", translate("Direct") .. " (" .. translate("Bypass PassWall completely") .. ")")
o:value("custom", translate("Custom Node"))
o.description = translate("Direct mode bypasses PassWall for both traffic and DNS.") .. "<br />" ..
	translate("Custom Node exposes the advanced per-ACL settings below.")
o.cfgvalue = function(self, section)
	local v = m:get(section, "acl_mode")
	if valid_mode(v) then
		return v
	end
	return api.get_acl_mode(section)
end
o.write = function(self, section, value)
	value = value or "direct"
	m:set(section, "acl_mode", value)

	-- 把模式语义下沉到下面这几个字段上（见 acl_mode_of 的用法）。
	-- 这里先兜底写一遍，保证即使某个字段被 depends 隐藏、没有参与提交，
	-- 底层字段也不会残留上一种模式的值。
	-- custom 分支不动 use_global_config：老配置里它可能是 1（表示复用全局节点），
	-- 保留下来行为不变，用户在页面上能看到这个勾选。
	if value == "direct" then
		m:set(section, "use_global_config", "0")
		m:set(section, "tcp_no_redir_ports", "1:65535")
		m:set(section, "udp_no_redir_ports", "1:65535")
	end
end

-- 读取当前表单里的模式（还没保存时也能拿到正确值）
local acl_mode_of = function(section)
	local f = s.fields["acl_mode"]
	local v = f and f:formvalue(section)
	if valid_mode(v) then
		return v
	end
	return api.get_acl_mode(section)
end

-- direct 模式下端口字段一律固定为「全部不代理」；
-- 这样即使 LuCI 仍然把这个被隐藏的字段写回，也不会破坏模式语义。
local mode_bound_port_write = function(self, section, value)
	local mode = acl_mode_of(section)
	if mode == "direct" then
		value = "1:65535"
	end
	return Value.write(self, section, value)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = false

o = s:option(Value, "interface", translate("Source Interface"))
o:value("", translate("All"))
local iface = api.get_network_devices()
for _, d in ipairs(iface) do
	o:value(d.name, d.label)
end
o.validate = function(self, value, section)
	if value == "" or value:match("^[a-zA-Z0-9][a-zA-Z0-9%.%_%-]*$") then
		return value
	end
	return nil, translate("Invalid interface name")
end

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[#mac_t + 1] = {
		ip = t,
		mac = e
	}
end)
table.sort(mac_t, function(a,b)
	if #a.ip < #b.ip then
		return true
	elseif #a.ip == #b.ip then
		if a.ip < b.ip then
			return true
		else
			return #a.ip < #b.ip
		end
	end
	return false
end)

---- Source
sources = s:option(DynamicList, "sources", translate("Source"))
sources.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("MAC") .. ": 00:00:00:FF:FF:FF"
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("IP range") .. ": 192.168.1.100-192.168.1.200"
.. "</li><li>" .. translate("IPSet") .. ": ipset:lanlist"
.. "</li></ul>"
sources.cast = "string"
for _, key in pairs(mac_t) do
	sources:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end
sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
sources.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if v:find("ipset:") and v:find("ipset:") == 1 then
			local ipset = v:gsub("ipset:", "")
			if ipset and ipset ~= "" then
				flag = true
			end
		end

		if flag == false and datatypes.macaddr(v) then
			flag = true
		end

		if flag == false and datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and api.iprange(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end
sources.write = dynamicList_write

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate
o:depends({ acl_mode = "custom" })
o.write = mode_bound_port_write

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
	"<font color='red'>" .. 
		translate("Fill in the ports you don't want to be forwarded by the agent, with the highest priority.") ..
	"</font>")
o:value("", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate
o:depends({ acl_mode = "custom" })
o.write = mode_bound_port_write

o = s:option(DummyValue, "_hide_node_option", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ tcp_no_redir_ports = "1:65535", udp_no_redir_ports = "1:65535" })
if TCP_NO_REDIR_PORTS == "1:65535" and UDP_NO_REDIR_PORTS == "1:65535" then
	o:depends({ tcp_no_redir_ports = "", udp_no_redir_ports = "" })
end
-- 直连模式下端口字段被固定成 1:65535，上面两组自然会命中，节点选择器随之隐藏。

o = s:option(Flag, "use_global_config", translatef("Use global config"))
o.default = "0"
o.rmempty = false
-- 只在「自定义节点」档、且节点选择器可见时才显示。
-- 这里必须用正向条件（和下面 tcp_node 一致的写法），不能用原来的
-- { _hide_node_option = "1", ['!reverse'] = true }：['!reverse'] 是整组取反，
-- 一旦往组里加 acl_mode 条件，条件本身也会被取反，字段反而会在直连模式下冒出来。
o:depends({ acl_mode = "custom", _hide_node_option = false })
o.write = function(self, section, value)
	-- 直连模式下这个字段不可见，强制写成 0，避免残留上一次的勾选
	if acl_mode_of(section) == "direct" then
		value = "0"
	end
	return Flag.write(self, section, value)
end

o = s:option(ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
o.default = ""
o:depends({ acl_mode = "custom", _hide_node_option = false, use_global_config = false })
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {}
o.remove = function(self, section)
	m:del(section, self.option)
	m:del(section, "udp_node")
end

o = s:option(DummyValue, "_tcp_node_bool", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ acl_mode = "custom", tcp_node = "",  ['!reverse'] = true })

o = s:option(ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
o.default = ""
o:value("", translate("Close"))
o:value("tcp", translate("Same as the tcp node"))
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {"",""}
o = s:option(DummyValue, "_udp_node_bool", "")
o.template = "passwall/cbi/hidevalue"
o.value = "1"
o:depends({ acl_mode = "custom", udp_node = "",  ['!reverse'] = true })

---- TCP Proxy Drop Ports
local TCP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "tcp_proxy_drop_ports")
o = s:option(Value, "tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o.validate = port_validate
o:depends({ acl_mode = "custom", use_global_config = true })
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

---- UDP Proxy Drop Ports
local UDP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "udp_proxy_drop_ports")
o = s:option(Value, "udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. UDP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("443", translate("QUIC"))
o.validate = port_validate
o:depends({ acl_mode = "custom", use_global_config = true })
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

---- TCP Redir Ports
local TCP_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_redir_ports")
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"), translatef("Only work with using the %s node.", "TCP"))
o:value("", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))
o.validate = port_validate
o:depends({ acl_mode = "custom", use_global_config = true })
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

---- UDP Redir Ports
local UDP_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_redir_ports")
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"), translatef("Only work with using the %s node.", "UDP"))
o:value("", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("53", "53")
o.validate = port_validate
o:depends({ acl_mode = "custom", use_global_config = true })
o:depends({ acl_mode = "custom", _udp_node_bool = "1" })

o = s:option(DummyValue, "tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>',
	translate("The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000."))
end
o:depends({ acl_mode = "custom", use_global_config = true })
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

o = s:option(Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

o = s:option(Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

o = s:option(Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

if has_gfwlist then
	o = s:option(Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
	o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })
end

if has_chnlist or has_chnroute then
	o = s:option(ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
	o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })
end

o = s:option(ListValue, "tcp_proxy_mode", "TCP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

o = s:option(ListValue, "udp_proxy_mode", "UDP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ acl_mode = "custom", _udp_node_bool = "1" })

o = s:option(DummyValue, "switch_mode", " ")
o.template = appname .. "/global/proxy"
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

-- Node → DNS Depends Settings
---- DNS
o = s:option(ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o.default = "chinadns-ng"
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", translate("ChinaDNS-NG (recommended)"))
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

o = s:option(DummyValue, "view_chinadns_log", " ")
o.template = appname .. "/acl/view_chinadns_log"
o:depends({ acl_mode = "custom" })

o = s:option(Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })

---- DNS Forward Mode
o = s:option(ListValue, "dns_mode", translate("Filter Mode"))
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end
o:depends({ acl_mode = "custom", _tcp_node_bool = "1" })
o.remove = function(self, section)
	local f = s.fields["tcp_node"]
	local id_val = f and f:formvalue(section) or ""
	if id_val == "" then
		return m:del(section, self.option)
	end
end

---- DNS Forward
o = s:option(Value, "remote_dns", translate("Remote DNS"))
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({ acl_mode = "custom", dns_mode = "dns2socks"})

o = s:option(ListValue, "chinadns_ng_default_tag", translate("Default DNS"))
o.default = "none"
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o:value("none", translate("Smart, Do not accept no-ip reply from Direct DNS"))
o:value("none_noip", translate("Smart, Accept no-ip reply from Direct DNS"))
local desc = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
o.description = desc
		.. "<li>" .. translate("Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.") .. "</li>"
		.. "<li>" .. translate("In smart mode, no-ip reply from Direct DNS:") .. "</li>"
		.. "<li>" .. translate("Do not accept: Wait and use Remote DNS Reply.") .. "</li>"
		.. "<li>" .. translate("Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.") .. "</li>"
		.. "</ul>"
o:depends({ acl_mode = "custom", dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:option(Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force queries with qtype 65 to respond with an SOA record."))
o.default = "0"
o.rmempty = false
o:depends({ acl_mode = "custom", dns_shunt = "chinadns-ng"})

o = s:option(ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({ acl_mode = "custom", dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

local tcp = s.fields["tcp_node"]
local udp = s.fields["udp_node"]
for k, v in pairs(socks_list) do
	tcp:value(v.id, v["remark"])
	tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	udp:value(v.id, v["remark"])
	udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end
for k, v in pairs(nodes_table) do
	if #normal_list == 0 then
		s.fields["dns_mode"]:depends({ acl_mode = "custom", _tcp_node_bool = "1" })
		break
	end
	tcp:value(v.id, v["remark"])
	tcp.group[#tcp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	udp:value(v.id, v["remark"])
	udp.group[#udp.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end

return m
