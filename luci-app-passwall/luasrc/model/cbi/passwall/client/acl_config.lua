local api = require "luci.passwall.api"
api.set_default_cbi()

m = Map()
m.redirect = api.url("acl")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:appendTemplate("/cbi/nodes_listvalue_com")


local has_gfwlist = api.fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = api.fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = api.fs.access("/usr/share/passwall/rules/chnroute")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

local nodes_table = {}
for _, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))

s:tab("Main", translate("Main"))
s:tab("Proxy", translate("Proxy"))
s:tab("DNS", translate("DNS"))
s:tab("Log", translate("Log"))

---- Enable
o = s:taboption("Main", Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:taboption("Main", Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = false

o = s:taboption("Main", Value, "interface", translate("Source Interface"))
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
api.sys.net.mac_hints(function(e, t)
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
sources = s:taboption("Main", DynamicList, "sources", translate("Source"))
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
		if flag == false and api.datatypes.macaddr(v) then
			flag = true
		end
		if flag == false and api.datatypes.ip4addr(v) then
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

local NODE = m:get("@global[0]", "node") or ""
o = s:taboption("Main", ListValue, "mode", translate("Mode"))
o:value("0", translate("No Proxy"))
o:value("1", translate("Proxy"))

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_no_redir_ports")
o = s:taboption("Proxy", Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o:depends("mode", "1")
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_no_redir_ports")
o = s:taboption("Proxy", Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
	"<font color='red'>" ..
		translate("Fill in the ports you don't want to be forwarded by the agent, with the highest priority.") ..
	"</font>")
o:value("", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o:depends("mode", "1")
o.validate = port_validate

o = s:taboption("Main", HideValue, "_hide_node_option", "")
o:depends("mode", "0")
o:depends({ tcp_no_redir_ports = "1:65535", udp_no_redir_ports = "1:65535" })
if TCP_NO_REDIR_PORTS == "1:65535" and UDP_NO_REDIR_PORTS == "1:65535" then
	o:depends({ tcp_no_redir_ports = "", udp_no_redir_ports = "" })
end

o = s:taboption("Main", Flag, "use_global_config", translatef("Use global config"))
o.default = "0"
o.rmempty = false
o:depends({ _hide_node_option = "1", ['!reverse'] = true })

o = s:taboption("Main", ListValue, "node", "<a style='color: red'>" .. translate("Proxy Node") .. "</a>")
o.group = {}
o:depends({ _hide_node_option = false, use_global_config = false })
o.template = m:template_path("/cbi/nodes_listvalue")
o.description = translate("Use global configuration when using the global node.")

current_node_id = m:get(arg[1], "node")
local node_value = s.fields["node"]:formvalue(s.section)
if node_value then
	current_node_id = node_value
end
current_node = current_node_id and m:get(current_node_id) or {}

o = s:taboption("Main", HideValue, "_acl_node_bool", "")
o:depends({ node = "", ['!reverse'] = true })

o = s:taboption("Main", HideValue, "_diff_global_node", "")
if NODE ~= "" then
	o:depends({ node = NODE, ['!reverse'] = true })
else
	o:depends({ _acl_node_bool = "1" })
end

---- TCP Proxy Drop Ports
local TCP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "tcp_proxy_drop_ports")
o = s:taboption("Proxy", Value, "tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _acl_node_bool = "1" })

---- UDP Proxy Drop Ports
local UDP_PROXY_DROP_PORTS = m:get("@global_forwarding[0]", "udp_proxy_drop_ports")
o = s:taboption("Proxy", Value, "udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"))
o:value("", translate("Use global config") .. "(" .. UDP_PROXY_DROP_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("443", translate("QUIC"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _acl_node_bool = "1" })

---- TCP Redir Ports
local TCP_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_redir_ports")
o = s:taboption("Proxy", Value, "tcp_redir_ports", translate("TCP Redir Ports"), translatef("Only work with using the %s node.", "TCP"))
o:value("", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _acl_node_bool = "1" })

---- UDP Redir Ports
local UDP_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_redir_ports")
o = s:taboption("Proxy", Value, "udp_redir_ports", translate("UDP Redir Ports"), translatef("Only work with using the %s node.", "UDP"))
o:value("", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("53", "53")
o.validate = port_validate
o:depends({ use_global_config = true })
o:depends({ _acl_node_bool = "1" })

o = s:taboption("Proxy", DummyValue, "tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>',
	translate("The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000."))
end
o:depends({ use_global_config = true })
o:depends({ _acl_node_bool = "1" })

o = s:taboption("Proxy", Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

o = s:taboption("Proxy", Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

o = s:taboption("Proxy", Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

if has_gfwlist then
	o = s:taboption("Proxy", Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
	o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })
end

if has_chnlist or has_chnroute then
	o = s:taboption("Proxy", ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
	o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })
end

o = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

o = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

o = s:taboption("Proxy", DummyValue, "switch_mode", "")
o.template = m:template_path("/global/proxy")
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

-- Node → DNS Depends Settings

---- DNS
o = s:taboption("DNS", ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o.default = "chinadns-ng"
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", translate("ChinaDNS-NG (recommended)"))
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })
o.write = function(self, section, value)
	local old = m:get(section, self.option)
	if old and old ~= value then
		m:set("@global[0]", "flush_set", "1")
	end
	return ListValue.write(self, section, value)
end

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

---- DNS Forward Mode
o = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end


o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })
o.write = function(self, section, value)
	if value == "dns2socks" then
		m:del(section, "v2ray_dns_mode")
	end
	return ListValue.write(self, section, value)
end

o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport(1))"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})

o = s:taboption("DNS", ListValue, "chinadns_ng_default_tag", translate("Default DNS"))
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
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:taboption("DNS", Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force queries with qtype 65 to respond with an SOA record."))
o.default = "0"
o.rmempty = false
o:depends({dns_shunt = "chinadns-ng"})

o = s:taboption("DNS", ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

---- Log
o = s:taboption("Log", Flag, "log", translate("Enable Node Log"))
o.default = 0
o.rmempty = false
o:depends({ _acl_node_bool = "1", _diff_global_node = "1" })

o = s:taboption("Log", ListValue, "loglevel", translate("Log Level"))
o.default = "warn"
o:value("debug", "Debug")
o:value("info", "Info")
o:value("warn", "Warning")
o:value("error", "Error")
o:depends("log", "1")

o = s:taboption("Log", DummyValue, "_node_log", translate("Log File"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local log_file = api.TMP_PATH .. "/acl/" .. arg[1] .. "/node.log"
	local log_url = api.url("get_redir_log") .. "?id=" .. arg[1]
	local s = "<code>%s</code>&nbsp;&nbsp;" % log_file
	if api.fs.access(log_file) then
		local btn = string.format(
			'<input class="btn cbi-button cbi-button-apply" type="button" value="%s" onclick="window.open(\'%s\', \'_blank\')" />',
			translate("View Log"),
			log_url
		)
		s = s .. btn
	end
	return s
end
o:depends("log", "1")

o = s:taboption("Log", Flag, "log_chinadns_ng", translate("Enable") .. " ChinaDNS-NG " .. translate("Log"))
o.default = "0"
o.rmempty = false
o:depends("dns_shunt", "chinadns-ng")

o = s:taboption("Log", DummyValue, "_chinadns_ng_log", translate("Log File"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local log_file = api.TMP_PATH .. "/acl/" .. arg[1] .. "/chinadns_ng.log"
	local log_url = api.url("get_chinadns_log") .. "?flag=" .. arg[1]
	local s = "<code>%s</code>&nbsp;&nbsp;" % log_file
	if api.fs.access(log_file) then
		local btn = string.format(
			'<input class="btn cbi-button cbi-button-apply" type="button" value="%s" onclick="window.open(\'%s\', \'_blank\')" />',
			translate("View Log"),
			log_url
		)
		s = s .. btn
	end
	return s
end
o:depends("log_chinadns_ng", "1")

local o_node = s.fields["node"]
for _, v in ipairs(nodes_table) do
	o_node:value(v.id, v.remark)
	o_node.group[#o_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end

return api.return_map(m)
