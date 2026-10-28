api = require "luci.passwall.api"
datatypes = api.datatypes
local fs = api.fs


local has_smartdns = api.is_finded("smartdns")
local has_gfwlist = fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = fs.access("/usr/share/passwall/rules/chnroute")

api.set_default_cbi()

m = Map()

m:appendTemplate("/cbi/nodes_listvalue_com")

local nodes_table = {}
for _, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

m:appendTemplate("/global/status")

s = m:section(NamedSection, "@global[0]", "global")

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- TCP Node
o = s:taboption("Main", ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
o.template = m:template_path("/cbi/nodes_listvalue")
o:value("", translate("Close"))
o.group = {""}
-- The merged selector this section may still carry is removed on the first
-- save. The runtime reads it before the canonical pair, so leaving it behind
-- would keep overriding whatever the user selects here.
o.write = function(self, section, value)
	m:del(section, "node")
	return ListValue.write(self, section, value)
end

---- UDP Node
o = s:taboption("Main", ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
o.template = m:template_path("/cbi/nodes_listvalue")
o:value("", translate("Close"))
o:value("tcp", translate("Same as the tcp node"))
o.group = {"", ""}

-- Read-only compatibility. A section that still carries the merged `node`
-- selector proxied both protocols with that one node, so it is shown as
-- TCP=<node> with UDP following TCP. Nothing is written by this block: the
-- values become canonical only when the page is saved, and the merged option is
-- removed at that point.
local legacy_node = m:get(s.section, "node") or ""
local o_tcp_field = s.fields["tcp_node"]
o_tcp_field.cfgvalue = function(self, section)
	local v = self.map:get(section, self.option)
	if (v == nil or v == "") and legacy_node ~= "" then
		return legacy_node
	end
	return v
end
local o_udp_field = s.fields["udp_node"]
o_udp_field.cfgvalue = function(self, section)
	local v = self.map:get(section, self.option)
	if v == nil and legacy_node ~= "" then
		return "tcp"
	end
	return v
end

current_node_id = m:get(s.section, "tcp_node")
if current_node_id == nil or current_node_id == "" then
	current_node_id = legacy_node
end
local node_value = s.fields["tcp_node"]:formvalue(s.section)
if node_value then
	current_node_id = node_value
end
current_node = current_node_id and m:get(current_node_id) or {}

o = s:taboption("Main", Value, "node_socks_port", translate("Node") .. " Socks " .. translate("Listen Port"))
o.default = 1070
o.placeholder = 1070
o.datatype = "range(1,65535)"
o:depends({ tcp_node = "", ['!reverse'] = true })

o = s:taboption("Main", Flag, "node_socks_bind_local", translate("Node") .. " Socks " .. translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "1"
o:depends({ tcp_node = "", ['!reverse'] = true })

-- [[ DNS Settings ]]--
s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", translate("ChinaDNS-NG (recommended)"))
o.write = function(self, section, value)
	local old = m:get(section, self.option)
	if old and old ~= value then
		m:set(section, "flush_set", "1")
	end
	return ListValue.write(self, section, value)
end
if has_smartdns then
	o:value("smartdns", "SmartDNS")
end

o = s:taboption("DNS", ListValue, "direct_dns_mode", translate("Direct DNS") .. " " .. translate("Request protocol"))
o:value("", translate("Auto"))
o:value("udp", translatef("Requery DNS By %s", "UDP"))
o:value("tcp", translatef("Requery DNS By %s", "TCP"))
o:depends({dns_shunt = "dnsmasq"})
o:depends({dns_shunt = "chinadns-ng"})

o = s:taboption("DNS", Value, "direct_dns", translate("Direct DNS"))
o.datatype = "or(ipaddr,ipaddrport(1))"
o.default = "223.5.5.5"
o:value("223.5.5.5")
o:value("223.6.6.6")
o:value("180.184.1.1")
o:value("180.184.2.2")
o:value("114.114.114.114")
o:value("114.114.115.115")
o:value("119.28.28.28")
o:depends({dns_shunt = "dnsmasq", direct_dns_mode = "udp"})
o:depends({dns_shunt = "dnsmasq", direct_dns_mode = "tcp"})
o:depends({dns_shunt = "chinadns-ng", direct_dns_mode = "udp"})
o:depends({dns_shunt = "chinadns-ng", direct_dns_mode = "tcp"})

if has_smartdns then
	o = s:taboption("DNS", DynamicList, "smartdns_direct_dns", translate("Direct DNS"))
	o.placeholder = translate("Auto")
	o.rmempty = true
	o:value("223.5.5.5")
	o:value("119.29.29.29")
	o:value("tcp://223.5.5.5")
	o:value("tcp://114.114.114.114")
	o:value("tls://dot.pub,1.12.12.12")
	o:value("tls://dns.alidns.com,223.5.5.5")
	o:value("https://223.5.5.5/dns-query")
	o:value("https://1.12.12.12/dns-query")
	o:depends({dns_shunt = "smartdns"})
end

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"))
o.default = "0"

-- 分流时dns过滤模式保存逻辑

---- DNS Forward Mode
o = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
o.default = "tcp"
o:value("udp", translatef("Requery DNS By %s", "UDP"))
o:value("tcp", translatef("Requery DNS By %s", "TCP"))
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end


o:depends({ dns_shunt = "chinadns-ng", })
o:depends({ dns_shunt = "dnsmasq", })
o.write = function(self, section, value)
	m:del(section, "socks_server")
	return ListValue.write(self, section, value)
end


---- SmartDNS Forward Mode
if has_smartdns then
	o = s:taboption("DNS", ListValue, "smartdns_dns_mode", translate("Filter Mode"))
	o:value("socks", "Socks")


	o:depends({ dns_shunt = "smartdns", })
	o.write = function(self, section, value)
		if value == "socks" then
			m:del(section, "v2ray_dns_mode")
		end
		return ListValue.write(self, section, value)
	end


	o = s:taboption("DNS", DynamicList, "smartdns_remote_dns", translate("Remote DNS"))
	o:value("tcp://1.1.1.1")
	o:value("tcp://8.8.4.4")
	o:value("tcp://8.8.8.8")
	o:value("tcp://9.9.9.9")
	o:value("tcp://208.67.222.222")
	o:value("tls://1.1.1.1")
	o:value("tls://8.8.4.4")
	o:value("tls://8.8.8.8")
	o:value("tls://9.9.9.9")
	o:value("tls://208.67.222.222")
	o:value("https://1.1.1.1/dns-query")
	o:value("https://8.8.4.4/dns-query")
	o:value("https://8.8.8.8/dns-query")
	o:value("https://9.9.9.9/dns-query")
	o:value("https://208.67.222.222/dns-query")
	o:value("https://dns.adguard.com/dns-query,94.140.14.14")
	o:value("https://doh.libredns.gr/dns-query,116.202.176.26")
	o:value("https://doh.libredns.gr/ads,116.202.176.26")
	o:depends({ dns_shunt = "smartdns", smartdns_dns_mode = "socks" })
	o.cfgvalue = function(self, section)
		return m:get(section, self.option) or {"tcp://1.1.1.1"}
	end
end

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport(1))"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9)")
o:value("149.112.112.112", "149.112.112.112 (Quad9)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({dns_mode = "tcp"})
o:depends({dns_mode = "udp"})

---- DoH

o = s:taboption("DNS", Value, "remote_dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
		translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"

o:depends("dns_shunt", "smartdns")

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

o = s:taboption("DNS", ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = desc .. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

if has_smartdns then
	o = s:taboption("DNS", ListValue, "smartdns_default_dns", translate("Default DNS"))
	o.default = "direct"
	o:value("remote", translate("Remote DNS"))
	o:value("direct", translate("Direct DNS"))
	o:value("auto", translate("Auto"))
	o.description = desc
		.. "<li>" .. translate("Auto: Prefer mainland China IPs returned by direct DNS and fall back to remote DNS when no usable result is available.") .. "</li>"
		.. "</ul>"
	o:depends({dns_shunt = "smartdns", tcp_proxy_mode = "proxy", chn_list = "direct"})
end

o = s:taboption("DNS", Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force queries with qtype 65 to respond with an SOA record."))
o.default = "0"
o:depends({dns_shunt = "chinadns-ng"})
if has_smartdns then
	o:depends({dns_shunt = "smartdns"})
end

o = s:taboption("DNS", Flag, "dns_redirect", translate("DNS Redirect"), translate("Force special DNS server to need proxy devices."))
o.default = "1"
o.rmempty = false

local prefer_nft = m:get("@global_forwarding[0]", "prefer_nft") == "1"
local set_title = api.i18n.translate(prefer_nft and "Clear NFTSET on Reboot" or "Clear IPSET on Reboot")
o = s:taboption("DNS", Flag, "flush_set_on_reboot", set_title, translate("Clear IPSET/NFTSET on service reboot. This may increase reboot time."))
o.default = "0"

set_title = api.i18n.translate(prefer_nft and "Clear NFTSET" or "Clear IPSET")
o = s:taboption("DNS", DummyValue, "clear_ipset", set_title, translate("Try this feature if the rule modification does not take effect."))
o.rawhtml = true
function o.cfgvalue(self, section)
	return string.format(
		[[<button type="button" class="cbi-button cbi-button-remove" onclick="location.href='%s'">%s</button>]],
		api.url("flush_set") .. "?redirect=1&reload=1", set_title)
end

s:tab("Proxy", translate("Mode"))

o = s:taboption("Proxy", Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"

o = s:taboption("Proxy", Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"

o = s:taboption("Proxy", Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"

if has_gfwlist then
	o = s:taboption("Proxy", Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
end

if has_chnlist or has_chnroute then
	o = s:taboption("Proxy", ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
end

---- TCP Default Proxy Mode
o = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("Default Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o.default = "proxy"

---- UDP Default Proxy Mode
o = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("Default Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o.default = "proxy"

o = s:taboption("Proxy", DummyValue, "switch_mode", "")
o.template = m:template_path("/global/proxy")

---- Check the transparent proxy component
local handle = io.popen("lsmod")
local mods = ""
if handle then
	mods = handle:read("*a") or ""
	handle:close()
end

if (mods:find("REDIRECT") and mods:find("TPROXY")) or (mods:find("nft_redir") and mods:find("nft_tproxy")) then
	o = s:taboption("Proxy", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
	o.default = "1"
	o.rmempty = false

	o = s:taboption("Proxy", Flag, "client_proxy", translate("Client Proxy"), translate("When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy."))
	o.default = "1"
	o.rmempty = false
else
	local html = string.format([[<div class="cbi-checkbox"><input class="cbi-input-checkbox" type="checkbox" disabled></div><div class="cbi-value-description"><font color="red">%s</font></div>]], translate("Missing components, transparent proxy is unavailable."))
	o = s:taboption("Proxy", DummyValue, "localhost_proxy", translate("Localhost Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end

	o = s:taboption("Proxy", DummyValue, "client_proxy", translate("Client Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end
end

o = s:taboption("Proxy", DummyValue, "_proxy_tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="%s">%s</a>', api.url("acl"), translate("Want different devices to use different proxy modes/ports/nodes? Please use access control."))
end

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "log_node", translate("Enable Node Log"))
o.default = "0"
o.rmempty = false

o = s:taboption("log", ListValue, "loglevel", translate("Log Level"))
o.default = "warn"
o:value("debug", "Debug")
o:value("info", "Info")
o:value("warn", "Warning")
o:value("error", "Error")

o = s:taboption("log", DummyValue, "_node_log", translate("Log File"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local log_file = api.TMP_PATH .. "/acl/default/global.log"
	local log_url = api.url("get_redir_log") .. "?id=default"
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
o:depends("log_node", "1")

o = s:taboption("log", Flag, "log_chinadns_ng", translate("Enable") .. " ChinaDNS-NG " .. translate("Log"))
o.default = "0"
o.rmempty = false
o:depends("dns_shunt", "chinadns-ng")

o = s:taboption("log", DummyValue, "_chinadns_ng_log", translate("Log File"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local log_file = api.TMP_PATH .. "/acl/default/chinadns_ng.log"
	local log_url = api.url("get_chinadns_log") .. "?flag=default"
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

if has_smartdns then
	o = s:taboption("log", Flag, "log_smartdns", translate("Enable") .. " SmartDNS " .. translate("Log"))
	o.default = "0"
	o.rmempty = false
	o:depends("dns_shunt", "smartdns")

	o = s:taboption("log", ListValue, "smartdns_log_level", "SmartDNS " .. translate("Log Level"))
	o.default = "error"
	o:value("fatal", "Fatal")
	o:value("error", "Error")
	o:value("warn", "Warning")
	o:value("notice", "Notice")
	o:value("info", "Info")
	o:value("debug", "Debug")
	o:depends("log_smartdns", "1")

	o = s:taboption("log", Value, "smartdns_log_size", translate("Log Size") .. " (MB)")
	o.default = "1"
	o.datatype = "and(uinteger,min(1))"
	o:depends("log_smartdns", "1")

	o = s:taboption("log", DummyValue, "_smartdns_log", translate("Log File"))
	o.rawhtml = true
	o.cfgvalue = function(t, n)
		local log_file = api.TMP_PATH .. "/acl/default/smartdns.log"
		local log_url = api.url("get_smartdns_log")
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
	o:depends("log_smartdns", "1")

	if api.fs.access("/usr/lib/smartdns_ui.so") or api.fs.access("/usr/lib/smartdns/smartdns_ui.so") then
		o = s:taboption("log", Flag, "smartdns_ui", "SmartDNS " .. translate("Enable WebUI"))
		o.default = "0"
		o.rmempty = false
		o:depends("dns_shunt", "smartdns")

		o = s:taboption("log", Value, "smartdns_ui_port", translate("WebUI Port"))
		o.default = "9880"
		o.datatype = "range(1,65535)"
		o:depends("smartdns_ui", "1")

		o = s:taboption("log", Value, "smartdns_ui_data_dir", translate("WebUI Database Directory"))
		o.default = api.CACHE_PATH .. "/smartdns"
		o.validate = function(self, value, section)
			value = api.trim(value)
			if value:sub(1, 1) ~= "/" or value:find("%s") then
				return nil, translate("An absolute path without spaces is required.")
			end
			return value
		end
		o:depends("smartdns_ui", "1")

		o = s:taboption("log", Value, "smartdns_ui_log_max_age", translate("WebUI Log Retention Days"))
		o.default = "7"
		o.datatype = "and(uinteger,min(1))"
		o:depends("smartdns_ui", "1")

		o = s:taboption("log", DummyValue, "_smartdns_ui_link", "WebUI")
		o.rawhtml = true
		o.cfgvalue = function(self, section)
			local port = tonumber(m:get(section, "smartdns_ui_port")) or 9880
			if port < 1 or port > 65535 or port % 1 ~= 0 then port = 9880 end
			return string.format(
				[[<input class="btn cbi-button cbi-button-apply" type="button" value="%s" onclick="var host = window.location.hostname; if (host.indexOf(':') !== -1 &amp;&amp; host.charAt(0) !== '[') host = '[' + host + ']'; window.open('http://' + host + ':%d', '_blank', 'noopener,noreferrer');" />]],
				translate("Open WebUI"), port
			)
		end
		o:depends("smartdns_ui", "1")
	end
end

o = s:taboption("log", DummyValue, "_log_tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>', translate("It is recommended to disable logging during regular use to reduce system overhead."))
end

s:tab("faq", "FAQ")
o = s:taboption("faq", DummyValue, "")
o.template = m:template_path("/global/faq")

s:tab("maintain", translate("Maintain"))
o = s:taboption("maintain", DummyValue, "")
o.template = m:template_path("/global/backup")


-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s2 = m:section(TypedSection, "socks", translate("Socks Config"))
s2.template = "cbi/tblsection"
s2.sortable = true
s2.anonymous = true
s2.addremove = true
s2.extedit = api.url("socks_config", "%s")
function s2.create(e, t)
	local uid = "socks_" .. api.gen_random_char(5)
	local n = 1
	m:foreach("socks", function(s)
		if s[".name"] == section then
			return false
		end
		n = n + 1
	end)
	TypedSection.create(e, uid)
	m:set(uid, "port", 1080 + n)
	m:set(uid, "http_port", 0)
	luci.http.redirect(e.extedit:format(uid))
end
function s2.remove(e, t)
	local new_node = ""
	local node0 = m:get("@nodes[0]") or nil
	if node0 then
		new_node = node0[".name"]
	end
	if (m:get("@global[0]", "tcp_node") or "") == t then
		m:set('@global[0]', "tcp_node", new_node)
	end
	-- Removing the node a UDP selector points at falls back to following TCP,
	-- which is the only remaining selector that cannot dangle.
	if (m:get("@global[0]", "udp_node") or "") == t then
		m:set('@global[0]', "udp_node", "tcp")
	end
	m:foreach("acl_rule", function(s)
		if s["node"] and s["node"] == t then
			m:set(s[".name"], "node", "default")
		end
	end)
	TypedSection.remove(e, t)
end

---- Enable
o = s2:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

o = s2:option(ListValue, "node", translate("Socks Node"))
o.template = m:template_path("/cbi/nodes_listvalue")
o.group = {}

o = s2:option(DummyValue, "now_node", translate("Current Node"))
o.rawhtml = true
o.cfgvalue = function(_, n)
	local current_node = api.get_cache_var(n)
	if current_node then
		local node = m:get(current_node)
		if node then
			return (api.get_node_remarks(node) or ""):gsub("(：)%[", "%1<br>[")
		end
	end
end

o = s2:option(DummyValue, "port_status", translate("Port Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local socks = m:get(n, "port") or "0"
	local http = m:get(n, "http_port") or "0"
	local node = m:get(n, "node")
	local core = node and m:get(node, "type")
	local http_status = (core == "Hysteria" or core == "SS-Rust") and ("<br><span class='_http'></span> HTTP: " .. http) or ""
	return string.format([[
	<div class="_socks_status" socks_id="%s">
		<span class="_socks"></span> SOCKS: %s
		%s
	</div>
	]], n, socks, http_status)
end

local o_tcp_node = s.fields["tcp_node"]
local o_udp_node = s.fields["udp_node"]
local o_socks = s2.fields["node"]
for _, v in ipairs(nodes_table) do
	o_tcp_node:value(v.id, v.remark)
	o_tcp_node.group[#o_tcp_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	o_udp_node:value(v.id, v.remark)
	o_udp_node.group[#o_udp_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	if v.type ~= "Socks" then
		o_socks:value(v.id, v.remark)
		o_socks.group[#o_socks.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	end
end

m:appendTemplate("/global/footer")

m:appendTemplate("/cbi/sortable", {sectiontype = s2.sectiontype})

return api.return_map(m)
