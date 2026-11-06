local api = require "luci.passwall.api"
local appname = "passwall"
local sys = api.sys

m = Map(appname)
api.set_apply_on_parse(m)

s = m:section(TypedSection, "global", translate("ACLs"),
	"<font color='red'>" ..
	translate("ACLs are exceptions to the global settings. Clients without an ACL are proxied normally.") ..
	"<br />" .. translate("Direct") .. " - " .. translate("Bypass PassWall completely") .. " (" .. translate("including DNS") .. ")" ..
	"<br />" .. translate("Custom Node") .. " - " .. translate("Use a dedicated node and DNS") ..
	"</font>")
s.anonymous = true

o = s:option(Flag, "acl_enable", translate("Main switch"))
o.rmempty = false
o.default = false

-- [[ ACLs Settings ]]--
s = m:section(TypedSection, "acl_rule")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true
s.extedit = api.url("acl_config", "%s")
function s.create(e, t)
	t = TypedSection.create(e, t)
	-- 新建的 ACL 默认是「直连」—— ACL 的语义就是例外清单，默认全部代理。
	-- 但此时还没有配置源，而底层的「空源」等于「所有设备」，
	-- 所以先禁用，等用户填好源并勾上 Enable 后再生效，避免一建就误伤全网。
	m:set(t, "acl_mode", "direct")
	m:set(t, "enabled", "0")
	luci.http.redirect(e.extedit:format(t))
end
function s.remove(e, t)
	sys.call("rm -rf /tmp/etc/passwall_tmp/dns_" .. t .. "*")
	TypedSection.remove(e, t)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.rmempty = true

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[e] = {
		ip = t,
		mac = e
	}
end)

o = s:option(DummyValue, "sources", translate("Source"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local e = ''
	local v = Value.cfgvalue(t, n) or '-'
	string.gsub(v, '[^' .. " " .. ']+', function(w)
		local a = w
		if mac_t[w] then
			a = a .. ' (' .. mac_t[w].ip .. ')'
		end
		if #e > 0 then
			e = e .. "<br />"
		end
		e = e .. a
	end)
	return e
end

o = s:option(DummyValue, "acl_mode", translate("Proxy Mode"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local mode = api.get_acl_mode(n)
	if mode == "direct" then
		return "<span style='color:gray'>" .. translate("Direct") .. "</span>"
	end
	return translate("Custom Node")
end

o = s:option(DummyValue, "interface", translate("Source Interface"))
o.cfgvalue = function(t, n)
	local v = Value.cfgvalue(t, n) or '-'
	return v
end

--[[
---- TCP No Redir Ports
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))

---- UDP No Redir Ports
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))

---- TCP Redir Ports
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"))
o.default = "default"
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))

---- UDP Redir Ports
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"))
o.default = "default"
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))
o:value("53", "53")
]]--

return m
