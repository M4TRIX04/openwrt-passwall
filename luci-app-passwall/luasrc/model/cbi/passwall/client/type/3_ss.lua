if not api.is_finded("ss-local") and not api.is_finded("ss-redir") then
	return
end

-- [[ Shadowsocks Libev ]]
local m, s1 = ...
local type_name = "SS"

s1.fields["type"]:value(type_name, "Shadowsocks Libev")

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "ss_"
api.set_type_cbi(s)

local ss_encrypt_method_list = {
	"rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
	"aes-192-ctr", "aes-256-ctr", "bf-cfb", "salsa20", "chacha20", "chacha20-ietf",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305"
}

o = s:option(ListValue, "del_protocol")
o:depends({ __hide = "1" })
o.rewrite_option = "protocol"

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "password", translate("Password"))
o.password = true

o = s:option(ListValue, "method", translate("Encrypt Method"))
for _, t in ipairs(ss_encrypt_method_list) do o:value(t) end

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

o = s:option(Flag, "plugin_enabled", translate("plugin"))
o.default = 0

o = s:option(Value, "plugin", "SIP003 " .. translate("plugin"), translate("Supports custom SIP003 plugins, Make sure the plugin is installed."))
o.default = "none"
o:value("none", translate("none"))
if api.is_finded("xray-plugin") then o:value("xray-plugin") end
if api.is_finded("v2ray-plugin") then o:value("v2ray-plugin") end
if api.is_finded("obfs-local") then o:value("obfs-local") end
o:depends({ plugin_enabled = true })
o.validate = function(self, value)
	if value and value ~= "" and value ~= "none" then
		if not api.is_finded(value) then
			return nil, value .. ": " .. translate("Can't find this file!")
		end
		return value
	end
	return nil
end

o = s:option(Value, "plugin_opts", translate("opts"))
o:depends({ plugin_enabled = true })

api.type_cbi_section(s1, s)
