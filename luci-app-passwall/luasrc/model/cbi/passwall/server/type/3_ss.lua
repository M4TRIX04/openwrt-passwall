if not api.is_finded("ss-server") then
	return
end

-- [[ Shadowsocks Libev ]]
local m, s1 = ...
local type_name = "SS"

s1.fields["type"]:value(type_name, translate("Shadowsocks Libev"))

if not s1.val["type"] then
	s1.val["type"] = type_name
end

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "ss_"
api.set_type_cbi(s)

local ss_encrypt_method_list = {
	"rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
	"aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
	"camellia-192-cfb", "camellia-256-cfb", "salsa20", "chacha20",
	"chacha20-ietf", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
	"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"
}

o = s:option(Flag, "custom", translate("Use Custom Config"))

o = s:option(TextValue, "custom_config", translate("Custom Config") .. " (JSON)")
o.rows = 10
o.wrap = "off"
o:depends({ custom = true })
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	local v = o_validate(self, value)
	if v then return v end
	return nil, translate("Custom Config") .. " " .. translate("Must be JSON text!")
end
o.cfgvalue = function(self, section)
	local config_str = m:get(section, "config_str")
	if config_str then return api.base64Decode(config_str) end
end
o.write = function(self, section, value)
	m:set(section, "config_str", api.base64Encode(value) or "")
end

o = s:option(Value, "port", translate("Listen Port"))
o.datatype = "port"
o:depends({ custom = false })

o = s:option(Value, "password", translate("Password"))
o.password = true
o:depends({ custom = false })

o = s:option(ListValue, "method", translate("Encrypt Method"))
for _, t in ipairs(ss_encrypt_method_list) do o:value(t) end
o:depends({ custom = false })

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300
o:depends({ custom = false })

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Flag, "firewall_allow", translate("Firewall Allow"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Value, "firewall_allow_src", translate("Source zone"))
o.rmempty = not m.is_js_luci
o.nocreate = true
o.allowany = true
o.default = "wan"
o.template = "cbi/firewall_zonelist"
o:depends({ custom = false, firewall_allow = true })

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

api.type_cbi_section(s1, s)
