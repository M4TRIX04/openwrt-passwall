if not api.finded_com("hysteria") then return end
local m, s1 = ...
local type_name = "Hysteria"
s1.fields["type"]:value(type_name, "Hysteria 1.3.5")
if s1.val["type"] ~= type_name then return end
local s = NamedSection(m, arg[1], "tmp_" .. s1.sectiontype)
s.parent = s1
s.type_name = type_name
s.option_prefix = "hysteria_"
api.set_type_cbi(s)
local o
local function value(name, label, datatype, required, keep)
 o = s:option(Value, name, translate(label))
 o.datatype = datatype
 if required then o.rmempty = false end
 if keep then o.rewrite_option = o.option end
 return o
end
local function flag(name, label, default, keep)
 o = s:option(Flag, name, translate(label))
 o.default = default or "0"
 if keep then o.rewrite_option = o.option end
 return o
end
o = s:option(ListValue, "protocol", translate("Transport Protocol"))
o:value("udp", "UDP")
o:value("faketcp", "Fake TCP (Linux root)")
o:value("wechat-video", "WeChat Video (UDP)")
o.default = "udp"
o.rmempty = false
value("address", "Address", "host", true)
value("port", "Port", "port", true)
o = s:option(ListValue, "auth_type", translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", "STRING")
o:value("base64", "BASE64")
o.default = "string"
o.rmempty = false
o.rewrite_option = o.option
value("auth_password", "Auth Password", nil, false, true)
o.password = true
o:depends({auth_type="string"})
o:depends({auth_type="base64"})
value("obfs", "Obfs Password", nil, false, true)
o.password = true
value("alpn", "QUIC TLS ALPN", nil, false, true)
value("up_mbps", "Max upload Mbps", "range(1,1000000)", true, true)
o.default = "10"
value("down_mbps", "Max download Mbps", "range(1,1000000)", true, true)
o.default = "50"
value("recv_window_conn", "QUIC stream receive window (bytes)", "range(65536,4294967295)", false, true)
value("recv_window", "QUIC connection receive window (bytes)", "range(65536,4294967295)", false, true)
flag("disable_mtu_discovery", "Disable MTU detection", "0", true)
value("tls_serverName", "TLS Server Name")
flag("tls_allowInsecure", "Allow insecure TLS")
value("ca", "Custom CA path", "file", false, true)
value("handshake_timeout", "Handshake Timeout (seconds)", "range(2,3600)", false, true)
value("idle_timeout", "Idle Timeout (seconds)", "range(4,3600)", false, true)
flag("fast_open", "Fast Open")
flag("lazy_start", "Lazy Start", "0", true)
api.type_cbi_section(s1, s)
