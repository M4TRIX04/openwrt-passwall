if not api.finded_com("hysteria") then return end
local m, s1 = ...
local type_name = "Hysteria"
s1.fields["type"]:value(type_name, "Hysteria 1.3.5")
if s1.val["type"] and s1.val["type"] ~= type_name then return end
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
o:value("faketcp", "Fake TCP (Linux root, iptables TTL/HL required)")
o:value("wechat-video", "WeChat Video (UDP)")
o.default = "udp"
o.rmempty = false
value("port", "Port", "port", true)
o = s:option(ListValue, "auth_type", translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", "STRING")
o.default = "string"
o.rmempty = false
o.rewrite_option = o.option
value("auth_password", "Auth Password", nil, false, true)
o.password = true
o:depends({auth_type="string"})
value("obfs", "Obfs Password", nil, false, true)
o.password = true
value("alpn", "QUIC TLS ALPN", nil, false, true)
value("up_mbps", "Max upload Mbps", "range(0,1000000)", false, true)
value("down_mbps", "Max download Mbps", "range(0,1000000)", false, true)
value("recv_window_conn", "QUIC stream receive window (bytes)", "range(65536,4294967295)", false, true)
value("recv_window", "QUIC connection receive window (bytes)", "range(65536,4294967295)", false, true)
flag("disable_mtu_discovery", "Disable MTU detection", "0", true)
value("tls_certificateFile", "Certificate path", "file", true)
value("tls_keyFile", "Private key path", "file", true)
flag("udp", "UDP forwarding", "1", true)
flag("firewall_allow", "Firewall Allow")
value("firewall_allow_src", "Source zone", nil, false)
o.default = "wan"
o.template = "cbi/firewall_zonelist"
o.nocreate = true
o.allowany = true
o:depends({firewall_allow=true})
flag("log", "Log", "1")
o.rmempty = false
api.type_cbi_section(s1, s)
