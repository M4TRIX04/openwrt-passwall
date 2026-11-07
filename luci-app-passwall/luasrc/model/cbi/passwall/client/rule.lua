local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname)
api.set_apply_on_parse(m)

-- [[ Rule Settings ]]--
s = m:section(TypedSection, "global_rules", translate("Rule status"))
s.anonymous = true

--[[
o = s:option(Flag, "adblock", translate("Enable adblock"))
o.rmempty = false
]]--

---- gfwlist URL
o = s:option(DynamicList, "gfwlist_url", translate("GFW domains(gfwlist) Update URL"))
o:value("https://cdn.jsdelivr.net/gh/YW5vbnltb3Vz/domain-list-community@release/gfwlist.txt", translate("v2fly/domain-list-community"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt", translate("Loyalsoldier/v2ray-rules-dat"))
o:value("https://cdn.jsdelivr.net/gh/Loukky/gfwlist-by-loukky/gfwlist.txt", translate("Loukky/gfwlist-by-loukky"))
o:value("https://cdn.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt", translate("gfwlist/gfwlist"))
o.default = o.keylist[2]

----chnroute  URL
o = s:option(DynamicList, "chnroute_url", translate("China IPs(chnroute) Update URL"))
o:value("https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt", translate("gaoyifan/china-operator-ip/china"))
o:value("https://ispip.clang.cn/all_cn.txt", translate("Clang.CN"))
o:value("https://cdn.jsdelivr.net/gh/soffchen/GeoIP2-CN@release/CN-ip-cidr.txt", translate("soffchen/GeoIP2-CN"))
o:value("https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt", translate("Hackl0us/GeoIP2-CN"))
o:value("https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_IP_No_IPv6.txt", translate("ios_rule_script/ChinaMax_IP_No_IPv6"))

----chnroute6 URL
o = s:option(DynamicList, "chnroute6_url", translate("China IPv6s(chnroute6) Update URL"))
o:value("https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt", translate("gaoyifan/china-operator-ip/china6"))
o:value("https://ispip.clang.cn/all_cn_ipv6.txt", translate("Clang.CN.IPv6"))
o:value("https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_IP.txt", translate("ios_rule_script/ChinaMax_IP"))

----chnlist URL
o = s:option(DynamicList, "chnlist_url", translate("China List(Chnlist) Update URL"))
o:value("https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf", translate("felixonmars/domains.china"))
o:value("https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf", translate("felixonmars/apple.china"))
o:value("https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf", translate("felixonmars/google.china"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/china-list.txt", translate("Loyalsoldier/china-list"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/apple-cn.txt", translate("Loyalsoldier/apple-cn"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/google-cn.txt", translate("Loyalsoldier/google-cn"))
o:value("https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_Domain.txt", translate("ios_rule_script/ChinaMax_Domain"))

---- Auto Update
o = s:option(Flag, "auto_update", translate("Enable auto update rules"))
o.default = 0
o.rmempty = false

---- Week Update
o = s:option(ListValue, "week_update", translate("Update Mode"))
o:value(8, translate("Loop Mode"))
o:value(7, translate("Every day"))
o:value(1, translate("Every Monday"))
o:value(2, translate("Every Tuesday"))
o:value(3, translate("Every Wednesday"))
o:value(4, translate("Every Thursday"))
o:value(5, translate("Every Friday"))
o:value(6, translate("Every Saturday"))
o:value(0, translate("Every Sunday"))
o.default = 7
o:depends("auto_update", true)
o.rmempty = true

---- Time Update
o = s:option(ListValue, "time_update", translate("Update Time(every day)"))
for t = 0, 23 do o:value(t, t .. ":00") end
o.default = 0
o:depends("week_update", "0")
o:depends("week_update", "1")
o:depends("week_update", "2")
o:depends("week_update", "3")
o:depends("week_update", "4")
o:depends("week_update", "5")
o:depends("week_update", "6")
o:depends("week_update", "7")
o.rmempty = true

---- Interval Update
o = s:option(ListValue, "interval_update", translate("Update Interval(hour)"))
for t = 1, 24 do o:value(t, t .. " " .. translate("hour")) end
o.default = 2
o:depends("week_update", "8")
o.rmempty = true

---- 更新选项，始终被js隐藏
local flags = {
	"gfwlist_update", "chnroute_update", "chnroute6_update",
	"chnlist_update"
}
for _, f in ipairs(flags) do
	o = s:option(Flag, f)
	o.rmempty = false
end

s:append(Template(appname .. "/rule/rule_version"))

return m
