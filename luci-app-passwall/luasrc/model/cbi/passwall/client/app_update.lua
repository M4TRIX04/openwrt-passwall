local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname)
api.set_apply_on_parse(m)

-- [[ App Settings ]]--
s = m:section(TypedSection, "global_app", translate("App Update"),
				"<font color='red'>" ..
				translate("Please confirm that your firmware supports FPU.") ..
				"</font>")
s.anonymous = true
s:append(Template(appname .. "/app_update/app_version"))

return m
