local _M = {}

local function gh_release_url(self)
	--return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
	return "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/" .. string.lower(self.name) .. "-release-api.json"
end

-- 排序顺序定义
_M.order = {
	"geoview",
	"chinadns-ng",
	"hysteria"
}

-- PassWall uses the same cached GitHub Release API, but is not listed as a
-- downloadable component because its LuCI package update flow is handled separately.
_M.passwall = {
	name = "PassWall",
	get_url = gh_release_url
}

_M.hysteria = {
	name = "Hysteria",
	repo = "HyNetworks/hysteria",
	-- Pin the private Lite target; never offer the v2 latest release.
	get_url = function(self) return "https://api.github.com/repos/" .. self.repo .. "/releases/tags/v1.3.5" end,
	cmd_version = "--version | sed -n 's/^hysteria version v*\\([0-9][0-9.]*\\).*/\\1/p'",
	remote_version_str_replace = "app/",
	zipped = false,
	default_path = "/usr/bin/hysteria",
	match_fmt_str = "linux%%-%s$",
	file_tree = {
		armv6 = "arm",
		armv7 = "arm",
		mipsel = "mipsle"
	}
}

_M["chinadns-ng"] = {
	name = "ChinaDNS-NG",
	repo = "zfl9/chinadns-ng",
	get_url = gh_release_url,
	cmd_version = "-V | awk '{print $2}'",
	zipped = false,
	default_path = "/usr/bin/chinadns-ng",
	match_fmt_str = "%s",
	file_tree = {
		x86_64  = "wolfssl@x86_64.*x86_64@",
		x86     = "wolfssl@i386.*i686",
		mips    = "wolfssl@mips%-.*mips32%+soft_float@",
		mips64  = "wolfssl@mips64%-.*mips64%+soft_float@",
		mipsel  = "wolfssl@mipsel.*mips32%+soft_float@",
		mips64el = "wolfssl@mips64el%-.*mips64%+soft_float@",
		aarch64 = "wolfssl_noasm@aarch64.*v8a",
		rockchip = "wolfssl@aarch64.*v8a",
		armv5   = "wolfssl@arm.*v5te",
		armv6   = "wolfssl@arm.*v6t2",
		armv7   = "wolfssl@arm.*eabihf.*v7a",
		armv8   = "wolfssl_noasm@aarch64.*v8a",
		riscv64 = "wolfssl@riscv64.*"
	}
}

_M.geoview = {
	name = "Geoview",
	repo = "snowie2000/geoview",
	get_url = gh_release_url,
	cmd_version = '-version 2>/dev/null | awk \'NR==1 && $1=="Geoview" {print $2}\'',
	zipped = false,
	default_path = "/usr/bin/geoview",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		mipsel = "mipsle",
		mips64el = "mips64le"
	}
}

return _M
