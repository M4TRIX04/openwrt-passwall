local _M = {}

local function gh_release_url(self)
	--return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
	return "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/" .. string.lower(self.name) .. "-release-api.json"
end

-- 排序顺序定义
-- App Update 页会为这里的每一项生成「检查更新 / 强制更新」，只放需要在线升级的组件。
_M.order = {
	"chinadns-ng"
}

-- 下面这个条目不在 order 里，因此不会有在线升级入口。
-- 保留它是因为 api.get_app_path("hysteria") / api.finded_com("hysteria")
-- 依赖它拿到默认路径：节点页、服务端和 app.sh 都靠这个找到二进制。
-- Hysteria 由用户自行编译安装（见 build 目录），官方上游也不再需要跟。
_M.hysteria = {
	name = "Hysteria",
	cmd_version = "version | awk '/^Version:/ {print $2}'",
	default_path = "/usr/bin/hysteria"
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

return _M
