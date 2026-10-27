#!/bin/sh
# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization

. /lib/functions.sh
. /lib/functions/service.sh
. /usr/share/libubox/jshn.sh

. /usr/share/passwall/utils.sh
# B3.3-3C stop adapter. Definitions only: loading it starts nothing, creates no
# record and touches no helper. The ACL failure paths and stop() below use it to
# stop a scope's helper before that scope's runtime directory is removed.
. /usr/share/passwall/global_nodes.sh
. /usr/share/passwall/dns_helper.sh
# B1/B3.3-1/B3.3-2 modules. Definitions only as well: no process, record, live
# UCI read or configuration write happens at load time. Only start_global_frozen()
# and stop() call them, and only for the canonical Global scope.
. /usr/share/passwall/node_config.sh
. /usr/share/passwall/runtime_snapshot.sh
. /usr/share/passwall/bound_nodes.sh
# B3.3-3B dependency resolution plus the B3.1 instance-location helper it reuses.
# Definitions only: no UCI, cache, process or file access happens at load time.
. /usr/share/passwall/acl_nodes.sh
. /usr/share/passwall/dns_dependency.sh
GLOBAL_ACL_PATH=${TMP_ACL_PATH}/default
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_NAIVE=$LUA_UTIL_PATH/util_naiveproxy.lua
UTIL_HYSTERIA=$LUA_UTIL_PATH/util_hysteria.lua
HYSTERIA_RUNTIME=$LUA_UTIL_PATH/hysteria_runtime.lua
# The DNS helper adapter runs this Lua probe for every identity check. An
# explicit caller value wins; otherwise use the installed module path. A
# missing or broken probe is never substituted here, so the identity check
# stays fail-closed instead of guessing another location.
PW_DNS_HELPER_PROBE=${PW_DNS_HELPER_PROBE:-$LUA_UTIL_PATH/dns_helper_probe.lua}
# The frozen-node adapter follows the same rule: an explicit caller value wins
# and a missing module is never replaced by another location.
PW_BOUND_HELPER=${PW_BOUND_HELPER:-$LUA_UTIL_PATH/runtime_binding.lua}
# The 3B candidate probe and the H3 dnsmasq generator are addressed the same
# way: an explicit path wins, a missing module is never substituted.
PW_DEPENDENCY_HELPER=${PW_DEPENDENCY_HELPER:-$LUA_UTIL_PATH/dependency_probe.lua}
PW_DNSMASQ_GENERATOR=${PW_DNSMASQ_GENERATOR:-$APP_PATH/helper_dnsmasq.lua}

check_run_environment() {
	local prefer_nft=$(config_n_get @global_forwarding[0] prefer_nft 1)
	local dnsmasq_info=$(dnsmasq -v 2>/dev/null)
	local dnsmasq_ver=$(echo "$dnsmasq_info" | sed -n '1s/.*version \([0-9.]*\).*/\1/p')
	# local dnsmasq_opts=$(echo "$dnsmasq_info" | grep -i "Compile time options")
	local dnsmasq_ipset=0; echo "$dnsmasq_info" | grep -qw "ipset" && dnsmasq_ipset=1
	local dnsmasq_nftset=0; echo "$dnsmasq_info" | grep -qw "nftset" && dnsmasq_nftset=1
	local has_ipt=0; { command -v iptables-legacy || command -v iptables; } >/dev/null && has_ipt=1
	local has_ipset=$(command -v ipset >/dev/null && echo 1 || echo 0)
	local has_fw4=$(command -v fw4 >/dev/null && echo 1 || echo 0)
	if [ "$prefer_nft" = "1" ]; then
		if [ "$dnsmasq_nftset" -eq 1 ] && [ "$has_fw4" -eq 1 ]; then
			USE_TABLES="nftables"
		elif [ "$has_ipset" -eq 1 ] && [ "$has_ipt" -eq 1 ] && [ "$dnsmasq_ipset" -eq 1 ]; then
			echolog "警告：nftables (fw4) 应用环境不完整，切换至 iptables。(has_fw4:$has_fw4/dnsmasq_nftset:$dnsmasq_nftset)"
			USE_TABLES="iptables"
		fi
	else
		if [ "$has_ipset" -eq 1 ] && [ "$has_ipt" -eq 1 ] && [ "$dnsmasq_ipset" -eq 1 ]; then
			USE_TABLES="iptables"
		elif [ "$dnsmasq_nftset" -eq 1 ] && [ "$has_fw4" -eq 1 ]; then
			echolog "警告：iptables (fw3) 应用环境不完整，切换至 nftables。(has_ipt:$has_ipt/has_ipset:$has_ipset/dnsmasq_ipset:$dnsmasq_ipset)"
			USE_TABLES="nftables"
		fi
	fi

	if [ -n "$USE_TABLES" ]; then
		local dep_list
		local file_path="/usr/lib/opkg/info"
		local file_ext=".control"
		[ -d "/lib/apk/packages" ] && { file_path="/lib/apk/packages"; file_ext=".list"; }

		if [ "$USE_TABLES" = "iptables" ]; then
			dep_list="iptables-mod-tproxy iptables-mod-socket iptables-mod-iprange iptables-mod-conntrack-extra iptables-mod-extra kmod-ipt-nat"
		else
			dep_list="kmod-nft-socket kmod-nft-tproxy kmod-nft-nat kmod-nf-reject kmod-nf-reject6"
			nftflag=1
			local v_num=$(echo "$dnsmasq_ver" | tr -cd '0-9')
			if [ "${v_num:-0}" -lt 292 ]; then
				echolog "提示：Dnsmasq ($dnsmasq_ver) 低于 2.92，建议升级以增强稳定性。"
			fi
		fi
		local pkg
		for pkg in $dep_list; do
			if [ ! -s "${file_path}/${pkg}${file_ext}" ]; then
				echolog "警告：${USE_TABLES} 透明代理缺失基础依赖 ${pkg}！"
			fi
		done
	else
		echolog "警告：不满足任何透明代理系统环境。(has_fw4:$has_fw4/has_ipt:$has_ipt/has_ipset:$has_ipset/dnsmasq_nftset:$dnsmasq_nftset/dnsmasq_ipset:$dnsmasq_ipset)"
	fi
}

run_ipt2socks() {
	local flag tcp_tproxy local_port socks_address socks_port socks_username socks_password log_file param
	for param in "$@"; do
		case "$param" in
			flag=*) flag="${param#*=}" ;;
			tcp_tproxy=*) tcp_tproxy="${param#*=}" ;;
			local_port=*) local_port="${param#*=}" ;;
			socks_address=*) socks_address="${param#*=}" ;;
			socks_port=*) socks_port="${param#*=}" ;;
			socks_username=*) socks_username="${param#*=}" ;;
			socks_password=*) socks_password="${param#*=}" ;;
			log_file=*) log_file="${param#*=}" ;;
		esac
	done
	[ -n "$log_file" ] || log_file="/dev/null"
	socks_address=$(get_host_ip "ipv4" "$socks_address")
	set -- -o 60 -n 65535 -v
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && set -- "$@" -a "$socks_username" -k "$socks_password"
	[ -n "$tcp_tproxy" ] || set -- "$@" -R
	flag="${flag}_TCP_UDP"
	ln_run "$(first_type ipt2socks)" "ipt2socks_${flag}" "$log_file" -l "$local_port" -b 0.0.0.0 -B :: -s "$socks_address" -p "$socks_port" "$@"
}

run_dns2socks() {
	local flag socks socks_address socks_port socks_username socks_password listen_address listen_port dns cache log_file
	local _extra_param=""
	eval_set_val "$@"
	[ -n "$flag" ] && flag="_${flag}"
	[ -n "$log_file" ] || log_file="/dev/null"
	dns=$(format_dns $dns 53)
	[ -n "$socks" ] && {
		socks="${socks//#/:}"
		socks_address=$(echo $socks | awk -F ':' '{print $1}')
		socks_port=$(echo $socks | awk -F ':' '{print $2}')
	}
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} /u $socks_username /p $socks_password"
	[ -z "$cache" ] && cache=1
	[ "$cache" = "0" ] && _extra_param="${_extra_param} /d"
	ln_run "$(first_type dns2socks)" "dns2socks${flag}" $log_file ${_extra_param} "${socks_address}:${socks_port}" "${dns}" "${listen_address}:${listen_port}"
}

run_chinadns_ng() {
	local _flag _listen_port _dns_local _dns_trust _no_ipv6_trust _use_direct_list _use_proxy_list _gfwlist _chnlist _default_mode _default_tag _no_logic_log _node _filter_https _log
	local _extra_param=""
	eval_set_val "$@"

	local _CONF_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.conf
	local _LOG_FILE="/dev/null"
	[ "${_log}" = "1" ] && _LOG_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.log

	_extra_param="-FLAG ${_flag} -NODE ${_node} -LISTEN_PORT ${_listen_port} -DNS_LOCAL ${_dns_local} -DNS_TRUST ${_dns_trust}"
	_extra_param="${_extra_param} -USE_DIRECT_LIST ${_use_direct_list} -USE_PROXY_LIST ${_use_proxy_list} -USE_BLOCK_LIST ${_use_block_list}"
	_extra_param="${_extra_param} -GFWLIST ${_gfwlist} -CHNLIST ${_chnlist} -NO_IPV6_TRUST ${_no_ipv6_trust} -DEFAULT_MODE ${_default_mode}"
	_extra_param="${_extra_param} -DEFAULT_TAG ${_default_tag} -NFTFLAG ${nftflag} -NO_LOGIC_LOG ${_no_logic_log}"
	_extra_param="${_extra_param} -FILTER_HTTPS ${_filter_https} -LOG_FILE ${_LOG_FILE}"

	lua $APP_PATH/helper_chinadns_add.lua ${_extra_param} > ${_CONF_FILE}
	ln_run "$(first_type chinadns-ng)" chinadns-ng "${_LOG_FILE}" -C ${_CONF_FILE}
}

gen_ss_config() {
	local output="$2"
	if ! lua "$UTIL_SS" gen_config "$1" > "$output" 2> "${output}.error"; then
		echolog "SS configuration rejected: $(cat "${output}.error")"
		cat "${output}.error" >&2
		rm -f "$output" "${output}.error"
		return 1
	fi
	rm -f "${output}.error"
}

# Retired nodes remain in UCI for manual migration, never as runnable endpoints.
check_node_supported() {
	case "$(config_n_get "$1" type)" in
	Hysteria2|Xray|sing-box|Socks)
		echolog "Node $1 rejected: $(config_n_get "$1" type) support has been removed."
		return 1
	;;
	esac
	if [ "$(config_get_type "$1")" = socks ]; then
		echolog "Node $1 rejected: SOCKS services are listeners, not proxy nodes. Select their SS/Hysteria node instead."
		return 1
	fi
	case "$(config_n_get "$1" protocol)" in
	_shunt|_balancing|_urltest|_iface)
		echolog "Node $1 rejected: core-specific special nodes have been removed."
		return 1
	;;
	esac
	return 0
}

check_dns_config() {
	local shunt="$1" mode="$2" scope="$3"
	if [ "$scope" = global ] && [ "$mode" = dns2socks ]; then
		local legacy_socks=$(config_n_get @global[0] socks_server)
		local native_socks="127.0.0.1:$(config_n_get @global[0] node_socks_port 1070)"
		if [ -n "$legacy_socks" ] && [ "$legacy_socks" != "$native_socks" ]; then
			echolog "DNS global rejected: legacy socks_server=$legacy_socks is not the proxy node listener $native_socks. Clear socks_server and save DNS settings."
			return 1
		fi
	fi
	if [ "$scope" = global ]; then
		case "$shunt:$mode" in
		dnsmasq:udp|dnsmasq:tcp|dnsmasq:dns2socks|chinadns-ng:udp|chinadns-ng:tcp|chinadns-ng:dns2socks|smartdns:socks) return 0 ;;
		esac
	else
		case "$shunt:$mode" in dnsmasq:dns2socks|chinadns-ng:dns2socks) return 0 ;; esac
	fi
	echolog "DNS $scope rejected: unsupported backend $shunt/$mode. Reconfigure DNS; removed core backends are not converted automatically."
	return 1
}

# Stop the DNS helper owned by exactly one scope, before that scope's runtime
# directory is removed. Scope-local and idempotent: no record means nothing is
# owned here, and the adapter never claims a process by name or port. Returns
# non-zero only when a recorded helper could not be confirmed stopped, in which
# case the caller must keep the record instead of deleting it.
stop_scope_dns_helper() {
	command -v passwall_stop_dns_helper >/dev/null 2>&1 || return 0
	local scope_dir
	# A scope name the adapter cannot represent never owns a record, so it must
	# not turn an ordinary ACL cleanup into a failure.
	case "${1:-}" in
		global) scope_dir=${TMP_ACL_PATH:-}/default ;;
		acl)
			case "${2:-}" in ''|*[!A-Za-z0-9_]*) return 0 ;; esac
			scope_dir=${TMP_ACL_PATH:-}/$2
			;;
		*) return 0 ;;
	esac
	# Nothing owned: without a runtime root, or without this scope's own
	# directory, no record exists that could authorize a stop. This keeps a
	# cold stop/restart (empty /tmp, never started) successful, exactly like a
	# directory that exists but holds no record. An existing directory is always
	# handed to the adapter, which decides by identity alone.
	[ -n "${TMP_ACL_PATH:-}" ] && [ -d "$TMP_ACL_PATH" ] || return 0
	[ -e "$scope_dir" ] || [ -L "$scope_dir" ] || return 0
	passwall_stop_dns_helper "" "$1" "${2:-}"
}

fail_acl() {
	local failed_sid="$1" key cleanup_status=0
	for key in node redir_port dns_port default fakedns; do
		del_cache_var "ACL_${failed_sid}_${key}" || cleanup_status=1
	done
	set_cache_var "ACL_${failed_sid}_failed" 1 || cleanup_status=1
	# Contract 5.2 item 5: never drop the identity record before the process is
	# confirmed stopped. An unconfirmed stop keeps this ACL's records and fails
	# the cleanup instead of deleting them.
	if stop_scope_dns_helper acl "$failed_sid"; then
		rm -rf "${TMP_ACL_PATH:?}/${failed_sid}" || cleanup_status=1
	else
		cleanup_status=1
		echolog "ACL $failed_sid: DNS helper stop unconfirmed; runtime records retained."
	fi
	echolog "ACL $failed_sid rejected: $2"
	[ "$cleanup_status" = 0 ] || echolog "ACL $failed_sid cache cleanup failed; firewall initialization must stop."
	return "$cleanup_status"
}

check_ss_node() {
	[ "$(config_n_get "$1" type)" = "SS" ] || return 0
	local check_file="$TMP_ACL_PATH/check_ss_${1}.json"
	gen_ss_config "{\"node\":\"$1\"}" "$check_file" || return 1
	rm -f "$check_file"
}

fail_ss_acl() {
	local failed_sid="$1" failed_node="$2" failed_config="$3" key
	for key in node redir_port dns_port default fakedns; do
		del_cache_var "ACL_${failed_sid}_${key}"
	done
	if [ -z "$failed_config" ]; then
		local failed_socks=$(get_cache_var "acl_node_${failed_node}_socks_port")
		for key in socks_port redir_port enable_log; do
			del_cache_var "acl_node_${failed_node}_${key}"
		done
		# Preflight rejected this node before any ACL could start it.
		[ ! -f "$TMP_PATH/var" ] || sed -i "/^node_${failed_node}_[0-9a-f]*=/d; /^node_${failed_node}_[0-9a-f]*_ipv6=/d" "$TMP_PATH/var"
		if [ -n "$failed_socks" ]; then
			local failed_file="${TMP_ACL_PATH:?}/${failed_node}_SOCKS_${failed_socks}"
			rm -f "${failed_file}.json" "${failed_file}.json.error" "${failed_file}_DNS.json" "${failed_file}_DNS.json.error"
		fi
	else
		# Preserve a successful instance shared by another ACL of the same node.
		rm -f "$TMP_PATH/$failed_config" "$TMP_PATH/${failed_config}.error"
	fi
	set_cache_var "ACL_${failed_sid}_failed" 1
	if stop_scope_dns_helper acl "$failed_sid"; then
		rm -rf "${TMP_ACL_PATH:?}/${failed_sid}"
	else
		echolog "ACL ${failed_sid}: DNS helper stop unconfirmed; runtime records retained."
	fi
	echolog "ACL ${failed_sid}: SS node ${failed_node} rejected; skipping this ACL."
}

gen_hysteria_config() {
	if ! lua "$UTIL_HYSTERIA" gen_config "$1" > "$2" 2> "$2.error"; then
		echolog "Hysteria 1 configuration rejected: $(cat "$2.error")"
		rm -f "$2" "$2.error"
		return 1
	fi
	rm -f "$2.error"
}

check_hysteria_node() {
	[ "$(config_n_get "$1" type)" = "Hysteria" ] || return 0
	local output="$TMP_ACL_PATH/check_hysteria_${1}.json"
	gen_hysteria_config "{\"node\":\"$1\",\"local_socks_port\":\"1080\"}" "$output" || return 1
	rm -f "$output"
}

start_hysteria() {
	local config_file="$1" log_file="$2" level="$3"
	json_init
	json_add_string config "$config_file"
	json_add_string bin "$(first_type "$(config_n_get @global_app[0] hysteria_file)")"
	json_add_string scope client
	json_add_string bin_dir "$TMP_BIN_PATH"
	json_add_string mode client
	json_add_string log "${log_file:-/dev/null}"
	json_add_string loglevel "${level:-warn}"
	if ! lua "$HYSTERIA_RUNTIME" start "$(json_dump)"; then
		echolog "Hysteria 1 startup failed: $config_file"
		rm -f "$config_file"
		return 1
	fi
}

fail_hysteria_acl() {
	local cleanup_status=0 key
	# The node cache may belong to another successful ACL. Only a caller's
	# explicit, newly allocated instance path may be reclaimed here.
	if [ -n "$3" ]; then
		lua "$HYSTERIA_RUNTIME" stop client "$3" || {
			cleanup_status=1
			echolog "ACL $1: Hysteria cleanup pending: $3"
		}
	fi
	for key in node redir_port dns_port default fakedns; do del_cache_var "ACL_${1}_${key}"; done
	set_cache_var "ACL_${1}_failed" 1
	if stop_scope_dns_helper acl "$1"; then
		rm -rf "${TMP_ACL_PATH:?}/$1"
	else
		cleanup_status=1
		echolog "ACL $1: DNS helper stop unconfirmed; runtime records retained."
	fi
	echolog "ACL $1: Hysteria 1 node $2 failed; skipping this ACL."
	return "$cleanup_status"
}

run_hysteria_acl() {
	local config_file="$TMP_PATH/$2"
	json_init
	json_add_string node "$1"
	json_add_string local_redir_port "$3"
	json_add_string local_socks_address 127.0.0.1
	json_add_string local_socks_port "$4"
	json_add_string tcp_proxy_way "$TCP_PROXY_WAY"
	json_add_string proxy_ipv6 "${PROXY_IPV6:-0}"
	gen_hysteria_config "$(json_dump)" "$config_file" || return 1
	start_hysteria "$config_file" "$5" "$6"
}

run_socks() {
	local flag node bind socks_port config_file http_port http_config_file relay_port log_file no_run loglevel
	eval_set_val "$@"
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	[ -n "$http_port" ] || http_port=0
	[ -n "$http_config_file" ] && [ -z "$(echo ${http_config_file} | grep $TMP_PATH)" ] && http_config_file=$TMP_PATH/$http_config_file
	if [ -z "$log_file" ] || [ "$log_file" = "/dev/null" ]; then
		log_file="/dev/null"
	elif [ "${log_file#"$TMP_PATH/"}" = "$log_file" ]; then
		log_file=$TMP_PATH/$log_file
	fi
	loglevel=${loglevel:-warn}

	check_node_supported "$node" || return 1
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	if [ "$http_port" != 0 ] && [ "$type" != hysteria ] && [ "$type" != ss-rust ]; then
		echolog "Node $node: HTTP conversion has been removed; HTTP port $http_port disabled, native SOCKS retained."
		http_port=0
	fi
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local server_port=$(config_n_get $node port)

	[ -n "$relay_port" ] && {
		server_host="127.0.0.1"
		server_port=$relay_port
	}
	local error_msg tmp

	if [ -n "$server_host" ] && [ -n "$server_port" ]; then
		check_host $server_host
		[ $? != 0 ] && {
			echolog "  - Socks节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
		tmp="${server_host}:${server_port}"
	else
		error_msg="某种原因，此 Socks 服务的相关配置已失联，启动中止！"
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动中止 ${bind}:${socks_port} ${error_msg}"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动 ${bind}:${socks_port}"

	json_init
	json_add_string "node" "${node}"
	json_add_string "server_host" "${server_host}"
	json_add_string "server_port" "${server_port}"
	case "$type" in
	naiveproxy)
		json_add_string "run_type" "socks"
		json_add_string "local_addr" "$bind"
		json_add_string "local_port" "$socks_port"
		lua $UTIL_NAIVE gen_config "$(json_dump)" > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type naive)" naive $log_file "$config_file"
	;;
	ss)
		json_add_string "local_addr" "$bind"
		json_add_string "local_port" "$socks_port"
		json_add_string "mode" "tcp_and_udp"
		gen_ss_config "$(json_dump)" "$config_file" || return 1
		[ -n "$no_run" ] || ln_run "$(first_type ss-local)" "ss-local" $log_file -c "$config_file" -v
	;;
	ssr)
		json_add_string "local_addr" "$bind"
		json_add_string "local_port" "$socks_port"
		lua $UTIL_SS gen_config "$(json_dump)" > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss-rust)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file%%.*}+http${config_file#${config_file%%.*}}"
			json_add_string "local_http_address" "$bind"
			json_add_string "local_http_port" "$http_port"
		}
		[ -n "$no_run" ] || {
			local plugin_sh="${config_file%.json}_plugin.sh"
			json_add_string "plugin_sh" "$plugin_sh"
		}
		json_add_string "local_socks_address" "$bind"
		json_add_string "local_socks_port" "$socks_port"
		json_add_string "loglevel" "$loglevel"
		lua $UTIL_SS gen_config "$(json_dump)" > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria)
		json_add_string local_socks_address "$bind"
		json_add_string local_socks_port "$socks_port"
		if [ "$http_port" != 0 ]; then
			http_flag=1
			json_add_string local_http_address "$bind"
			json_add_string local_http_port "$http_port"
		fi
		gen_hysteria_config "$(json_dump)" "$config_file" || return 1
		[ -n "$no_run" ] || start_hysteria "$config_file" "$log_file" "$loglevel" || return 1
	;;
	esac

	[ -z "$no_run" ] && [ "${server_host}" != "127.0.0.1" ] && echo "${node}" >> $TMP_PATH/direct_node_list
	return 0
}

# Production entry for the canonical Global scope. The merged `node` selector is
# absent here, so the frozen bound mechanism owns the only Global SOCKS listener
# and start_global() below is never reached for the same scope. Every published
# endpoint value is read back from the instance that mechanism sealed; nothing
# here launches a second listener or reuses a legacy one as a bound candidate.
start_global_frozen() {
	local snapshot layout frozen_node instance node port socks preference=ipv4 family=4 DNS_HELPER_BLOCKED=0
	[ -n "$PW_BOUND_HELPER" ] && [ -f "$PW_BOUND_HELPER" ] || {
		echolog "全局节点：冻结运行适配器缺失，停止启动。"
		return 1
	}
	passwall_snapshot_capture || {
		echolog "全局节点：冻结配置快照生成失败，停止启动。"
		return 1
	}
	snapshot=$PW_SNAPSHOT_DIR
	passwall_snapshot_pair "$snapshot" global || {
		echolog "全局节点：冻结配置解析失败，停止启动。"
		return 1
	}
	layout=$PW_SNAPSHOT_LAYOUT
	frozen_node=$PW_SNAPSHOT_TCP
	# The firewall still routes one Global port for both protocols. A split
	# layout needs that work (B4), so it is refused instead of half-starting.
	if [ "$layout" != "combined" ]; then
		echolog "全局节点：冻结路径本轮仅支持 TCP/UDP 同节点（当前 ${layout}），已拒绝启动。"
		return 1
	fi
	[ "$PROXY_IPV6" != "1" ] || { preference=ipv6; family=6; }
	echolog "全局节点：[${frozen_node}]，冻结绑定启动。"
	# A previous generation's DNS helper is stopped before its instance is
	# replaced, in the same order stop() uses. An unconfirmed stop blocks the new
	# helper instead of running two claims side by side.
	DNS_HELPER_BLOCKED=0
	stop_scope_dns_helper global || {
		echolog "全局节点：上一代 DNS Helper 停止未确认，本轮不启动新 Helper。"
		DNS_HELPER_BLOCKED=1
	}
	passwall_start_bound_global_nodes "$snapshot" "$preference" "$family" || return 1
	instance=$(get_cache_var ACL_GLOBAL_TCP_instance) || return 1
	case "$instance" in
		"$GLOBAL_ACL_PATH"/split/instance.*/config.json) ;;
		*) echolog "全局节点：绑定实例发布指针无效。"; return 1 ;;
	esac
	instance=${instance%/config.json}
	node=$(sed -n '2p' "$instance/meta") || return 1
	port=$(sed -n '3p' "$instance/meta") || return 1
	socks=$(cat "$instance/socks_port") || return 1
	# A combined instance serves both protocols on one port and must be the node
	# the frozen snapshot selected. Anything else is not a usable endpoint.
	if [ "$node" != "$frozen_node" ] || [ -z "$port" ] || [ -z "$socks" ] ||
		[ "$(sed -n '4p' "$instance/meta")" != "$port" ]; then
		echolog "全局节点：绑定实例端点记录不完整。"
		return 1
	fi
	# Bridge only what the DNS and firewall consumers still read. These values
	# are the instance's own, so the frozen candidate keys published above stay
	# authoritative for 3B.
	NODE=$node
	REDIR_PORT=$port
	GLOBAL_SOCKS_server="127.0.0.1:$socks"
	echo "${NODE}" >> $TMP_PATH/direct_node_list
	# DNS-H4-F2-C: the helper depends on this instance and is verified here.
	# start_dns below consumes its published claim as the production upstream.
	[ "$DNS_HELPER_BLOCKED" = 0 ] &&
		start_global_dns_helper "$snapshot" "$frozen_node" "$preference" "$family"
	# start() publishes the complete endpoint only after DNS also succeeds.
	return 0
}

# Start the Global scope's DNS helper from the same frozen snapshot and the
# instance this launcher just published. Every input is frozen: no live UCI is
# re-read and no production dnsmasq configuration is generated or reloaded here.
# A helper that cannot be proven ready publishes no dep_ready, and start_dns
# then refuses to publish any upstream for this scope at all.
start_global_dns_helper() {
	local snapshot="$1" node="$2" preference="$3" family="$4"
	local global port fragment base dnsmasq request candidate rc=0
	local use_direct use_proxy use_block use_gfw chn use_default filter_ipv6 proxy_mode
	local local_dns default_dns
	command -v passwall_start_dns_helper >/dev/null 2>&1 &&
		command -v passwall_validate_dns_dependency >/dev/null 2>&1 &&
		[ -n "${PW_DEPENDENCY_HELPER:-}" ] && [ -f "$PW_DEPENDENCY_HELPER" ] &&
		[ -n "${PW_DNSMASQ_GENERATOR:-}" ] && [ -f "$PW_DNSMASQ_GENERATOR" ] || {
		echolog "DNS helper：依赖适配层缺失，未启动 Helper，未发布 dep_ready。"
		return 1
	}
	case "$node" in ''|*[!a-zA-Z0-9_-]*) return 1 ;; esac
	# The caller has already stopped the previous generation's helper, before the
	# instance it depended on was replaced.
	passwall_validate_dns_dependency "$snapshot" global GLOBAL "$preference" "$family" || {
		echolog "DNS 依赖：3B 校验拒绝（${PW_DNS_DEP_REASON:-dns_dep_identity}），未启动 Helper。"
		return 1
	}
	candidate=$PW_DNS_DEP_JSON
	global=$(cat "$snapshot/global") || return 1
	# The base is the running system dnsmasq configuration. Without it the
	# fragment cannot preserve local/SRV/hosts behaviour, so it is refused.
	base="/var/etc/dnsmasq.conf.${DEFAULT_DNSMASQ_CFGID:-}"
	[ -n "${DEFAULT_DNSMASQ_CFGID:-}" ] && [ -f "$base" ] && [ -r "$base" ] || {
		echolog "DNS helper：系统 dnsmasq 配置 ${base} 不可读，未启动 Helper。"
		return 1
	}
	dnsmasq=$(first_type dnsmasq) || dnsmasq=
	case "$dnsmasq" in /*) ;; *) echolog "DNS helper：dnsmasq 不可用。"; return 1 ;; esac
	port=$(passwall_alloc_dns_helper_port) || port=
	case "$port" in ''|*[!0-9]*) echolog "DNS helper：Helper 端口分配失败。"; return 1 ;; esac
	fragment=$(get_new_port 11400 tcp,udp) || fragment=
	case "$fragment" in ''|*[!0-9]*) return 1 ;; esac
	[ "$fragment" != "$port" ] || fragment=$(get_new_port 11500 tcp,udp)
	case "$fragment" in ''|*[!0-9]*) return 1 ;; esac
	[ "$fragment" != "$port" ] || return 1

	use_direct=$(_pw_snapshot_option "$snapshot" "$global" use_direct_list) || return 1
	use_proxy=$(_pw_snapshot_option "$snapshot" "$global" use_proxy_list) || return 1
	use_block=$(_pw_snapshot_option "$snapshot" "$global" use_block_list) || return 1
	use_gfw=$(_pw_snapshot_option "$snapshot" "$global" use_gfw_list) || return 1
	chn=$(_pw_snapshot_option "$snapshot" "$global" chn_list) || return 1
	use_default=$(_pw_snapshot_option "$snapshot" "$global" use_default_dns) || return 1
	filter_ipv6=$(_pw_snapshot_option "$snapshot" "$global" filter_proxy_ipv6) || return 1
	proxy_mode=$(_pw_snapshot_option "$snapshot" "$global" tcp_proxy_mode) || return 1
	: "${use_direct:=1}" "${use_proxy:=1}" "${use_block:=1}" "${use_gfw:=1}"
	: "${chn:=direct}" "${use_default:=direct}" "${filter_ipv6:=0}"
	case "$proxy_mode" in disable) proxy_mode=disable ;; *) proxy_mode=proxy ;; esac
	# Derived DNS inputs only: the same literal IP#port lists the production
	# fragment uses, never a helper or cache value.
	local_dns=$(printf '%s\n' "${LOCAL_DNS:-}" | awk -F',' '{for(i=1;i<=NF;i++){if($i !~ /#/) $i=$i"#53";} print $0;}' OFS=',')
	default_dns=$(printf '%s\n' "${DEFAULT_DNS:-${LOCAL_DNS:-}}" | awk -F',' '{for(i=1;i<=NF;i++){if($i !~ /#/) $i=$i"#53";} print $0;}' OFS=',')
	request=$(printf '{"-FLAG":"default","-NODE":"%s","-LISTEN_PORT":"%s","-DEFAULT_DNS":"%s","-LOCAL_DNS":"%s","-TUN_DNS":"127.0.0.1#%s","-USE_DEFAULT_DNS":"%s","-CHINADNS_DNS":"0","-USE_DIRECT_LIST":"%s","-USE_PROXY_LIST":"%s","-USE_BLOCK_LIST":"%s","-USE_GFW_LIST":"%s","-CHN_LIST":"%s","-DEFAULT_PROXY_MODE":"%s","-NO_PROXY_IPV6":"%s","-NFTFLAG":"%s","-NO_LOGIC_LOG":"1"}' \
		"$node" "$fragment" "$default_dns" "$local_dns" "$port" "$use_default" \
		"$use_direct" "$use_proxy" "$use_block" "$use_gfw" "$chn" "$proxy_mode" "$filter_ipv6" "${nftflag:-0}")

	passwall_start_dns_helper "$snapshot" global GLOBAL "$preference" "$family" "$candidate" \
		"$base" "$dnsmasq" "$port" "$request" || rc=$?
	case "$rc" in
	0)
		echolog "DNS helper：已就绪（127.0.0.1#${port}，${PW_DNS_HELPER_L3_EVIDENCE:-L3 未取证}）。"
		[ -z "${PW_DNS_HELPER_DEP_READY:-}" ] ||
			echolog "DNS helper：dep_ready 已发布（${PW_DNS_HELPER_DEP_READY}），生产 DNS 上游待消费前复核后发布。"
		;;
	*)
		echolog "DNS helper：未就绪（rc=${rc}，${PW_DNS_HELPER_REASON:-dns_dep_identity}，phase=${PW_DNS_HELPER_PHASE:-unknown}${PW_DNS_HELPER_L3_ERROR:+，l3=${PW_DNS_HELPER_L3_ERROR}}），未发布 dep_ready。"
		;;
	esac
	return 0
}

start_global() {
	check_node_supported "$NODE" || return 1
	check_dns_config "${DNS_SHUNT:-dnsmasq}" "${DNS_MODE:-tcp}" global || return 1
	[ -z "$NODE" ] && return 1
	local config_file=${GLOBAL_ACL_PATH}/global.json
	local log_file=${GLOBAL_ACL_PATH}/global.log

	local remarks=$(config_n_get $NODE remarks)
	local server_host=$(config_n_get $NODE address)
	local port=$(config_n_get $NODE port)
	local type=$(echo $(config_n_get $NODE type) | tr 'A-Z' 'a-z')

	local enable_log=$(config_n_get @global[0] log_node 1)
	[ "$enable_log" != "1" ] && log_file="/dev/null"
	[ -n "$server_host" ] && [ -n "$port" ] && {
		check_host $server_host
		[ $? != 0 ] && {
			echolog "全局节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
	}
	echolog "全局节点：[$remarks]，监听端口：$REDIR_PORT"
	local on_node_socks=1
	local node_socks_bind_local=$(config_n_get @global[0] node_socks_bind_local 1)
	local node_socks_bind="127.0.0.1"
	[ "${node_socks_bind_local}" != "1" ] && node_socks_bind="0.0.0.0"
	GLOBAL_SOCKS_port=$(config_n_get @global[0] node_socks_port 1070)
	GLOBAL_HTTP_port=$(config_n_get @global[0] node_http_port 0)
	if [ "$GLOBAL_HTTP_port" != 0 ] && [ "$type" != hysteria ] && [ "$type" != ss-rust ]; then
		echolog "Global node $NODE: HTTP conversion has been removed; HTTP port $GLOBAL_HTTP_port disabled, native SOCKS retained."
		GLOBAL_HTTP_port=0
	fi
	[ "$GLOBAL_HTTP_port" != "0" ] && local on_node_http=1
	if [ $PROXY_IPV6 = "1" ]; then
		echolog "开启实验性IPv6透明代理(TProxy)，请确认您的节点及类型支持IPv6！"
	fi
	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		can_ipt=$(echo "$REDIRECT_LIST" | grep "$type")
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		can_ipt=$(echo "$TPROXY_LIST" | grep "$type")
	fi
	[ -z "$can_ipt" ] && type="socks"

	json_init
	json_add_string "node" "$NODE"

	local _socks_flag node_socks_flag node_http_flag _socks_address _socks_port _socks_username _socks_password
	case "$type" in
	socks)
		_socks_flag=1
		_socks_address=$server_host
		_socks_port=$port
		_socks_username=$(config_n_get $NODE username)
		_socks_password=$(config_n_get $NODE password)
		[ -z "$can_ipt" ] && {
			local _config_file="global_${NODE}_socks.json"
			_socks_address="127.0.0.1"
			_socks_port=$GLOBAL_SOCKS_port
			run_socks flag="global" node=$NODE bind=${node_socks_bind} socks_port=${_socks_port} config_file=${_config_file} http_port=${GLOBAL_HTTP_port} http_config_file=${GLOBAL_ACL_PATH}/global_socks_http.json
			node_socks_flag=1
			[ "$on_node_http" = "1" ] && node_http_flag=1
			unset _socks_username
			unset _socks_password
		}
	;;
	naiveproxy)
		json_add_string "run_type" "redir"
		json_add_string "local_addr" "0.0.0.0"
		json_add_string "local_port" "$REDIR_PORT"
		lua $UTIL_NAIVE gen_config "$(json_dump)" > $config_file
		ln_run "$(first_type naive)" naive $log_file "$config_file"
		echolog "注意：Naiveproxy 不支持 UDP 转发！"
	;;
	ss)
		[ "${TCP_PROXY_WAY}" = "tproxy" ] && json_add_string "tcp_tproxy" "true"
		json_add_string "local_addr" "0.0.0.0"
		json_add_string "local_port" "$REDIR_PORT"
		json_add_string "mode" "tcp_and_udp"
		gen_ss_config "$(json_dump)" "$config_file" || return 1
		ln_run "$(first_type ss-redir)" "ss-redir" $log_file -c "$config_file" -v
	;;
	ssr)
		[ "${TCP_PROXY_WAY}" = "tproxy" ] && json_add_string "tcp_tproxy" "true"
		local _extra_param="-u"
		json_add_string "local_addr" "0.0.0.0"
		json_add_string "local_port" "$REDIR_PORT"
		lua $UTIL_SS gen_config "$(json_dump)" > $config_file
		ln_run "$(first_type ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v ${_extra_param}
	;;
	ss-rust)
		json_add_string "local_redir_port" "$REDIR_PORT"
		[ "${TCP_PROXY_WAY}" = "tproxy" ] && json_add_string "tcp_tproxy" "true"
		[ "$on_node_socks" = "1" ] && {
			node_socks_flag=1
			json_add_string "local_socks_address" "${node_socks_bind}"
			json_add_string "local_socks_port" "${GLOBAL_SOCKS_port}"
		}
		[ "$on_node_http" = "1" ] && {
			node_http_flag=1
			json_add_string "local_http_port" "${GLOBAL_HTTP_port}"
		}
		local plugin_sh="${config_file%.json}_plugin.sh"
		json_add_string "plugin_sh" "$plugin_sh"
		json_add_string "loglevel" "$(config_n_get @global[0] loglevel "warn")"
		lua $UTIL_SS gen_config "$(json_dump)" > $config_file
		ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria)
		json_add_string local_redir_port "$REDIR_PORT"
		json_add_string tcp_proxy_way "$TCP_PROXY_WAY"
		json_add_string proxy_ipv6 "${PROXY_IPV6:-0}"
		json_add_string local_socks_address "$node_socks_bind"
		json_add_string local_socks_port "$GLOBAL_SOCKS_port"
		[ "$on_node_http" = 1 ] && json_add_string local_http_port "$GLOBAL_HTTP_port"
		gen_hysteria_config "$(json_dump)" "$config_file" || return 1
		start_hysteria "$config_file" "$log_file" "$(config_n_get @global[0] loglevel warn)" || return 1
		node_socks_flag=1
		[ "$on_node_http" = 1 ] && node_http_flag=1
	;;
	esac
	if [ -n "${_socks_flag}" ]; then
		local _socks_tproxy=""
		[ "${TCP_PROXY_WAY}" = "tproxy" ] && _socks_tproxy="1"
		run_ipt2socks flag=default tcp_tproxy="${_socks_tproxy}" local_port="${REDIR_PORT}" socks_address="${_socks_address}" socks_port="${_socks_port}" socks_username="${_socks_username}" socks_password="${_socks_password}" log_file="${log_file}"
	fi

	[ -z "$node_socks_flag" ] && {
		[ "$on_node_socks" = "1" ] && {
			local config_file=${GLOBAL_ACL_PATH}/global_socks.json
			local log_file=${GLOBAL_ACL_PATH}/global_socks.log
			local http_port=0
			local http_config_file=${GLOBAL_ACL_PATH}/global_socks_http.json
			[ "$on_node_http" = "1" ] && [ -z "$node_http_flag" ] && {
				http_port=$GLOBAL_HTTP_port
			}
			run_socks flag=TCP node=$NODE bind=$node_socks_bind socks_port=$GLOBAL_SOCKS_port config_file=$config_file http_port=$http_port http_config_file=$http_config_file || { [ "$type" = "ss" ] && return 1; }
		}
	}

	[ "$on_node_socks" = "1" ] && {
		GLOBAL_SOCKS_server="127.0.0.1:$GLOBAL_SOCKS_port"
	}
	echo "${NODE}" >> $TMP_PATH/direct_node_list
	# start() publishes the complete endpoint only after DNS also succeeds.
	return 0
}

start_socks() {
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		[ -n "$ids" ] && {
			echolog "分析 Socks 服务的节点配置..."
			for id in $ids; do
				local enabled=$(config_n_get $id enabled 0)
				[ "$enabled" = "0" ] && continue
				local node=$(config_n_get $id node)
				check_node_supported "$node" || { del_cache_var "$id"; continue; }
				[ -z "$node" ] && continue
				local bind_local=$(config_n_get $id bind_local 0)
				local bind="0.0.0.0"
				[ "$bind_local" = "1" ] && bind="127.0.0.1"
				local port=$(config_n_get $id port)
				local config_file="${id}.json"
				local log_file="${id}.log"
				local log=$(config_n_get $id log 1)
				[ "$log" = "0" ] && log_file=""
				local http_port=$(config_n_get $id http_port 0)
				local http_config_file="${id}_http.json"
				local enable_autoswitch=$(config_n_get $id enable_autoswitch 0)
				local no_rec=0
				[ "$enable_autoswitch" = "1" ] && no_rec=1
				NO_REC_PROCESS=$no_rec $APP_PATH/app.sh run_socks flag=$id node=$node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file || { { [ "$(config_n_get $node type)" = "SS" ] || [ "$(config_n_get $node type)" = Hysteria ]; } && continue; }
				set_cache_var "${id}" "$node"
				#自动切换逻辑
				[ "$enable_autoswitch" = "1" ] && { $APP_PATH/socks_auto_switch.sh ${id} > /dev/null 2>&1 & }
			done
		}
	}
}

socks_node_switch() {
	local flag new_node
	eval_set_val "$@"
	[ -n "$flag" ] && [ -n "$new_node" ] && {
		check_node_supported "$new_node" || return 1
		[ ! -f "$HYSTERIA_RUNTIME" ] || lua "$HYSTERIA_RUNTIME" stop client "$TMP_PATH/${flag}.json"
		local suffix pf filename
		# 结束 SS 插件进程
		for suffix in "" "+http"; do
			pf="$TMP_PATH/${flag}${suffix}_plugin.pid"
			[ -s "$pf" ] && kill -9 "$(head -n1 "$pf")" >/dev/null 2>&1
		done

		busybox pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1 && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
		for suffix in "" "+http" "_http"; do
			rm -rf "$TMP_PATH/${flag}${suffix}"*
		done

		for filename in $(ls ${TMP_SCRIPT_FUNC_PATH}); do
			grep -q "${flag}" "${TMP_SCRIPT_FUNC_PATH}/${filename}" && \
				rm -f "${TMP_SCRIPT_FUNC_PATH}/${filename}" "${TMP_PATH}/script_rstats/${filename}.count"
		done
		local bind_local=$(config_n_get $flag bind_local 0)
		local bind="0.0.0.0"
		[ "$bind_local" = "1" ] && bind="127.0.0.1"
		local port=$(config_n_get $flag port)
		local config_file="${flag}.json"
		local log_file="${flag}.log"
		local log=$(config_n_get $flag log 1)
		[ "$log" = "0" ] && log_file=""
		local http_port=$(config_n_get $flag http_port 0)
		local http_config_file="${flag}_http.json"
		LOG_FILE="/dev/null"
		run_socks flag=$flag node=$new_node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file || { { [ "$(config_n_get $new_node type)" = "SS" ] || [ "$(config_n_get $new_node type)" = Hysteria ]; } && return 1; }
		sleep 2s
		[ "$(check_port_exists "$port" tcp)" = "0" ] && return 1
		set_cache_var "${flag}" "$new_node"
		return 0
	}
}

clean_crontab() {
	touch /etc/crontabs/root
	#sed -i "/${CONFIG}/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "/etc/init.d/${CONFIG}" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/rule_update.lua log" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	# Remove legacy subscription jobs on upgrade; never schedule them again.
	sed -i '/lua .*\/passwall\/subscribe\.lua start/d' /etc/crontabs/root >/dev/null 2>&1

	busybox pgrep -af "${CONFIG}/" | awk '/tasks\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
	rm -f ${LOCK_PATH}/${CONFIG}_tasks.lock
}

start_crontab() {
	local update_loop
	local setsid_cmd=""
	command -v setsid >/dev/null 2>&1 && setsid_cmd="setsid "

	if [ "$ENABLED_DEFAULT_ACL" = "1" ] || [ "$ENABLED_ACLS" = "1" ]; then
		local start_daemon=$(config_n_get @global_delay[0] start_daemon 0)
		[ "$start_daemon" = "1" ] && { $APP_PATH/monitor.sh > /dev/null 2>&1 & }
	fi

	if [ "$1" = "cron" ]; then
		echolog "当前为计划任务自动运行，不重新配置定时任务。"
		return
	fi

	clean_crontab

	if [ "$ENABLED" != "1" ]; then
		[ -x /etc/init.d/cron ] && /etc/init.d/cron restart >/dev/null 2>&1
		return
	fi

	build_time() {
		local w="$1"
		local t="$2"
		local h m
		if echo "$t" | grep -q ':'; then
			h="${t%%:*}"
			m="${t##*:}"
		else
			h="$t"
			m=0
		fi
		h=$(printf '%s' "$h" | sed 's/^0*//')
		m=$(printf '%s' "$m" | sed 's/^0*//')
		h=$(printf '%d' "${h:-0}")
		m=$(printf '%d' "${m:-0}")
		local expr="$m $h * * $w"
		[ "$w" = "7" ] && expr="$m $h * * *"
		echo "$expr"
	}

	add_service_cron() {
		local week="$1"
		local time="$2"
		local action="$3"
		local logmsg="$4"
		[ -z "$week" ] && return
		local svr_t=$(build_time "$week" "$time")
		if [ "$week" = "8" ]; then
			update_loop=1
		else
			echo "$svr_t ${setsid_cmd}/etc/init.d/$CONFIG $action cron > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "$logmsg"
	}

	# ===== stop/start/restart =====
	add_service_cron "$(config_n_get @global_delay[0] stop_week_mode)" "$(config_n_get @global_delay[0] stop_time_mode)" "stop" "配置定时任务：自动关闭服务。"

	add_service_cron "$(config_n_get @global_delay[0] start_week_mode)" "$(config_n_get @global_delay[0] start_time_mode)" "start" "配置定时任务：自动开启服务。"

	add_service_cron "$(config_n_get @global_delay[0] restart_week_mode)" "$(config_n_get @global_delay[0] restart_time_mode)" "restart" "配置定时任务：自动重启服务。"

	# ===== rule update =====
	local rules_update_week_mode=$(config_n_get @global_rules[0] update_week_mode)
	local rules_update_time_mode=$(config_n_get @global_rules[0] update_time_mode)
	if [ -n "$rules_update_week_mode" ]; then
		local rule_t=$(build_time "$rules_update_week_mode" "$rules_update_time_mode")
		if [ "$rules_update_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$rule_t ${setsid_cmd}lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动更新规则。"
	fi

	# ===== loop =====
	if [ "$ENABLED_DEFAULT_ACL" = "1" ] || [ "$ENABLED_ACLS" = "1" ]; then
		if [ "$update_loop" = "1" ]; then
			$APP_PATH/tasks.sh > /dev/null 2>&1 &
			echolog "自动更新：启动循环更新进程。"
		fi
	else
		echolog "运行于非代理模式，仅允许服务启停的定时任务。"
	fi

	[ -x /etc/init.d/cron ] && /etc/init.d/cron restart >/dev/null 2>&1
}

stop_crontab() {
	[ "$1" = "cron" ] && return
	clean_crontab
	[ -x /etc/init.d/cron ] && /etc/init.d/cron restart >/dev/null 2>&1
	#echolog "清除定时执行命令。"
}

get_direct_dns_mode() {
	# SmartDNS 使用独立直连列表，其余 DNS 分流模式继续读取原来的设置。
	if [ "$ENABLED_DEFAULT_ACL" = "1" ] && [ "$DNS_SHUNT" = "smartdns" ]; then
		echo auto
	else
		config_n_get @global[0] direct_dns_mode "auto"
	fi
}

start_dns() {
	check_dns_config "${DNS_SHUNT:-dnsmasq}" "${DNS_MODE:-tcp}" global || return 1
	echolog "DNS域名解析："

	local china_ng_local_dns="${LOCAL_DNS}"
	local direct_dns_mode=$(get_direct_dns_mode)

	#获取访问控制节点所使用的DNS分流模式
	local ACL_RULE_DNSMASQ=0
	for acl_section in $(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		if [ "$(config_n_get $acl_section enabled)" = "1" ] && \
		   [ "$(config_n_get $acl_section dns_shunt)" = "dnsmasq" ]; then
			ACL_RULE_DNSMASQ=1
			break
		fi
	done

	case "$direct_dns_mode" in
		udp)
			LOCAL_DNS=$(normalize_dns "$(config_n_get @global[0] direct_dns 223.5.5.5:53)")
			set_cache_var "LOCAL_DNS" "$LOCAL_DNS"
			china_ng_local_dns=${LOCAL_DNS}
		;;
		tcp)	
			local DIRECT_DNS=$(normalize_dns "$(config_n_get @global[0] direct_dns 223.5.5.5:53)")
			china_ng_local_dns="tcp://${DIRECT_DNS}"

			# ChinaDNS-NG and SmartDNS can query TCP upstreams directly.
			if { [ "$DNS_SHUNT" != "chinadns-ng" ] && [ "$DNS_SHUNT" != "smartdns" ]; } || [ "$ACL_RULE_DNSMASQ" = "1" ]; then
				LOCAL_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
				set_cache_var "LOCAL_DNS" "$LOCAL_DNS"
				ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b :: -l ${NEXT_DNS_LISTEN_PORT} -c ${china_ng_local_dns} -d chn
				echolog "  - ChinaDNS-NG(${LOCAL_DNS}) -> ${china_ng_local_dns}"
				echolog "  * 请确保上游直连 DNS 支持 TCP 查询。"
				NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
			fi
		;;
		auto)
			#Automatic logic is already done by default
			:
		;;
	esac

	# 追加直连DNS到iptables/nftables
	add_default_port() {
		[ -z "$1" ] && echo "" || echo "$1" | awk -F',' '{for(i=1;i<=NF;i++){if($i !~ /#/) $i=$i"#53";} print $0;}' OFS=','
	}
	LOCAL_DNS=$(add_default_port "$LOCAL_DNS")
	set_cache_var "LOCAL_DNS" "$LOCAL_DNS"
	IPT_APPEND_DNS=$(add_default_port "${IPT_APPEND_DNS:-$LOCAL_DNS}")
	echo "$IPT_APPEND_DNS" | grep -q -E "(^|,)$LOCAL_DNS(,|$)" || IPT_APPEND_DNS="${IPT_APPEND_DNS:+$IPT_APPEND_DNS,}$LOCAL_DNS"
	[ -n "$DIRECT_DNS" ] && {
		DIRECT_DNS=$(add_default_port "$DIRECT_DNS")
		echo "$IPT_APPEND_DNS" | grep -q -E "(^|,)$DIRECT_DNS(,|$)" || IPT_APPEND_DNS="${IPT_APPEND_DNS:+$IPT_APPEND_DNS,}$DIRECT_DNS"
	}
	# 排除127.0.0.1的条目
	IPT_APPEND_DNS=$(echo "$IPT_APPEND_DNS" | awk -F',' '{for(i=1;i<=NF;i++) if($i !~ /^127\.0\.0\.1/) printf (i>1?",":"") $i; print ""}' | sed 's/^,\|,$//g')

	TUN_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"

	case "$DNS_MODE" in
	dns2socks)
		# DNS-H4-F2-C: on the frozen Global path the helper is the only default
		# upstream, and only a claim that still verifies may be consumed. The
		# check re-proves this generation, the published instance, the SOCKS
		# listener and the helper identity/listener right before publication.
		# A rejected claim publishes no upstream at all: no stale claim, no
		# legacy dns2socks fallback and no direct resolver substitution.
		if [ -n "$PW_GLOBAL_FROZEN" ]; then
			local helper_port=
			if ! passwall_check_dns_helper_ready global GLOBAL "${PW_SNAPSHOT_DIR:-}"; then
				echolog "DNS global rejected: DNS helper claim unusable (${PW_DNS_HELPER_REASON:-dns_dep_identity}, detail=${PW_DNS_HELPER_CHECK_DETAIL:-unknown}); no upstream published."
				return 1
			fi
			[ "$PW_DNS_HELPER_CLAIM_LISTEN_ADDR" = 127.0.0.1 ] || {
				echolog "DNS global rejected: DNS helper claim listen address is not loopback; no upstream published."
				return 1
			}
			helper_port=$PW_DNS_HELPER_CLAIM_LISTEN_PORT
			case "$helper_port" in
				''|*[!0-9]*) echolog "DNS global rejected: DNS helper claim listen port is unusable; no upstream published."; return 1 ;;
			esac
			# The frozen endpoint replaces the local dns2socks instance, so the
			# two never run as competing default upstreams.
			TUN_DNS="127.0.0.1#${helper_port}"
			echolog "  - DNS helper(${TUN_DNS})，helper 冻结端点 -> tcp://${REMOTE_DNS}"
		else
			local dns2socks_socks_server="$GLOBAL_SOCKS_server"
			[ -n "$dns2socks_socks_server" ] || { echolog "DNS global rejected: native SOCKS listener is unavailable."; return 1; }
			run_dns2socks socks=$dns2socks_socks_server listen_address=127.0.0.1 listen_port=${NEXT_DNS_LISTEN_PORT} dns=$REMOTE_DNS cache=$DNS_CACHE
			echolog "  - dns2socks(${TUN_DNS})，${dns2socks_socks_server} -> tcp://${REMOTE_DNS}"
		fi
	;;
	udp)
		UDP_PROXY_DNS=1
		local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
		local china_ng_trust_dns="udp://${REMOTE_DNS}"
		if [ "$DNS_SHUNT" != "chinadns-ng" ] && [ "$FILTER_PROXY_IPV6" = "1" ]; then
			DNSMASQ_FILTER_PROXY_IPV6=0
			local no_ipv6_trust="-N"
			ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b :: -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
			echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
		else
			TUN_DNS=${REMOTE_DNS}
			echolog "  - udp://${TUN_DNS}"
		fi
	;;
	tcp)
		TCP_PROXY_DNS=1
		local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
		local china_ng_trust_dns="tcp://${REMOTE_DNS}"
		[ "$DNS_SHUNT" != "chinadns-ng" ] && {
			[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0 && local no_ipv6_trust="-N"
			ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b :: -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
			echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
		}
	;;
	esac

	[ -n "${resolve_dns_log}" ] && echolog "  - ${resolve_dns_log}"

	[ -n "${TCP_PROXY_DNS}" ] && echolog "  * 请确认上游 DNS 支持 TCP/DoH 查询，如非直连地址，确保 TCP 代理打开，并且已经正确转发！"
	[ -n "${UDP_PROXY_DNS}" ] && echolog "  * 请确认上游 DNS 支持 UDP 查询并已使用 UDP 节点，如上游 DNS 非直连地址，确保 UDP 代理打开，并且已经正确转发！"

	local china_ng_listen=0
	[ "${DNS_SHUNT}" = "smartdns" ] && {
		local smartdns_bin=$(first_type smartdns)
		if [ -n "$smartdns_bin" ]; then
			rm -rf $TMP_PATH2/dnsmasq_default*
			local smartdns_remote_dns=$(config_n_get @global[0] smartdns_remote_dns)
			if [ -n "${smartdns_remote_dns}" ] && [ "${smartdns_remote_dns}" != "nil" ]; then
				smartdns_remote_dns=$(echo ${smartdns_remote_dns} | tr -s ' ' '|')
			else
				smartdns_remote_dns="tcp://1.1.1.1"
			fi
			local smartdns_default_dns=$(config_n_get @global[0] smartdns_default_dns direct)
			local smartdns_listen_port=$(get_new_port "$(expr $NEXT_DNS_LISTEN_PORT + 1)")
			[ -n "$smartdns_listen_port" ] || {
				echolog "  * SmartDNS 无法获取可用的 DNS 监听端口！"
				return 1
			}
			local smartdns_config="${GLOBAL_ACL_PATH}/smartdns.conf"
			local subnet_ip=$(config_n_get @global[0] remote_dns_client_ip)
			echolog "  - SmartDNS(127.0.0.1#${smartdns_listen_port})，直连 DNS：${SMARTDNS_DIRECT_DNS} -> 分组(direct)"
			[ "${SMARTDNS_LOCAL_PORT:-0}" != "0" ] && echolog "  - SmartDNS 直连入口：${LOCAL_DNS} -> 分组(direct)"

			lua "$APP_PATH/helper_smartdns_add.lua" -FLAG "default" \
				-LISTEN_PORT "$smartdns_listen_port" -DIRECT_DNS "$SMARTDNS_DIRECT_DNS" -LOCAL_PORT "${SMARTDNS_LOCAL_PORT:-0}" -DNS_REDIRECT "${DNS_REDIRECT}" \
				-REMOTE_PROXY_SERVER "${GLOBAL_SOCKS_server}" -USE_DEFAULT_DNS "${smartdns_default_dns}" \
				-REMOTE_DNS "${smartdns_remote_dns}" -DNS_MODE "${DNS_MODE:-socks}" -TUN_DNS "${TUN_DNS}" \
				-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
				-NODE "${NODE}" -DEFAULT_PROXY_MODE "${TCP_PROXY_MODE}" -NO_PROXY_IPV6 "${FILTER_PROXY_IPV6:-0}" -NFTFLAG "${nftflag:-0}" \
				-SUBNET "${subnet_ip:-0}" -NO_LOGIC_LOG "${NO_LOGIC_LOG:-0}" \
				-LOG "$(config_n_get @global[0] log_smartdns 0)" \
				-LOG_LEVEL "$(config_n_get @global[0] smartdns_log_level error)" \
				-LOG_SIZE "$(config_n_get @global[0] smartdns_log_size 1)" \
				-UI "$(config_n_get @global[0] smartdns_ui 0)" \
				-UI_PORT "$(config_n_get @global[0] smartdns_ui_port 9880)" \
				-UI_DATA_DIR "$(config_n_get @global[0] smartdns_ui_data_dir "$TMP_PATH2/smartdns")" \
				-UI_LOG_MAX_AGE "$(config_n_get @global[0] smartdns_ui_log_max_age 7)" || {
				echolog "  * SmartDNS 配置生成失败！"
				return 1
			}
			ln_run "$smartdns_bin" smartdns "/dev/null" -f -c "$smartdns_config" -p "${GLOBAL_ACL_PATH}/smartdns.pid"
			china_ng_listen="127.0.0.1#${smartdns_listen_port},::1#${smartdns_listen_port}"
			USE_DEFAULT_DNS="chinadns_ng"
		else
			DNS_SHUNT="dnsmasq"
			echolog "  * 未安装SmartDNS，默认使用Dnsmasq进行域名解析！"
		fi
	}

	[ "${DNS_SHUNT}" = "chinadns-ng" ] && [ -n "$(first_type chinadns-ng)" ] && {
		chinadns_ng_min=2024.04.13
		chinadns_ng_now=$($(first_type chinadns-ng) -V | grep -i "ChinaDNS-NG " | awk '{print $2}')
		if [ $(check_ver "$chinadns_ng_now" "$chinadns_ng_min") = 1 ]; then
			echolog "  * 注意：当前 ChinaDNS-NG 版本为[ $chinadns_ng_now ]，请更新到[ $chinadns_ng_min ]或以上版本，否则 DNS 有可能无法正常工作！"
		fi

		[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0
		[ -z "${china_ng_listen_port}" ] && local china_ng_listen_port=$(expr $NEXT_DNS_LISTEN_PORT + 1)
		china_ng_listen="127.0.0.1#${china_ng_listen_port}"
		[ -z "${china_ng_trust_dns}" ] && local china_ng_trust_dns=${TUN_DNS}

		echolog "  - ChinaDNS-NG(${china_ng_listen})：直连DNS：${china_ng_local_dns}，可信DNS：${china_ng_trust_dns}"

		china_ng_listen="${china_ng_listen},::1#${china_ng_listen_port}"

		run_chinadns_ng \
			_flag="default" \
			_listen_port=${china_ng_listen_port} \
			_dns_local=${china_ng_local_dns} \
			_dns_trust=${china_ng_trust_dns} \
			_no_ipv6_trust=${FILTER_PROXY_IPV6} \
			_use_direct_list=${USE_DIRECT_LIST} \
			_use_proxy_list=${USE_PROXY_LIST} \
			_use_block_list=${USE_BLOCK_LIST} \
			_gfwlist=${USE_GFW_LIST} \
			_chnlist=${CHN_LIST} \
			_default_mode=${TCP_PROXY_MODE} \
			_default_tag=$(config_n_get @global[0] chinadns_ng_default_tag smart) \
			_no_logic_log=0 \
			_node=${NODE} \
			_filter_https=$(config_n_get @global[0] force_https_soa 0) \
			_log=$(config_n_get @global[0] log_chinadns_ng 0)

		USE_DEFAULT_DNS="chinadns_ng"
	}

	[ "$USE_DEFAULT_DNS" = "remote" ] && {
		dnsmasq_version=$(dnsmasq -v | grep -i "Dnsmasq version " | awk '{print $3}')
		[ "$(check_ver "$dnsmasq_version" "2.87")" = "1" ] && echolog "Dnsmasq版本低于2.87，有可能无法正常使用！！！"
	}

	local DNSMASQ_TUN_DNS=$(normalize_dns $TUN_DNS 53)
	local RUN_NEW_DNSMASQ=1
	RUN_NEW_DNSMASQ=${DNS_REDIRECT}
	if [ "${RUN_NEW_DNSMASQ}" = "0" ]; then
		#The old logic will be removed in the future.
		#Run a copy dnsmasq instance, DNS hijack that don't need a proxy devices.
		[ "1" = "0" ] && {
			DIRECT_DNSMASQ_PORT=$(get_new_port 11400)
			DIRECT_DNSMASQ_CONF=${GLOBAL_ACL_PATH}/direct_dnsmasq.conf
			DIRECT_DNSMASQ_CONF_PATH=${GLOBAL_ACL_PATH}/direct_dnsmasq.d
			mkdir -p ${DIRECT_DNSMASQ_CONF_PATH}
			lua $APP_PATH/helper_dnsmasq.lua copy_instance -LISTEN_PORT ${DIRECT_DNSMASQ_PORT} -DNSMASQ_CONF ${DIRECT_DNSMASQ_CONF} -TMP_DNSMASQ_PATH ${DIRECT_DNSMASQ_CONF_PATH}
			ln_run "$(first_type dnsmasq)" "dnsmasq_direct" "/dev/null" -C ${DIRECT_DNSMASQ_CONF} -x ${GLOBAL_ACL_PATH}/direct_dnsmasq.pid
			echo "${DIRECT_DNSMASQ_PORT}" > ${GLOBAL_ACL_PATH}/direct_dnsmasq_port
		}

		#Rewrite the default DNS service configuration
		#Modify the default dnsmasq service
		lua $APP_PATH/helper_dnsmasq.lua stretch
		lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "default" -TMP_DNSMASQ_PATH ${GLOBAL_DNSMASQ_CONF_PATH} -DNSMASQ_CONF_FILE ${GLOBAL_DNSMASQ_CONF} \
			-DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS ${LOCAL_DNS} -TUN_DNS ${DNSMASQ_TUN_DNS} \
			-USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" -CHINADNS_DNS ${china_ng_listen:-0} \
			-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
			-NODE ${NODE} -DEFAULT_PROXY_MODE ${TCP_PROXY_MODE} -NO_PROXY_IPV6 ${DNSMASQ_FILTER_PROXY_IPV6:-0} -NFTFLAG ${nftflag:-0} \
			-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
		uci -q delete dhcp.@dnsmasq[0].min_cache_ttl
		uci -q add_list dhcp.@dnsmasq[0].addnmount=${GLOBAL_DNSMASQ_CONF_PATH}
		uci -q commit dhcp
		lua $APP_PATH/helper_dnsmasq.lua logic_restart -LOG 1
	elif [ "${DNS_SHUNT}" = "smartdns" ]; then
		# SmartDNS reads DHCP leases itself; no forwarding dnsmasq instance is needed.
		DNS_REDIRECT_PORT=${smartdns_listen_port}
		ACL_default_dns_port=${DNS_REDIRECT_PORT}
	else
		#Run a copy dnsmasq instance, DNS hijack for that need proxy devices.
		GLOBAL_DNSMASQ_PORT=$(get_new_port 11400)
		GLOBAL_DNSMASQ_CONF=${GLOBAL_ACL_PATH}/dnsmasq.conf
		GLOBAL_DNSMASQ_CONF_PATH=${GLOBAL_ACL_PATH}/dnsmasq.d
		lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "default" -TMP_DNSMASQ_PATH ${GLOBAL_DNSMASQ_CONF_PATH} -DNSMASQ_CONF_FILE ${GLOBAL_DNSMASQ_CONF} \
			-LISTEN_PORT ${GLOBAL_DNSMASQ_PORT} -DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS ${LOCAL_DNS} -TUN_DNS ${DNSMASQ_TUN_DNS} \
			-USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" -CHINADNS_DNS ${china_ng_listen:-0} \
			-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
			-NODE ${NODE} -DEFAULT_PROXY_MODE ${TCP_PROXY_MODE} -NO_PROXY_IPV6 ${DNSMASQ_FILTER_PROXY_IPV6:-0} -NFTFLAG ${nftflag:-0} \
			-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
		ln_run "$(first_type dnsmasq)" "dnsmasq_default" "/dev/null" -C ${GLOBAL_DNSMASQ_CONF} -x ${GLOBAL_ACL_PATH}/dnsmasq.pid
		ACL_default_dns_port=${GLOBAL_DNSMASQ_PORT}
		DNS_REDIRECT_PORT=${GLOBAL_DNSMASQ_PORT}
		#dhcp.leases to hosts
		$APP_PATH/lease2hosts.sh > /dev/null 2>&1 &
	fi
}

start_haproxy() {
	[ "$(config_n_get @global_haproxy[0] balancing_enable 0)" != "1" ] && return
	local haproxy_ver=$($(first_type haproxy) -v 2>/dev/null | awk 'NR==1 {print $3}' | cut -d'-' -f1)
	if [ "$(check_ver "$haproxy_ver" "3.0.0")" = "1" ]; then
		echolog "* 注意：haproxy($haproxy_ver) 程序版本低，HAPROXY 负载均衡启动失败，请更新到 3.0 以上版本。"
		return
	fi
	local haproxy_path=$TMP_PATH/haproxy
	local haproxy_conf="config.cfg"
	lua $APP_PATH/haproxy.lua -path ${haproxy_path} -conf ${haproxy_conf}
	ln_run "$(first_type haproxy)" haproxy "/dev/null" -f "${haproxy_path}/${haproxy_conf}"
}

# Return 2 only for publication errors whose per-ACL rollback fully succeeded.
# Other nonzero statuses mean the firewall cannot safely consume ACL state.
acl_app() {
	local items=$(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	if [ -z "$items" ]; then
		ENABLED_ACLS=0
		set_cache_var ENABLED_ACLS $ENABLED_ACLS || return 1
		return
	else
		local has_enabled
		local cache_publish_failed=0
		local sid
		local socks_port redir_port dns_port dnsmasq_port chinadns_port
		local msg msg2
		socks_port=11100
		redir_port=11200
		dns_port=11300
		dnsmasq_port=${GLOBAL_DNSMASQ_PORT:-11400}
		chinadns_port=11500
		for sid in $items; do
			[ "$(config_n_get $sid enabled)" = "1" ] || continue
			local check_node=$(config_n_get "$sid" node)
			local GLOBAL_NODE=$(get_cache_var "ACL_GLOBAL_node")
			local inherit_global=0 no_proxy=0
			if [ "$(config_n_get "$sid" use_global_config 0)" = 1 ] || [ "$check_node" = default ]; then
				check_node="$NODE"
				inherit_global=1
			fi
			[ -n "$GLOBAL_NODE" ] && [ "$check_node" = "$GLOBAL_NODE" ] && inherit_global=1
			# Match the firewall's effective mode before validating unused node/DNS fields.
			if [ "$(config_n_get "$sid" mode 0)" = 0 ] || { has_1_65535 "$(config_n_get "$sid" tcp_no_redir_ports "$TCP_NO_REDIR_PORTS")" && has_1_65535 "$(config_n_get "$sid" udp_no_redir_ports "$UDP_NO_REDIR_PORTS")"; }; then
				no_proxy=1
				check_node=
			fi
			if [ -n "$check_node" ] && ! check_node_supported "$check_node"; then
				fail_acl "$sid" "unsupported node $check_node" || return 1
				continue
			fi
			if [ -n "$check_node" ]; then
				if [ "$inherit_global" = 1 ]; then
					if [ "$(get_cache_var ACL_GLOBAL_failed)" = 1 ]; then
						fail_acl "$sid" "global proxy configuration failed" || return 1
						continue
					fi
				elif ! check_dns_config "$(config_n_get "$sid" dns_shunt dnsmasq)" "$(config_n_get "$sid" dns_mode dns2socks)" "$sid"; then
					fail_acl "$sid" "invalid DNS configuration" || return 1
					continue
				fi
			fi
			if [ -n "$check_node" ] && ! check_ss_node "$check_node"; then
				fail_ss_acl "$sid" "$check_node"
				continue
			fi
			if [ -n "$check_node" ] && [ "$(config_n_get "$check_node" type)" = Hysteria ] && ! check_hysteria_node "$check_node"; then
				fail_hysteria_acl "$sid" "$check_node"
				continue
			fi
			del_cache_var "ACL_${sid}_failed" || return 1
			# Republish inheritance only if this ACL actually reuses the current global.
			del_cache_var "ACL_${sid}_default" || return 1
			local acl_failed=0
			has_enabled=1
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)

			log=${log:-0}
			loglevel=${loglevel:-warn}
			log_chinadns_ng=${log_chinadns_ng:-0}

			if [ -n "${sources}" ]; then
				for s in $sources; do
					local s2
					is_iprange=$(lua_api "iprange(\"${s}\")")
					if [ "${is_iprange}" = "true" ]; then
						s2="iprange:${s}"
					elif [ -n "$(echo ${s} | grep '^ipset:')" ]; then
						s2="ipset:${s}"
					else
						_ip_or_mac=$(lua_api "ip_or_mac(\"${s}\")")
						if [ "${_ip_or_mac}" = "ip" ]; then
							s2="ip:${s}"
						elif [ "${_ip_or_mac}" = "mac" ]; then
							s2="mac:${s}"
						fi
					fi
					[ -n "${s2}" ] && source_list="${source_list}\n${s2}"
					unset s2
				done
			else
				source_list="any"
			fi

			local acl_path=${TMP_ACL_PATH}/$sid
			mkdir -p ${acl_path}
			[ -n "${source_list}" ] && printf "%b\n" "${source_list}" | sed '/^$/d' > ${acl_path}/source_list

			use_global_config=${use_global_config:-0}
			[ "${use_global_config}" = "1" ] && {
				node="default"
			}
			tcp_no_redir_ports=${tcp_no_redir_ports:-${TCP_NO_REDIR_PORTS}}
			udp_no_redir_ports=${udp_no_redir_ports:-${UDP_NO_REDIR_PORTS}}
			if [ "$no_proxy" = 1 ]; then
				# Clear only this ACL's published proxy state; shared instances stay owned.
				local key
				for key in node redir_port dns_port default fakedns; do
					del_cache_var "ACL_${sid}_${key}" || return 1
				done
				unset use_global_config
				unset node
			else
				use_direct_list=${use_direct_list:-1}
				use_proxy_list=${use_proxy_list:-1}
				use_block_list=${use_block_list:-1}
				use_gfw_list=${use_gfw_list:-1}
				chn_list=${chn_list:-direct}
				tcp_proxy_mode=${tcp_proxy_mode:-proxy}
				udp_proxy_mode=${udp_proxy_mode:-proxy}
				filter_proxy_ipv6=${filter_proxy_ipv6:-0}
				dnsmasq_filter_proxy_ipv6=${filter_proxy_ipv6}
				dns_shunt=${dns_shunt:-dnsmasq}
				dns_mode=${dns_mode:-dns2socks}
				remote_dns=$(normalize_dns "${remote_dns:-1.1.1.1}")
				use_default_dns=${use_default_dns:-direct}
			fi

			[ -n "$node" ] && {
				[ -n "${GLOBAL_NODE}" ] && {
					local GLOBAL_redir_port=$(get_cache_var "ACL_GLOBAL_redir_port")
					local GLOBAL_dns_port=$(get_cache_var "ACL_default_dns_port")
					[ "$node" = "${GLOBAL_NODE}" ] && node="default"
				}
				if [ "$node" = "default" ]; then
					if [ -n "${GLOBAL_NODE}" ]; then
						# DNS_REDIRECT=0 intentionally uses the system dnsmasq on port 53.
						[ "$DNS_REDIRECT" != 0 ] || GLOBAL_dns_port=${GLOBAL_dns_port:-53}
						if [ -z "$GLOBAL_redir_port" ] || [ -z "$GLOBAL_dns_port" ] || ! set_cache_vars \
							"ACL_${sid}_node" "$GLOBAL_NODE" \
							"ACL_${sid}_redir_port" "$GLOBAL_redir_port" \
							"ACL_${sid}_dns_port" "$GLOBAL_dns_port" \
							"ACL_${sid}_default" 1; then
							fail_acl "$sid" "cannot publish global inheritance" || return 1
							cache_publish_failed=2
							acl_failed=1
						fi
					else
						echolog "  - 全局节点未启用，跳过【${remarks}】"
					fi
				else
					([ "$(config_get_type $node)" = "nodes" ] || [ "$(config_get_type $node)" = "socks" ]) && {
						local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
						local dns_cache_str="${dns_mode}_${remote_dns}_${filter_proxy_ipv6}"
						dns_cache_key="$(echo -n "${dns_cache_str}" | md5sum | cut -d " " -f1)"


						run_dns() {
							local dns_fwd_port=$1
							[ -z "$dns_fwd_port" ] && {
								dns_port=$(get_new_port $(expr $dns_port + 1))
								dns_fwd_port=$dns_port
								if [ "$dns_mode" = "dns2socks" ]; then
									run_dns2socks flag=acl_${sid} socks_address=127.0.0.1 socks_port=$socks_port listen_address=0.0.0.0 listen_port=$dns_fwd_port dns=$remote_dns cache=1
								fi
								set_cache_var "node_${node}_${dns_cache_key}" "$dns_fwd_port"
							}

							[ "$dns_shunt" = "chinadns-ng" ] && [ -n "$(first_type chinadns-ng)" ] && {
								chinadns_ng_min=2024.04.13
								chinadns_ng_now=$($(first_type chinadns-ng) -V | grep -i "ChinaDNS-NG " | awk '{print $2}')
								if [ $(check_ver "$chinadns_ng_now" "$chinadns_ng_min") = 1 ]; then
									echolog "  * 注意：当前 ChinaDNS-NG 版本为[ $chinadns_ng_now ]，请更新到[ $chinadns_ng_min ]或以上版本，否则 DNS 有可能无法正常工作！"
								fi

								[ "$filter_proxy_ipv6" = "1" ] && dnsmasq_filter_proxy_ipv6=0
								chinadns_port=$(expr $chinadns_port + 1)
								_china_ng_listen="127.0.0.1#${chinadns_port},::1#${chinadns_port}"

								_chinadns_local_dns="${LOCAL_DNS}"
								_direct_dns_mode=$(get_direct_dns_mode)
								case "${_direct_dns_mode}" in
									udp)
										_chinadns_local_dns=$(normalize_dns "$(config_n_get @global[0] direct_dns 223.5.5.5:53)")
									;;
									tcp)
										_chinadns_local_dns="tcp://$(normalize_dns "$(config_n_get @global[0] direct_dns 223.5.5.5:53)")"
									;;
								esac

								run_chinadns_ng \
									_flag="$sid" \
									_listen_port=${chinadns_port} \
									_dns_local=${_chinadns_local_dns} \
									_dns_trust=127.0.0.1#${dns_fwd_port} \
									_no_ipv6_trust=${filter_proxy_ipv6} \
									_use_direct_list=${use_direct_list} \
									_use_proxy_list=${use_proxy_list} \
									_use_block_list=${use_block_list} \
									_gfwlist=${use_gfw_list} \
									_chnlist=${chn_list} \
									_default_mode=${tcp_proxy_mode} \
									_default_tag=${chinadns_ng_default_tag:-smart} \
									_no_logic_log=1 \
									_node=${node} \
									_filter_https=${force_https_soa:-0} \
									_log=${log_chinadns_ng}

								use_default_dns="chinadns_ng"
							}

							([ "$filter_proxy_ipv6" = "1" ] && [ "$dnsmasq_filter_proxy_ipv6" = "1" ]) && {
								dnsmasq_filter_proxy_ipv6=$(get_cache_var "node_${node}_${dns_cache_key}_ipv6")
								dnsmasq_filter_proxy_ipv6=${dnsmasq_filter_proxy_ipv6:-1}
							}

							dnsmasq_port=$(get_new_port $(expr $dnsmasq_port + 1))
							local dnsmasq_conf=${acl_path}/dnsmasq.conf
							local dnsmasq_conf_path=${acl_path}/dnsmasq.d
							lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG ${sid} -TMP_DNSMASQ_PATH ${dnsmasq_conf_path} -DNSMASQ_CONF_FILE ${dnsmasq_conf} \
								-LISTEN_PORT ${dnsmasq_port} -DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS $LOCAL_DNS \
								-USE_DIRECT_LIST "${use_direct_list}" -USE_PROXY_LIST "${use_proxy_list}" -USE_BLOCK_LIST "${use_block_list}" -USE_GFW_LIST "${use_gfw_list}" -CHN_LIST "${chn_list}" \
								-TUN_DNS "127.0.0.1#${dns_fwd_port}" -USE_DEFAULT_DNS "${use_default_dns:-direct}" -CHINADNS_DNS ${_china_ng_listen:-0} \
								-NODE $node -DEFAULT_PROXY_MODE ${tcp_proxy_mode} -NO_PROXY_IPV6 ${dnsmasq_filter_proxy_ipv6:-0} -NFTFLAG ${nftflag:-0} \
								-NO_LOGIC_LOG 1
							ln_run "$(first_type dnsmasq)" "dnsmasq_${sid}" "/dev/null" -C ${dnsmasq_conf} -x ${acl_path}/dnsmasq.pid
							set_cache_var "ACL_${sid}_dns_port" "${dnsmasq_port}"
							#dhcp.leases to hosts
							$APP_PATH/lease2hosts.sh > /dev/null 2>&1 &
						}
						local _redir_port=$(get_cache_var "acl_node_${node}_redir_port")
						local _socks_port=$(get_cache_var "acl_node_${node}_socks_port")
						local _enable_log=$(get_cache_var "acl_node_${node}_enable_log")
						local _dns_port
						if [ -n "${_socks_port}" ] && [ -n "${_redir_port}" ] && { { [ "$type" = hysteria ] && [ "${_enable_log}" = 1 ]; } || { [ "${_enable_log}" != 1 ] && [ "${log}" != 1 ]; }; }; then
							socks_port=${_socks_port}
							node_port=${_redir_port}
							_dns_port=$(get_cache_var "node_${node}_${dns_cache_key}")
							run_dns ${_dns_port}
						else
							socks_port=$(get_new_port $(expr $socks_port + 1))
							{ [ "$type" = ss ] || [ "$type" = hysteria ]; } || set_cache_var "acl_node_${node}_socks_port" "${socks_port}"
							redir_port=$(get_new_port $(expr $redir_port + 1))
							{ [ "$type" = ss ] || [ "$type" = hysteria ]; } || set_cache_var "acl_node_${node}_redir_port" "${redir_port}"
							node_port=$redir_port
							local log_file="/dev/null"
							[ "${log}" = "1" ] && {
								log_file="${TMP_ACL_PATH}/${sid}/node.log"
								{ [ "$type" = ss ] || [ "$type" = hysteria ]; } || set_cache_var "acl_node_${node}_enable_log" "1"
							}

							if [ "$type" = hysteria ]; then
								# Native v1 listeners allow the checked launcher to verify
								# every forwarding port; SOCKS remains available for DNS.
								config_file="acl/${node}_SOCKS_${socks_port}.json"
								if ! run_hysteria_acl "$node" "$config_file" "$redir_port" "$socks_port" "$log_file" "$loglevel"; then
									acl_failed=1
									fail_hysteria_acl "$sid" "$node" "$TMP_ACL_PATH/${node}_SOCKS_${socks_port}.json"
								fi
							else
								config_file="acl/${node}_SOCKS_${socks_port}.json"
								if ! run_socks flag=$node node=$node bind=127.0.0.1 socks_port=$socks_port config_file=$config_file log_file=$log_file loglevel=$loglevel; then
									if [ "$type" = ss ]; then
										acl_failed=1
										fail_ss_acl "$sid" "$node" "$config_file"
									fi
								fi
								# log_file=$TMP_ACL_PATH/ipt2socks_${node}_${redir_port}.log
								log_file="/dev/null"
								[ "$acl_failed" = 1 ] || run_ipt2socks flag=acl_${node} tcp_tproxy=${is_tproxy} local_port=$redir_port socks_address=127.0.0.1 socks_port=$socks_port log_file=$log_file
							fi
							if { [ "$type" = ss ] || [ "$type" = hysteria ]; } && [ "$acl_failed" != 1 ]; then
								set_cache_var "acl_node_${node}_socks_port" "$socks_port"
								set_cache_var "acl_node_${node}_redir_port" "$redir_port"
								[ "$log" != 1 ] || set_cache_var "acl_node_${node}_enable_log" 1
							fi
							[ "$acl_failed" = 1 ] || run_dns ${_dns_port}
						fi
						if [ "$acl_failed" != 1 ]; then
							set_cache_var "ACL_${sid}_node" "${node}"
							set_cache_var "ACL_${sid}_redir_port" "${node_port}"
						fi
					}
				fi
				[ "$acl_failed" != 1 ] && [ "${use_fakedns}" = "1" ] && set_cache_var "ACL_${sid}_fakedns" "1"
			}
			unset enabled sid remarks sources interface tcp_no_redir_ports udp_no_redir_ports use_global_config node use_direct_list use_proxy_list use_block_list use_gfw_list chn_list tcp_proxy_mode udp_proxy_mode filter_proxy_ipv6 dns_mode remote_dns
			unset _ip _mac _iprange _ipset _ip_or_mac source_list node_port config_file _extra_param dns_cache_key log loglevel log_chinadns_ng
			unset _china_ng_listen _chinadns_local_dns _direct_dns_mode chinadns_ng_default_tag dnsmasq_filter_proxy_ipv6 remote_fakedns force_https_soa use_fakedns remote_rewrite_ttl dns_shunt use_default_dns
		done
		unset socks_port redir_port dns_port dnsmasq_port chinadns_port
		[ -n "${has_enabled}" ] || {
			ENABLED_ACLS=0
			set_cache_var ENABLED_ACLS $ENABLED_ACLS || return 1
		}
		return "$cache_publish_failed"
	fi
}

start() {
	busybox pgrep -f ${TMP_PATH}/bin > /dev/null 2>&1 && {
		logger -t PSW-RESTART "Upgrade or overload residue is detected, and the subprocess is being called to perform complete cleaning..."
		(stop "$1")
		sleep 2
	}
	mkdir -p /tmp/etc /tmp/log $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2
	# Only start_global/start_dns below may publish this run's global endpoint.
	# Preserve independent SOCKS services, device ACLs and shared node caches.
	local key
	for key in ACL_GLOBAL_node ACL_GLOBAL_redir_port ACL_default_dns_port GLOBAL_SOCKS_server ACL_GLOBAL_failed; do
		del_cache_var "$key" || return 1
	done
	# Enabled is a success marker, published with the endpoint after DNS completes.
	set_cache_vars LOCAL_DNS "$LOCAL_DNS" ENABLED_DEFAULT_ACL 0 || return 1
	get_config || return 1
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] && ! check_dns_config "${DNS_SHUNT:-dnsmasq}" "${DNS_MODE:-tcp}" global; then
		ENABLED_DEFAULT_ACL=0
		set_cache_vars ENABLED_DEFAULT_ACL 0 ACL_GLOBAL_failed 1 || return 1
	fi
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] && ! check_node_supported "$NODE"; then
		ENABLED_DEFAULT_ACL=0
		set_cache_vars ENABLED_DEFAULT_ACL 0 ACL_GLOBAL_failed 1 || return 1
	fi
	# Reject invalid SS configuration before starting any client processes or DNS.
	# Keep independent SOCKS services and valid device ACLs available.
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] && ! check_ss_node "$NODE"; then
		ENABLED_DEFAULT_ACL=0
		set_cache_vars ENABLED_DEFAULT_ACL 0 ACL_GLOBAL_failed 1 || return 1
		echolog "Global SS node ${NODE} rejected; global transparent proxy disabled."
	fi
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] && [ "$(config_n_get "$NODE" type)" = Hysteria ] && ! check_hysteria_node "$NODE"; then
		ENABLED_DEFAULT_ACL=0
		set_cache_vars ENABLED_DEFAULT_ACL 0 ACL_GLOBAL_failed 1 || return 1
	fi
	export SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN=1
	ulimit -n 65535
	start_haproxy
	start_socks
	nftflag=0
	USE_TABLES=""
	check_run_environment
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] || [ "$ENABLED_ACLS" = 1 ]; then
		[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect)" = "1" ] && {
			uci -q set ${CONFIG}.@global[0].dnsmasq_dns_redirect='1'
			uci -q commit ${CONFIG}
			uci -q set dhcp.@dnsmasq[0].dns_redirect='0'
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		}
	fi
	[ "$ENABLED_DEFAULT_ACL" = 1 ] && {
		mkdir -p ${GLOBAL_ACL_PATH}
		# Exactly one launcher starts the Global SOCKS owner: the frozen bound
		# path for a canonical section, the legacy merged-node path otherwise.
		if [ -n "$PW_GLOBAL_FROZEN" ]; then
			start_global_frozen
		else
			start_global
		fi || {
			if [ "$(config_n_get "$NODE" type)" = Hysteria ]; then
				ENABLED_DEFAULT_ACL=0
				set_cache_vars ENABLED_DEFAULT_ACL 0 ACL_GLOBAL_failed 1 || return 1
			else
				echolog "全局节点启动失败，停止服务。"
				stop
				return 1
			fi
		}
		[ "$ENABLED_DEFAULT_ACL" != 1 ] || start_dns || {
			echolog "DNS 启动失败，停止服务。"
			stop
			return 1
		}
		if [ "$ENABLED_DEFAULT_ACL" = 1 ]; then
			if [ -z "$NODE" ] || [ -z "$REDIR_PORT" ] || [ -z "$GLOBAL_SOCKS_server" ] ||
				{ [ "$DNS_REDIRECT" != 0 ] && [ -z "$ACL_default_dns_port" ]; } || ! set_cache_vars \
				ACL_GLOBAL_redir_port "$REDIR_PORT" \
				ACL_default_dns_port "$ACL_default_dns_port" \
				GLOBAL_SOCKS_server "$GLOBAL_SOCKS_server" \
				ACL_GLOBAL_node "$NODE" ENABLED_DEFAULT_ACL 1; then
				ENABLED_DEFAULT_ACL=0
				echolog "Global cache publication failed; aborting firewall initialization."
				return 1
			fi
		fi
	}
	set_cache_vars USE_TABLES "$USE_TABLES" || return 1
	local firewall_status=0
	if [ -n "$USE_TABLES" ]; then
		source $APP_PATH/${USE_TABLES}.sh start || firewall_status=$?
		case "$firewall_status" in 0|2) ;; *) return 1 ;; esac
	fi
	if [ "$ENABLED_DEFAULT_ACL" = 1 ] || [ "$ENABLED_ACLS" = 1 ]; then
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		set_cache_var "bak_bridge_nf_ipt" "$bridge_nf_ipt"
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" = "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			set_cache_var "bak_bridge_nf_ip6t" "$bridge_nf_ip6t"
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	fi

	start_crontab "$1"
	if [ "$firewall_status" = 2 ]; then
		echolog "Startup completed with isolated ACL cache publication failures."
		return 1
	fi
	echolog "运行完成！\n"

}

stop() {
	local hysteria_cleanup_status=0 dns_helper_cleanup_status=0 frozen_cleanup_status=0 acl_dir acl_sid
	# Contract 5.2 item 4: stop every scope's DNS helper before the instances it
	# depends on and the scope directories are released. Scope-local and
	# idempotent, so a stop with no helper records changes nothing here.
	stop_scope_dns_helper global || dns_helper_cleanup_status=1
	if [ -n "${TMP_ACL_PATH:-}" ] && [ -d "$TMP_ACL_PATH" ]; then
		for acl_dir in "$TMP_ACL_PATH"/*; do
			[ -d "$acl_dir" ] && [ ! -L "$acl_dir" ] || continue
			acl_sid=${acl_dir##*/}
			case "$acl_sid" in default|*[!A-Za-z0-9_]*) continue ;; esac
			stop_scope_dns_helper acl "$acl_sid" || dns_helper_cleanup_status=1
		done
	fi
	[ "$dns_helper_cleanup_status" = 0 ] || echolog "DNS helper cleanup pending; runtime records retained."
	# Frozen Global instances are stopped through their own identity records,
	# before the runtime tree that holds those records is removed. A cold stop
	# has no split directory and therefore nothing to reclaim here.
	if [ -n "${GLOBAL_ACL_PATH:-}" ] && [ -d "$GLOBAL_ACL_PATH/split" ]; then
		passwall_stop_global_nodes || frozen_cleanup_status=1
		[ "$frozen_cleanup_status" = 0 ] || echolog "Frozen global cleanup pending; instance records retained."
	fi
	[ ! -f "$HYSTERIA_RUNTIME" ] || lua "$HYSTERIA_RUNTIME" stop client || hysteria_cleanup_status=1
	[ "$hysteria_cleanup_status" = 0 ] || echolog "Hysteria cleanup pending; retry stop after resolving the error."
	clean_log
	eval_cache_var
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh stop
	delete_ip2route
	# 结束 SS 插件进程
	# kill_all xray-plugin v2ray-plugin obfs-local shadow-tls
	local pid_file pid
	find "$TMP_PATH" -type f -name '*_plugin.pid' 2>/dev/null | while read -r pid_file; do
		read -r pid < "$pid_file"
		if [ -n "$pid" ]; then
			kill -9 "$pid" >/dev/null 2>&1
		fi
	done
	busybox pgrep -af "${CONFIG}/monitor\.sh" | xargs -r kill -9 >/dev/null 2>&1
	busybox pgrep -f "sleep.*(6s|9s|58s)" | xargs -r kill -9 >/dev/null 2>&1
	busybox pgrep -af "${CONFIG}/" | awk '! /app\.sh|rule_update\.lua|tasks\.sh|server_app\.lua|ujail/{print $1}' | xargs -r kill -9 >/dev/null 2>&1
	unset SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN
	stop_crontab "$1"
	rm -rf $GLOBAL_DNSMASQ_CONF
	rm -rf $GLOBAL_DNSMASQ_CONF_PATH
	[ "1" = "1" ] && {
		#restore logic
		bak_dnsmasq_dns_redirect=$(config_n_get @global[0] dnsmasq_dns_redirect)
		[ -n "${bak_dnsmasq_dns_redirect}" ] && {
			uci -q set dhcp.@dnsmasq[0].dns_redirect="${bak_dnsmasq_dns_redirect}"
			uci -q commit dhcp
			uci -q delete ${CONFIG}.@global[0].dnsmasq_dns_redirect
			uci -q commit ${CONFIG}
		}
		if [ -z "${ACL_default_dns_port}" ] || [ -n "${bak_dnsmasq_dns_redirect}" ]; then
			uci -q del_list dhcp.@dnsmasq[0].addnmount="${GLOBAL_DNSMASQ_CONF_PATH}"
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		fi
		[ -n "${bak_bridge_nf_ipt}" ] && sysctl -w net.bridge.bridge-nf-call-iptables=${bak_bridge_nf_ipt} >/dev/null 2>&1
		[ -n "${bak_bridge_nf_ip6t}" ] && sysctl -w net.bridge.bridge-nf-call-ip6tables=${bak_bridge_nf_ip6t} >/dev/null 2>&1
	}
	# Removing the runtime tree would also delete any identity record a helper or
	# instance still needs to be stopped later, so it is skipped while one is
	# unconfirmed.
	if [ "$dns_helper_cleanup_status" = 0 ] && [ "$frozen_cleanup_status" = 0 ]; then
		rm -rf $TMP_PATH
	else
		echolog "Runtime cache kept: an unstopped DNS helper or global instance still needs its records."
	fi
	echolog "清空并关闭相关程序和缓存完成。"
	[ "$dns_helper_cleanup_status" = 0 ] || hysteria_cleanup_status=1
	[ "$frozen_cleanup_status" = 0 ] || hysteria_cleanup_status=1
	# Return, never exit: start() calls stop() on its failure paths and must still
	# reach its own non-zero return, which a script-wide exit here would swallow
	# and report a refused start as success. The top-level `stop` entry is
	# unaffected: its dispatch case is the last statement, so this status becomes
	# the script's exit status exactly as the exit did.
	return "$hysteria_cleanup_status"
}

get_config() {
	ENABLED_DEFAULT_ACL=0
	REDIR_PORT=$(echo $(get_new_port 1041 tcp,udp))
	ENABLED=$(config_n_get @global[0] enabled 0)
	SOCKS_ENABLED=$(config_n_get @global[0] socks_enabled 0)
	NODE=$(config_n_get @global[0] node)
	# A canonical section carries no merged selector; its TCP node is the scope's
	# proxy node for every consumer that still reads a single one. The schemas
	# are mutually exclusive, which is what keeps exactly one Global launcher.
	PW_GLOBAL_FROZEN=
	if [ -z "$NODE" ]; then
		NODE=$(config_n_get @global[0] tcp_node)
		[ -z "$NODE" ] || PW_GLOBAL_FROZEN=1
	fi

	[ "$ENABLED" = 1 ] && {
		if [ -n "$NODE" ] && ([ "$(config_get_type $NODE)" = "nodes" ] || [ "$(config_get_type $NODE)" = "socks" ]); then
			ENABLED_DEFAULT_ACL=1
		fi
	}
	ENABLED_ACLS=$(config_n_get @global[0] acl_enable 0)
	# The global enabled marker is committed by start() with its complete endpoint.
	set_cache_var ENABLED_ACLS "$ENABLED_ACLS" || return 1

	TCP_PROXY_WAY=$(config_n_get @global_forwarding[0] tcp_proxy_way redirect)
	PROXY_IPV6=$(config_n_get @global_forwarding[0] ipv6_tproxy 0)
	TCP_REDIR_PORTS=$(config_n_get @global_forwarding[0] tcp_redir_ports '80,443')
	UDP_REDIR_PORTS=$(config_n_get @global_forwarding[0] udp_redir_ports '1:65535')
	TCP_NO_REDIR_PORTS=$(config_n_get @global_forwarding[0] tcp_no_redir_ports 'disable')
	UDP_NO_REDIR_PORTS=$(config_n_get @global_forwarding[0] udp_no_redir_ports 'disable')
	TCP_PROXY_DROP_PORTS=$(config_n_get @global_forwarding[0] tcp_proxy_drop_ports 'disable')
	UDP_PROXY_DROP_PORTS=$(config_n_get @global_forwarding[0] udp_proxy_drop_ports '80,443')
	USE_DIRECT_LIST=$(config_n_get @global[0] use_direct_list 1)
	USE_PROXY_LIST=$(config_n_get @global[0] use_proxy_list 1)
	USE_BLOCK_LIST=$(config_n_get @global[0] use_block_list 1)
	USE_GFW_LIST=$(config_n_get @global[0] use_gfw_list 1)
	CHN_LIST=$(config_n_get @global[0] chn_list direct)
	TCP_PROXY_MODE=$(config_n_get @global[0] tcp_proxy_mode proxy)
	UDP_PROXY_MODE=$(config_n_get @global[0] udp_proxy_mode proxy)
	[ "${TCP_PROXY_MODE}" != "disable" ] && TCP_PROXY_MODE="proxy"
	[ "${UDP_PROXY_MODE}" != "disable" ] && UDP_PROXY_MODE="proxy"
	LOCALHOST_PROXY=$(config_n_get @global[0] localhost_proxy 1)
	[ "${LOCALHOST_PROXY}" = 1 ] && {
		LOCALHOST_TCP_PROXY_MODE=$TCP_PROXY_MODE
		LOCALHOST_UDP_PROXY_MODE=$UDP_PROXY_MODE
	}
	CLIENT_PROXY=$(config_n_get @global[0] client_proxy 1)
	DNS_SHUNT=$(config_n_get @global[0] dns_shunt dnsmasq)
	[ -z "$(first_type $DNS_SHUNT)" ] && DNS_SHUNT="dnsmasq"
	DNS_MODE=$(config_n_get @global[0] dns_mode tcp)
	[ "$DNS_SHUNT" = "smartdns" ] && DNS_MODE=$(config_n_get @global[0] smartdns_dns_mode socks)
	REMOTE_DNS=$(normalize_dns "$(config_n_get @global[0] remote_dns 1.1.1.1)")
	USE_DEFAULT_DNS=$(config_n_get @global[0] use_default_dns direct)
	FILTER_PROXY_IPV6=$(config_n_get @global[0] filter_proxy_ipv6 0)
	DNS_REDIRECT=$(config_n_get @global[0] dns_redirect 1)

	REDIRECT_LIST="ss ss-rust ssr naiveproxy hysteria"
	TPROXY_LIST="ss ss-rust ssr hysteria"

	NEXT_DNS_LISTEN_PORT=$(get_new_port 15353 tcp,udp)
	TUN_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
	DNS_CACHE=0
	DIRECT_DNS_QUERY_STRATEGY="UseIP"
	REMOTE_DNS_QUERY_STRATEGY="UseIP"
	[ "$FILTER_PROXY_IPV6" = "1" ] && REMOTE_DNS_QUERY_STRATEGY="UseIPv4"
	DNSMASQ_FILTER_PROXY_IPV6=${FILTER_PROXY_IPV6}

	IPT_APPEND_DNS=${LOCAL_DNS}

	DNSMASQ_CONF_DIR=/tmp/dnsmasq.d
	DEFAULT_DNSMASQ_CFGID="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"
	if [ -f "/var/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID" ]; then
		DNSMASQ_CONF_DIR="$(awk -F '=' '/^conf-dir=/ {print $2}' "/var/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID")"
		if [ -n "$DNSMASQ_CONF_DIR" ]; then
			DNSMASQ_CONF_DIR=${DNSMASQ_CONF_DIR%*/}
		else
			DNSMASQ_CONF_DIR="/tmp/dnsmasq.d"
		fi
	fi
	set_cache_vars GLOBAL_DNSMASQ_CONF "${DNSMASQ_CONF_DIR}/dnsmasq-${CONFIG}.conf" \
		GLOBAL_DNSMASQ_CONF_PATH "${GLOBAL_ACL_PATH}/dnsmasq.d" || return 1

	SMARTDNS_LOCAL_PORT=0
	SMARTDNS_DIRECT_DNS=
	if [ "$ENABLED_DEFAULT_ACL" = "1" ] && [ "$DNS_SHUNT" = "smartdns" ]; then
		# 显式列出空白字符，兼容未启用字符类支持的 BusyBox tr。
		SMARTDNS_DIRECT_DNS=$(config_n_get @global[0] smartdns_direct_dns | tr -s ' \t\r\n\v\f' '|' | sed 's/^|//;s/|$//')
		[ "$SMARTDNS_DIRECT_DNS" = "nil" ] && SMARTDNS_DIRECT_DNS=
		if [ -z "$SMARTDNS_DIRECT_DNS" ]; then
			SMARTDNS_DIRECT_DNS="$LOCAL_DNS"
		else
			local smartdns_single_dns="${SMARTDNS_DIRECT_DNS%%,*}"
			local smartdns_protocol=udp
			case "$smartdns_single_dns" in
				*://*)
					smartdns_protocol=$(printf '%s' "${smartdns_single_dns%%://*}" | tr 'A-Z' 'a-z')
					smartdns_single_dns="${smartdns_single_dns#*://}"
				;;
			esac
			if [ "${SMARTDNS_DIRECT_DNS#*|}" = "$SMARTDNS_DIRECT_DNS" ] && [ "$smartdns_protocol" = "udp" ]; then
				LOCAL_DNS=$(normalize_dns "$smartdns_single_dns" 53)
				local smartdns_host_ip="${SMARTDNS_DIRECT_DNS#*,}"
				[ "$smartdns_host_ip" != "$SMARTDNS_DIRECT_DNS" ] && [ -n "$smartdns_host_ip" ] && \
					LOCAL_DNS=$(normalize_dns "$smartdns_host_ip" "${LOCAL_DNS##*#}")
			else
				SMARTDNS_LOCAL_PORT=${NEXT_DNS_LISTEN_PORT}
				NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
				LOCAL_DNS="127.0.0.1#${SMARTDNS_LOCAL_PORT}"
			fi
		fi
		set_cache_var "LOCAL_DNS" "$LOCAL_DNS" || return 1
	fi
}

get_local_dns() {
	RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
	[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto

	ISP_DNS=$(grep -Eo "$IPv4_REGEX" "$RESOLVFILE" 2>/dev/null | grep -Ev '^(0\.0\.0\.0|127\.0\.0\.1)$' | awk '!seen[$0]++')
	ISP_DNS6=$(grep -Eo "$IPv6_REGEX" "$RESOLVFILE" 2>/dev/null | awk -F% '{print $1}' | grep -Ev '^::1$|^::$' | awk '!seen[$0]++')

	DEFAULT_DNS=$(uci show dhcp.@dnsmasq[0] | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | sed ':label;N;s/\n/,/;b label')
	[ -z "${DEFAULT_DNS}" ] && [ "$(echo $ISP_DNS | tr ' ' '\n' | wc -l)" -ge 1 ] && DEFAULT_DNS=$(echo -n $ISP_DNS | tr ' ' '\n' | tr '\n' ',' | sed 's/,$//')
	LOCAL_DNS="${DEFAULT_DNS:-223.5.5.5}"
	LOCAL_DNS="${LOCAL_DNS%%,*}"
}

get_local_dns

arg1=$1
shift
case $arg1 in
run_socks)
	run_socks "$@"
	;;
socks_node_switch)
	socks_node_switch "$@"
	;;
start)
	start "$@"
	;;
stop)
	stop "$@"
	;;
esac
