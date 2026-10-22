#!/bin/sh
# B3.3-2 explicit adapters only. Caller loads snapshot/B1/B2/B3.1 under the
# lifecycle lock. No source/call in app.sh, init, firewall, LuCI or DNS.

_pw_bound_helper() {
	[ -n "${PW_BOUND_HELPER:-}" ] || return 1
	lua "$PW_BOUND_HELPER" "$@"
}

_pw_bound_fresh() {
	[ -n "${PW_BOUND_SNAPSHOT:-}" ] && passwall_snapshot_check "$PW_BOUND_SNAPSHOT"
}

_pw_bound_prepare() {
	if [ "$PW_BOUND_FAMILY" != 4 ] && [ -n "$(sed -n '3p' "$2/meta")" ] && [ "$TCP_PROXY_WAY" != tproxy ]; then
		echolog 'Bound runtime: IPv6 TCP requires TPROXY.'; return 1
	fi
	_pw_bound_fresh && _pw_bound_helper prepare "$PW_BOUND_SNAPSHOT" "$1" "$PW_BOUND_PREFERENCE" "$PW_BOUND_FAMILY" "$2" "$3"
}

_pw_bound_hysteria() {
	local app bin
	app=$(sed -n 's/^[^.]*\.\([^.=]*\)=global_app$/\1/p' "$PW_BOUND_SNAPSHOT/view") || return 1
	[ "$(printf '%s\n' "$app" | wc -l)" = 1 ] || return 1
	bin=$(_pw_snapshot_option "$PW_BOUND_SNAPSHOT" "$app" hysteria_file) || return 1
	_pw_bound_helper hysteria "$1" "$(first_type "${bin:-hysteria}")" "$TMP_BIN_PATH" "$2" "$3"
}

_pw_bound_ready() {
	local instance="$1"
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then
		_pw_bound_helper compatible "$instance" "$PW_BOUND_SNAPSHOT" "$PW_BOUND_PREFERENCE" "$PW_BOUND_FAMILY"
	else _pw_bound_helper verify "$instance"; fi
}

_pw_bound_seal() {
	_pw_bound_fresh && _pw_bound_helper seal "$1"
}

_pw_bound_reference() {
	_pw_bound_fresh && _pw_bound_helper reference "$1" "$PW_BOUND_SNAPSHOT" "$PW_BOUND_PREFERENCE" "$PW_BOUND_FAMILY"
}

passwall_start_bound_global_nodes() {
	[ "$#" = 3 ] || return 1
	case "$2" in ipv4|ipv6|ipv4-only|ipv6-only) ;; *) return 1 ;; esac
	case "$3" in 4|6|dual) ;; *) return 1 ;; esac
	local PW_BOUND_SNAPSHOT="$1" PW_BOUND_PREFERENCE="$2" PW_BOUND_FAMILY="$3"
	local PROXY_IPV6=0
	[ "$3" = 4 ] || PROXY_IPV6=1
	_pw_bound_fresh && passwall_snapshot_pair "$1" global || return 1
	[ "$PW_SNAPSHOT_ENABLED" = 1 ] || { passwall_start_global_nodes '' ''; return; }
	passwall_start_global_nodes "$PW_SNAPSHOT_TCP" "$PW_SNAPSHOT_UDP_RAW"
}

passwall_start_bound_acl_nodes() {
	[ "$#" = 6 ] || return 1
	case "$3" in ipv4|ipv6|ipv4-only|ipv6-only) ;; *) return 1 ;; esac
	case "$4" in 4|6|dual) ;; *) return 1 ;; esac
	local PW_BOUND_SNAPSHOT="$1" PW_BOUND_PREFERENCE="$3" PW_BOUND_FAMILY="$4"
	local mode inherit tcp udp proto requested state result=0 PROXY_IPV6=0
	[ "$4" = 4 ] || PROXY_IPV6=1
	_pw_bound_fresh && passwall_snapshot_pair "$1" acl "$2" || return 1
	if [ "$PW_SNAPSHOT_ENABLED" != 1 ]; then passwall_stop_acl_nodes "$2"; return; fi
	mode=$(_pw_snapshot_option "$1" "$2" mode) && inherit=$(_pw_snapshot_option "$1" "$2" use_global_config) || return 1
	tcp=$PW_SNAPSHOT_TCP; udp=$PW_SNAPSHOT_UDP
	passwall_start_acl_nodes "$2" "$mode" "$inherit" "$PW_SNAPSHOT_TCP_RAW" "$PW_SNAPSHOT_UDP_RAW" "$5" "$6" || result=$?
	[ "$result" != 1 ] || return 1
	for proto in tcp udp; do
		requested=$tcp; [ "$proto" = tcp ] || requested=$udp
		state=$(passwall_acl_protocol_state "$2" "$proto" "$requested") || return 1
		[ "$state" != failed ] || result=2
	done
	[ "$result" != 2 ] || set_cache_vars "ACL_${2}_split_failed" 1 || return 1
	return "$result"
}
