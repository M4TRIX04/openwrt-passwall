#!/bin/sh
# B3.3-3B: definitions only; never sourced by a production entry point.
# Caller holds the existing lifecycle lock and loads B1/snapshot/B2/B3.1/bound.
# resolve/validate SNAPSHOT global|acl GLOBAL|SID PREFERENCE 4|6|dual [APPLICABILITY]
# Results (reset on every call): PW_DNS_DEP_JSON, PW_DNS_DEP_STATE,
# PW_DNS_DEP_REASON. No stdout, persistence, helper ports or resource creation.
# 0=candidate success (NOT consumable), 2=isolated rejection, 1=untrusted
# arguments/snapshot/cache/identity. APPLICABILITY defaults to proxy. The explicit
# not_applicable value is RESERVED for B4, not a supported DNS product mode:
# rc=0, empty state/reason, proxy_required=false. No dns_mode local/direct support.

_pw_dns_dep_error() {
	PW_DNS_DEP_STATE=
	PW_DNS_DEP_REASON=$2
	return "$1"
}

_pw_dns_dependency() {
	PW_DNS_DEP_JSON= PW_DNS_DEP_STATE= PW_DNS_DEP_REASON=dns_dep_argument
	{ [ "$#" = 6 ] || [ "$#" = 7 ]; } || return 1
	local action="$1" snapshot="$2" role="$3" sid="$4" preference="$5" family="$6"
	local applicability="${7:-proxy}" global source enabled mode inherit=0 tcp shunt dns_mode remote cache
	local prefix node port config instance result rc=0 gn gp gi default scope="$role:$sid"
	[ "$role" != global ] || scope=global
	case "$action" in resolve|validate) ;; *) return 1 ;; esac
	case "$preference" in ipv4|ipv6|ipv4-only|ipv6-only) ;; *) return 1 ;; esac
	case "$family" in 4|6|dual) ;; *) return 1 ;; esac
	case "$applicability" in proxy|not_applicable) ;; *) return 1 ;; esac
	case "$role:$sid" in global:GLOBAL) ;; acl:*) _pw_acl_id "$sid" || return 1 ;; *) return 1 ;; esac
	[ -n "${PW_DEPENDENCY_HELPER:-}" ] || return 1
	passwall_snapshot_check "$snapshot" || { _pw_dns_dep_error 1 dns_dep_stale_generation; return; }
	PW_DNS_DEP_REASON=dns_dep_identity
	global=$(cat "$snapshot/global") || return 1
	[ "$role" != acl ] || grep -Fxq "$sid" "$snapshot/acls" || return 1
	if [ "$applicability" = not_applicable ]; then
		PW_DNS_DEP_REASON=
		PW_DNS_DEP_JSON=$(printf '{"scope":"%s","generation":"%s","family":"%s","applicability":"reserved","proxy_required":false}' "$scope" "${snapshot##*/}" "$family")
		return 0
	fi
	source=$global
	if [ "$role" = acl ]; then
		source=$sid
		# Do not call snapshot_pair ACL for inheritance: it reads the ACL's
		# ignored node selectors. Resolve the global intent directly instead.
		mode=$(_pw_snapshot_option "$snapshot" "$sid" mode) &&
			inherit=$(_pw_snapshot_option "$snapshot" "$sid" use_global_config) &&
			enabled=$(_pw_snapshot_option "$snapshot" "$sid" enabled) || return 1
		case "${mode:-0}:${inherit:-0}:${enabled:-0}" in
			[01]:[01]:[01]) ;; *) return 1 ;;
		esac
		[ "${mode:-0}:${inherit:-0}" != 1:1 ] || source=$global
	fi
	shunt=$(_pw_snapshot_option "$snapshot" "$source" dns_shunt) &&
		dns_mode=$(_pw_snapshot_option "$snapshot" "$source" dns_mode) &&
		remote=$(_pw_snapshot_option "$snapshot" "$source" remote_dns) &&
		cache=$(_pw_snapshot_option "$snapshot" "$source" dns_cache) || return 1
	shunt=${shunt:-dnsmasq}
	if [ -z "$dns_mode" ]; then
		if [ "$source" = "$global" ]; then dns_mode=tcp; else dns_mode=dns2socks; fi
	fi
	# Neither dns_mode=local/direct nor use_default_dns=direct is a product
	# proxy-dependency bypass. Only the explicit RESERVED argument above is.
	[ "$shunt:$dns_mode" = dnsmasq:dns2socks ] || { _pw_dns_dep_error 2 dns_dep_backend_unsupported; return; }
	if [ "$source" = "$global" ]; then
		passwall_snapshot_pair "$snapshot" global || return 1
	else
		passwall_snapshot_pair "$snapshot" acl "$sid" || return 1
	fi
	tcp=$PW_SNAPSHOT_TCP
	if [ "$role" = acl ]; then
		gn=$(_pw_snapshot_option "$snapshot" "$global" acl_enable) || return 1
		case "${gn:-0}" in 0) tcp= ;; 1) ;; *) return 1 ;; esac
		[ "${enabled:-0}:${mode:-0}" = 1:1 ] || tcp=
	fi
	[ -n "$tcp" ] || { _pw_dns_dep_error 2 dns_dep_no_tcp; return; }
	# Never read a UDP cache key, even if TCP is absent or failed.
	if [ "$role" = global ]; then prefix=ACL_GLOBAL_TCP; else prefix=ACL_${sid}_tcp; fi
	if [ ! -e "$TMP_PATH/var" ] && [ ! -L "$TMP_PATH/var" ]; then
		if [ "$role:$inherit" = acl:1 ]; then _pw_dns_dep_error 2 dns_dep_no_tcp
		else _pw_dns_dep_error 2 dns_dep_no_instance; fi
		return
	fi
	[ -f "$TMP_PATH/var" ] && [ -r "$TMP_PATH/var" ] || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
	if [ "$role:$inherit" = acl:1 ]; then
		# An inherited failed TCP request has no successful global tuple. Do
		# not misreport that as merely an uncreated ACL instance, or use UDP.
		gn=$(get_cache_var ACL_GLOBAL_TCP_node) && gp=$(get_cache_var ACL_GLOBAL_TCP_redir_port) &&
			gi=$(get_cache_var ACL_GLOBAL_TCP_instance) || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
		[ -n "$gn$gp$gi" ] || { _pw_dns_dep_error 2 dns_dep_no_tcp; return; }
		[ -n "$gn" ] && [ -n "$gp" ] && [ -n "$gi" ] || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
		[ "$gn" = "$tcp" ] || { _pw_dns_dep_error 1 dns_dep_identity; return; }
	fi
	node=$(get_cache_var "${prefix}_node") && port=$(get_cache_var "${prefix}_redir_port") &&
		config=$(get_cache_var "${prefix}_instance") || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
	[ -n "$node$port$config" ] || { _pw_dns_dep_error 2 dns_dep_no_instance; return; }
	[ -n "$node" ] && [ -n "$port" ] && [ -n "$config" ] || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
	[ "$node" = "$tcp" ] || { _pw_dns_dep_error 1 dns_dep_identity; return; }
	instance=${config%/config.json}
	# Validate location here; the Lua probe distinguishes ENOENT from an
	# unreadable path and from an existing but unbound instance.
	[ "$config" = "$instance/config.json" ] && _pw_acl_location "$instance" || { _pw_dns_dep_error 1 dns_dep_identity; return; }
	if [ "$role" = global ] || [ "${inherit:-0}" = 1 ]; then
		[ "${instance%/*}" = "$GLOBAL_ACL_PATH/split" ] || { _pw_dns_dep_error 1 dns_dep_identity; return; }
		if [ "$role" = acl ]; then
			default=$(get_cache_var "${prefix}_default") || { _pw_dns_dep_error 1 dns_dep_cache_untrusted; return; }
			[ "$gn:$gp:$gi:$default" = "$node:$port:$config:1" ] || { _pw_dns_dep_error 1 dns_dep_identity; return; }
		fi
	else
		[ "${instance%/*}" = "$TMP_ACL_PATH/split-acl" ] || { _pw_dns_dep_error 1 dns_dep_identity; return; }
	fi
	[ -n "$cache" ] || { if [ "$source" = "$global" ]; then cache=0; else cache=1; fi; }
	result=$(lua "$PW_DEPENDENCY_HELPER" "$action" "$snapshot" "$tcp" "$instance" "$port" \
		"$preference" "$family" "$scope" "$shunt" "$dns_mode" "${remote:-1.1.1.1}" "$cache" 2>/dev/null) || rc=$?
	case "$rc" in 0|2|1) ;; *) _pw_dns_dep_error 1 dns_dep_identity; return ;; esac
	PW_DNS_DEP_REASON=$(printf '%s\n' "$result" | sed -n '1p')
	PW_DNS_DEP_STATE=$(printf '%s\n' "$result" | sed -n '2p')
	PW_DNS_DEP_JSON=$(printf '%s\n' "$result" | sed -n '3p')
	if [ "$rc" = 0 ]; then
		case "$action:$PW_DNS_DEP_STATE:$PW_DNS_DEP_REASON" in
			resolve:dep_resolved:|validate:dep_validated:) ;;
			*) PW_DNS_DEP_JSON=; _pw_dns_dep_error 1 dns_dep_identity; return ;;
		esac
	else
		case "$PW_DNS_DEP_REASON" in dns_dep_*) ;; *) PW_DNS_DEP_JSON=; _pw_dns_dep_error 1 dns_dep_identity; return ;; esac
		# A nonzero helper result must never export a candidate state. Keep
		# only diagnostics from helpers following the same empty-state rule.
		[ -z "$PW_DNS_DEP_STATE" ] || PW_DNS_DEP_JSON=
		_pw_dns_dep_error "$rc" "$PW_DNS_DEP_REASON"
	fi
	if [ "$rc" = 0 ]; then
		passwall_snapshot_check "$snapshot" || {
			PW_DNS_DEP_JSON= PW_DNS_DEP_STATE=; _pw_dns_dep_error 1 dns_dep_stale_generation; return;
		}
	fi
	return "$rc"
}

passwall_resolve_dns_dependency() { _pw_dns_dependency resolve "$@"; }
passwall_validate_dns_dependency() { _pw_dns_dependency validate "$@"; }
