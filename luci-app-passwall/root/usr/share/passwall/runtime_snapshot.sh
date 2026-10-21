#!/bin/sh
# B3.3-1 preparation only. Caller supplies B1 and holds the lifecycle lock.
# This does not lock LuCI/external UCI writers, activate nodes or migrate UCI.

_pw_snapshot_path() {
	[ -n "$TMP_PATH" ] && [ "${1%/*}" = "$TMP_PATH/contracts" ] || return 1
	case "${1##*/}" in generation.*) ;; *) return 1 ;; esac
	case "${1##*/}" in *[!a-zA-Z0-9_.]*) return 1 ;; esac
	[ -d "$1" ] && [ ! -L "$1" ]
}

_pw_snapshot_digest() {
	local sum
	sum=$(md5sum < "$1") || return 1
	sum=${sum%% *}
	[ "${#sum}" = 32 ] || return 1
	case "$sum" in *[!a-fA-F0-9]*) return 1 ;; esac
	printf '%s' "$sum"
}

# Restrict the private cursor to reads; its unique package never consumes live
# passwall deltas. The frozen export includes pending changes and section order.
_pw_snapshot_uci() {
	local dir="$1" action="$2" section="$3" package
	_pw_snapshot_path "$dir" && [ "$#" = 3 ] || return 1
	case "$action" in get|show) ;; *) return 1 ;; esac
	case "$section" in ''|*[!a-zA-Z0-9_.-]*) return 1 ;; esac
	package=$(cat "$dir/package") || return 1
	case "$package" in passwall_contract_*) ;; *) return 1 ;; esac
	case "$package" in *[!a-zA-Z0-9_]*) return 1 ;; esac
	uci -q -X -c "$dir/config" -C "$dir/config" -t "$dir/state" "$action" "$package.$section"
}

_pw_snapshot_integrity() (
	_pw_snapshot_path "$1" && [ -f "$1/sealed" ] || return 1
	local package actual sealed
	package=$(cat "$1/package") || return 1
	[ "$package" = "passwall_contract_${1##*.}" ] || return 1
	cd "$1" || return 1
	# Check the complete, fixed file set. md5sum -c alone also accepts a
	# truncated manifest containing only a valid prefix of the original list.
	actual=$(md5sum source package view global acls source.md5 config.md5 "config/$package") &&
		sealed=$(cat sealed) || return 1
	[ "$actual" = "$sealed" ]
)

passwall_snapshot_uci() {
	local value
	_pw_snapshot_integrity "$1" && value=$(_pw_snapshot_uci "$@") || return 1
	printf '%s\n' "$value"
}

passwall_snapshot_check() (
	local dir="$1" package source config now status=0
	[ "$#" = 1 ] && _pw_snapshot_integrity "$dir" || return 1
	package=$(cat "$dir/package") && source=$(cat "$dir/source.md5") && config=$(cat "$dir/config.md5") || return 1
	[ "$(_pw_snapshot_digest "$dir/source")" = "$source" ] &&
		[ "$(_pw_snapshot_digest "$dir/config/$package")" = "$config" ] || return 1
	# Compare complete views, not just selected IDs or timestamps. This detects
	# edits; it is NOT a write lock or protection against an ABA concurrent edit.
	now=$(mktemp "$dir/check.XXXXXX") || return 1
	trap 'rm -f "$now"' EXIT
	uci -q -N export passwall > "$now" && cmp -s "$dir/source" "$now" || status=1
	rm -f "$now" || status=1
	trap - EXIT
	return "$status"
)

passwall_snapshot_capture() {
	PW_SNAPSHOT_DIR=
	[ "$#" = 0 ] && [ -n "$TMP_PATH" ] || return 1
	local dir package first status=0
	mkdir -p "$TMP_PATH/contracts" || return 1
	dir=$(umask 077; mktemp -d "$TMP_PATH/contracts/generation.XXXXXX") || return 1
	package="passwall_contract_${dir##*.}"
	(
		umask 077
		mkdir "$dir/config" "$dir/state" || exit 1
		uci -q -N export passwall > "$dir/source" || exit 1
		IFS= read -r first < "$dir/source" || exit 1
		[ "$first" = 'package passwall' ] || exit 1
		printf '%s\n' "$package" > "$dir/package" || exit 1
		sed "1s/^package passwall$/package $package/" "$dir/source" > "$dir/config/$package" || exit 1
		uci -q -X -c "$dir/config" -C "$dir/config" -t "$dir/state" show "$package" > "$dir/view" || exit 1
		sed -n "s/^$package\.\([^.=]*\)=global$/\1/p" "$dir/view" > "$dir/global" || exit 1
		[ "$(wc -l < "$dir/global")" = 1 ] || exit 1
		sed -n "s/^$package\.\([^.=]*\)=acl_rule$/\1/p" "$dir/view" > "$dir/acls" || exit 1
		# A legacy merged selector must never be silently read as both Close.
		local sid fields sections
		sections=$(cat "$dir/global" "$dir/acls") || exit 1
		for sid in $sections; do
			fields=$(_pw_snapshot_uci "$dir" show "$sid") || exit 1
			case "
$fields" in *"
$package.$sid.node="*)
				printf '%s\n' "Passwall snapshot rejected: legacy node field in $sid; offline migration is required." >&2
				exit 1
				;;
			esac
		done
		_pw_snapshot_digest "$dir/source" > "$dir/source.md5" &&
			_pw_snapshot_digest "$dir/config/$package" > "$dir/config.md5" || exit 1
		(cd "$dir" && md5sum source package view global acls source.md5 config.md5 "config/$package" > sealed) || exit 1
		passwall_snapshot_check "$dir"
	) || status=1
	if [ "$status" != 0 ]; then
		rm -rf "$dir" || printf '%s\n' "Passwall snapshot cleanup pending: $dir" >&2
		return 1
	fi
	PW_SNAPSHOT_DIR=$dir
}

_pw_snapshot_option() {
	local dir="$1" sid="$2" option="$3" fields package
	fields=$(passwall_snapshot_uci "$dir" show "$sid") && package=$(cat "$dir/package") || return 1
	case "
$fields" in *"
$package.$sid.$option="*)
		passwall_snapshot_uci "$dir" get "$sid.$option" || return 1
		;;
	esac
	return 0
}

# Config intent only. Inherited requests come from the frozen global request,
# NOT its successful subset. B3.1 still supplies actual live inherited bindings.
passwall_snapshot_pair() {
	PW_SNAPSHOT_TCP_RAW= PW_SNAPSHOT_UDP_RAW= PW_SNAPSHOT_TCP= PW_SNAPSHOT_UDP=
	PW_SNAPSHOT_LAYOUT=closed PW_SNAPSHOT_INHERIT=0 PW_SNAPSHOT_ENABLED=0
	PW_SNAPSHOT_ENABLED_RAW=0
	passwall_resolve_node_pair '' '' || return 1
	local dir="$1" role="$2" sid="${3:-}" global enabled raw_enabled master mode inherit tcp udp gt gu
	case "$#:$role" in 2:global|3:acl) ;; *) return 1 ;; esac
	_pw_snapshot_integrity "$dir" || return 1
	global=$(cat "$dir/global") || return 1
	[ "$role" != global ] || sid=$global
	case "$sid" in ''|*[!a-zA-Z0-9_]*) return 1 ;; esac
	if [ "$role" = acl ]; then grep -Fxq "$sid" "$dir/acls" || return 1; fi
	# Keep outputs empty on every error; do not publish intermediate results.
	enabled=$(_pw_snapshot_option "$dir" "$sid" enabled) || return 1
	tcp=$(_pw_snapshot_option "$dir" "$sid" tcp_node) || return 1
	udp=$(_pw_snapshot_option "$dir" "$sid" udp_node) || return 1
	case "${enabled:-0}" in 0|1) ;; *) return 1 ;; esac
	raw_enabled=${enabled:-0}
	if [ "$role" = acl ]; then
		master=$(_pw_snapshot_option "$dir" "$global" acl_enable) || return 1
		case "${master:-0}" in 0) enabled=0 ;; 1) ;; *) return 1 ;; esac
	fi
	if [ "${enabled:-0}" = 1 ]; then
		if [ "$role" = global ]; then
			passwall_resolve_node_pair "$tcp" "$udp" || return 1
		else
			mode=$(_pw_snapshot_option "$dir" "$sid" mode) || return 1
			inherit=$(_pw_snapshot_option "$dir" "$sid" use_global_config) || return 1
			gt=; gu=
			if [ "${mode:-0}:${inherit:-0}" = 1:1 ]; then
				passwall_snapshot_pair "$dir" global || return 1
				gt=$PW_SNAPSHOT_TCP; gu=$PW_SNAPSHOT_UDP
			fi
			passwall_resolve_acl_node_pair "$mode" "$inherit" "$tcp" "$udp" "$gt" "$gu" || {
				PW_SNAPSHOT_TCP_RAW= PW_SNAPSHOT_UDP_RAW= PW_SNAPSHOT_TCP= PW_SNAPSHOT_UDP=
				PW_SNAPSHOT_LAYOUT=closed PW_SNAPSHOT_INHERIT=0 PW_SNAPSHOT_ENABLED=0
				PW_SNAPSHOT_ENABLED_RAW=0
				return 1
			}
		fi
	fi
	PW_SNAPSHOT_TCP_RAW=$tcp; PW_SNAPSHOT_UDP_RAW=$udp
	PW_SNAPSHOT_TCP=$PW_NODE_TCP; PW_SNAPSHOT_UDP=$PW_NODE_UDP
	PW_SNAPSHOT_LAYOUT=$PW_NODE_LAYOUT; PW_SNAPSHOT_INHERIT=$PW_NODE_INHERIT
	PW_SNAPSHOT_ENABLED=${enabled:-0}
	PW_SNAPSHOT_ENABLED_RAW=$raw_enabled
}
