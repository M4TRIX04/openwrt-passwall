#!/bin/sh
# Stage A preparation ONLY: not packaged, sourced or called by any service or
# uci-defaults script. Running this file only defines the function below.
# A future stage must replace the reverse migration and switch UI/runtime/
# firewall consumers together before explicitly invoking this function.
#
# Usage: passwall_split_nodes_migrate /path/to/offline-candidate
# Reads the caller's current UCI view, including pending edits, but NEVER writes
# its config or pending changes. Only the explicitly named candidate is replaced
# after success; no commit/import into the live package, reload or restart.
#
# Canonical semantics (global and non-inheriting proxy ACL): missing TCP=Close;
# missing UDP=Close; UDP=tcp follows TCP; a UDP node with no TCP is UDP-only.
# Missing both means both Close. ACL mode=0/use_global_config remain untouched.
# A future UI must apply follow-TCP defaults on creation, not on missing reads.
passwall_split_nodes_migrate() (
	[ "$#" = 1 ] && [ -n "$1" ] && [ ! -d "$1" ] || return 1
	local output="$1" work package first
	local snapshot sections sid fields option legacy tcp
	local has_node has_tcp has_udp
	umask 077
	work=$(mktemp -d "${output}.XXXXXX") || return 1
	trap 'rm -rf "$work" || printf "%s\n" "Passwall: candidate cleanup pending: $work" >&2' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir "$work/config" "$work/state" || return 1
	uci -q -N export passwall > "$work/source" || return 1
	IFS= read -r first < "$work/source" || return 1
	[ "$first" = 'package passwall' ] || return 1
	# -t adds a delta path; it does not remove /tmp/.uci. A unique package name
	# prevents live passwall deltas from being reapplied to the private snapshot.
	package="passwall_split_${work##*.}"
	sed "1s/^package passwall$/package $package/" "$work/source" > "$work/config/$package" || return 1
	split_uci() { uci -q -c "$work/config" -C "$work/config" -t "$work/state" "$@"; }
	# -X uses stable cfg IDs for anonymous sections, including per-section show.
	snapshot=$(split_uci -X show "$package") || return 1
	sections=$(printf '%s\n' "$snapshot" | sed -n "s/^${package}\.\([^.=]*\)=\(global\|acl_rule\)$/\1/p") || return 1
	for sid in $sections; do
		fields=$(split_uci show "${package}.${sid}") || return 1
		has_node=0; has_tcp=0; has_udp=0
		for option in $(printf '%s\n' "$fields" | cut -d '=' -f 1); do
			case "$option" in
				"${package}.${sid}.node") has_node=1 ;;
				"${package}.${sid}.tcp_node") has_tcp=1 ;;
				"${package}.${sid}.udp_node") has_udp=1 ;;
			esac
		done
		[ "$has_node" = 1 ] || continue
		legacy=$(split_uci get "${package}.${sid}.node") || return 1
		if [ "$has_tcp" = 0 ]; then
			# Merged Lite implicitly proxies both protocols. Write UDP first so
			# an interrupted retry cannot mistake this for a legacy main config.
			if [ "$has_udp" = 0 ]; then
				split_uci set "${package}.${sid}.udp_node=tcp" || return 1
			fi
			split_uci set "${package}.${sid}.tcp_node=${legacy}" || return 1
		else
			# Existing canonical TCP wins. UCI removes empty options; in legacy
			# main, absent UDP means Close, so do not add a default here.
			tcp=$(split_uci get "${package}.${sid}.tcp_node") || return 1
			if [ "$tcp" != "$legacy" ]; then
				printf '%s\n' "Passwall: ${sid}: keeping tcp_node; discarding conflicting legacy node option" >&2
			fi
		fi
		split_uci delete "${package}.${sid}.node" || return 1
	done
	split_uci -N export "$package" > "$work/result" || return 1
	sed "1s/^package $package$/package passwall/" "$work/result" > "$work/candidate" || return 1
	# Remove private deltas before publishing. A failed cleanup cannot leave
	# live pending changes; if cleanup fails, keep the previous output intact.
	rm -rf "$work/config" "$work/state" || return 1
	mv -f "$work/candidate" "$output" || return 1
	return 0
)
