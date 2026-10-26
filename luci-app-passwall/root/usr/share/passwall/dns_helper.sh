#!/bin/sh
# B3.3-3C-A, definitions only. Explicit diagnostic adapter, NOT a production
# entry or a completed runtime provider. Caller loads snapshot/B1/B2/B3.1/bound,
# dns_dependency.sh and the existing check_dns_config under the lifecycle lock.
# PW_DNS_HELPER_PROBE points to dns_helper_probe.lua (installed Lua module).
# DNS-H3 adds explicit private configuration capture/generation + dnsmasq --test.
# No port allocation, helper launch/stop, runtime binding or ready publication.
# 0=diagnostic success only, 2=isolated rejection/BLOCKED, 1=untrusted input.

_pw_dns_helper_reset() {
	PW_DNS_HELPER_JSON= PW_DNS_HELPER_STATE= PW_DNS_HELPER_REASON=
}

_pw_dns_helper_error() {
	_pw_dns_helper_reset
	PW_DNS_HELPER_REASON=$2
	return "$1"
}

# Run the actual compatibility gate against the same frozen global settings.
# Its legacy socks_server check must not be bypassed, even for an inherited ACL.
# Never source app.sh here: loading definitions remains the explicit caller's job.
_pw_dns_helper_compatibility() (
	local snapshot="$1" role="$2" sid="$3" global legacy native
	command -v check_dns_config >/dev/null 2>&1 || exit 1
	# Preserve gate diagnostics without letting the production logger write a
	# shared log from this diagnostic adapter.
	echolog() { printf '%s\n' "$*" >&2; }
	global=$(cat "$snapshot/global") &&
		legacy=$(_pw_snapshot_option "$snapshot" "$global" socks_server) &&
		native=$(_pw_snapshot_option "$snapshot" "$global" node_socks_port) || exit 1
	# Only these two reads are part of the existing check_dns_config contract.
	config_n_get() {
		[ "$#" = 2 ] || [ "$#" = 3 ] || return 1
		case "$1:$2" in
			'@global[0]:socks_server') printf '%s\n' "$legacy" ;;
			'@global[0]:node_socks_port') printf '%s\n' "${native:-${3:-1070}}" ;;
			*) return 1 ;;
		esac
	}
	if [ "$role" = global ]; then
		check_dns_config dnsmasq dns2socks global
	else
		local inherit
		inherit=$(_pw_snapshot_option "$snapshot" "$sid" use_global_config) || exit 1
		if [ "${inherit:-0}" = 1 ]; then check_dns_config dnsmasq dns2socks global
		else check_dns_config dnsmasq dns2socks "$sid"; fi
	fi
)

# SNAPSHOT global|acl GLOBAL|SID PREFERENCE FAMILY VALIDATED_CANDIDATE_JSON
# Accept only an exact 3B dep_validated record, then repeat the complete 3B
# snapshot/cache/owner/capability/SOCKS negotiation checks. JSON is never eval'd.
# This is a candidate check, NOT stage-A external-tool capability preflight.
passwall_check_dns_helper_candidate() {
	_pw_dns_helper_reset
	[ "$#" = 6 ] && [ -n "${PW_DNS_HELPER_PROBE:-}" ] || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	command -v passwall_validate_dns_dependency >/dev/null 2>&1 || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	local snapshot="$1" role="$2" sid="$3" preference="$4" family="$5" candidate="$6" rc=0 result
	passwall_validate_dns_dependency "$snapshot" "$role" "$sid" "$preference" "$family" || rc=$?
	[ "$rc" = 0 ] || { _pw_dns_helper_error "$rc" "${PW_DNS_DEP_REASON:-dns_dep_identity}"; return; }
	[ "$PW_DNS_DEP_STATE" = dep_validated ] || { _pw_dns_helper_error 1 dns_dep_identity; return; }
	result=$(lua "$PW_DNS_HELPER_PROBE" candidate "$candidate" "$PW_DNS_DEP_JSON" 2>/dev/null) || {
		_pw_dns_helper_error 1 dns_dep_identity; return;
	}
	_pw_dns_helper_compatibility "$snapshot" "$role" "$sid" || {
		_pw_dns_helper_error 2 dns_dep_compatibility; return;
	}
	passwall_snapshot_check "$snapshot" || { _pw_dns_helper_error 1 dns_dep_stale_generation; return; }
	PW_DNS_HELPER_JSON=$result
	# Deliberately no public dependency state: success means candidate equality.
}

# Candidate arguments above, then PID BIRTH CANONICAL_BINARY LISTEN_PORT
# [PREVIOUS_OBSERVATION_JSON]. The optional previous observation detects helper
# identity changes; it is not accepted as an ownership or DNS validation receipt.
# Surround the read-only helper probe with fresh 3B checks, then recheck the
# helper after the second SOCKS negotiation. Never adopt a PID for cleanup.
passwall_observe_dns_helper() {
	_pw_dns_helper_reset
	{ [ "$#" = 10 ] || [ "$#" = 11 ]; } || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	local observation result
	passwall_check_dns_helper_candidate "$1" "$2" "$3" "$4" "$5" "$6" || return $?
	if [ "$#" = 11 ]; then
		observation=$(lua "$PW_DNS_HELPER_PROBE" check "$PW_DNS_HELPER_JSON" "$7" "$8" "$9" "${10}" "${11}" 2>/dev/null) || {
			_pw_dns_helper_error 1 dns_dep_helper_identity; return;
		}
	else
		observation=$(lua "$PW_DNS_HELPER_PROBE" observe "$PW_DNS_HELPER_JSON" "$7" "$8" "$9" "${10}" 2>/dev/null) || {
			_pw_dns_helper_error 1 dns_dep_helper_identity; return;
		}
	fi
	passwall_check_dns_helper_candidate "$1" "$2" "$3" "$4" "$5" "$6" || return $?
	result=$(lua "$PW_DNS_HELPER_PROBE" check "$PW_DNS_HELPER_JSON" "$7" "$8" "$9" "${10}" "$observation" 2>/dev/null) || {
		_pw_dns_helper_error 1 dns_dep_helper_identity; return;
	}
	passwall_snapshot_check "$1" || { _pw_dns_helper_error 1 dns_dep_stale_generation; return; }
	PW_DNS_HELPER_JSON=$result
}

# Same six candidate arguments. DNS-H3's separate configuration-only entry below
# does not remove the lifecycle/outer/L1/L3 blockers. This internal diagnostic
# code remains provisional; no caller flag or config check authorizes a launch.
passwall_start_dns_helper() {
	passwall_check_dns_helper_candidate "$@" || return $?
	_pw_dns_helper_error 2 dns_dep_config_unimplemented
}

# No stop adapter is exposed: this revision creates no helper. The read-only
# observer in dns_helper_probe.lua never authorizes a signal or reclamation. In
# particular, never pass a helper directory to public bound.stop_owner.

_pw_dns_helper_config_reset() {
	PW_DNS_HELPER_CONFIG_DIR= PW_DNS_HELPER_CONFIG= PW_DNS_HELPER_INPUT_MD5=
	PW_DNS_HELPER_CONFIG_MD5= PW_DNS_HELPER_CONFIG_MANIFEST_MD5= PW_DNS_HELPER_CONFIG_CHECK_LOG=
	PW_DNS_HELPER_CONFIG_PHASE= PW_DNS_HELPER_CONFIG_ERROR=
}

# Only a creation-local directory receipt may authorize this private cleanup.
# No public stop, instance walk, cache invalidation or process signal is involved.
_pw_dns_helper_config_owned() {
	local dir="$1" receipt="$2"
	[ -n "${TMP_PATH:-}" ] && [ "${dir%/*}" = "$TMP_PATH" ] || return 1
	case "${dir##*/}" in dns-helper.*) ;; *) return 1 ;; esac
	printf '%s\n' "$receipt" | grep -Eq '^[0-9]+:[0-9]+:[0-9]+$' || return 1
	[ -n "$receipt" ] && [ -d "$dir" ] && [ ! -L "$dir" ] &&
		[ "$(readlink -f "$dir")" = "$dir" ] &&
		[ "$(stat -c '%d:%i:%u' "$dir")" = "$receipt" ]
}

_pw_dns_helper_config_discard() {
	local dir="$1" receipt="$2"
	_pw_dns_helper_config_owned "$dir" "$receipt" || return 1
	rm -rf -- "$dir" || return 1
	[ ! -e "$dir" ] && [ ! -L "$dir" ]
}

# Explicit, side-effecting CONFIGURATION-ONLY entry, never called by production:
#   SNAPSHOT REQUEST_JSON BASE_DNSMASQ_CONF DNSMASQ_BINARY
# PW_DNSMASQ_GENERATOR points to the existing helper_dnsmasq.lua.
# REQUEST_JSON supplies the existing add_rule string arguments, without output
# paths. Required keys: FLAG NODE LISTEN_PORT DEFAULT_DNS LOCAL_DNS TUN_DNS
# USE_DEFAULT_DNS CHINADNS_DNS USE_DIRECT_LIST USE_PROXY_LIST USE_BLOCK_LIST
# USE_GFW_LIST CHN_LIST DEFAULT_PROXY_MODE NO_PROXY_IPV6 NFTFLAG NO_LOGIC_LOG,
# each prefixed with '-'. LOCAL_DNS/DEFAULT_DNS must be literal IP#port lists.
# Caller supplies actual prospective ports/derived inputs for the same frozen
# scope; no defaults, dummy ports or live cache values are invented here.
# This entry does NOT validate a 3B candidate or satisfy complete stage A/L2:
# it captures inputs, generates the complete proposed config and runs --test.
# L1/L3, production-PID evidence and runtime binding remain separate work.
# Success retains the private artifacts for later inspection/L2/L3 validation.
# Failure clears exported results and removes only this call's directory; an
# uncertain cleanup retains CONFIG_DIR as responsibility and returns 1.
passwall_generate_dns_helper_config() {
	_pw_dns_helper_reset
	_pw_dns_helper_config_reset
	[ "$#" = 4 ] && [ -n "${PW_DNSMASQ_GENERATOR:-}" ] && [ -f "$PW_DNSMASQ_GENERATOR" ] || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	local snapshot="$1" request="$2" base="$3" dnsmasq="$4" dir receipt= reason=dns_dep_config_invalid rc=2 phase detail
	local tool
	for tool in lua cp chmod md5sum stat readlink mktemp mkdir rm grep sed cat; do
		command -v "$tool" >/dev/null 2>&1 || { _pw_dns_helper_error 2 dns_dep_tool_missing; return; }
	done
	[ -n "${TMP_PATH:-}" ] && [ -d "$TMP_PATH" ] &&
		[ "$(readlink -f "$TMP_PATH")" = "$TMP_PATH" ] || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	case "$dnsmasq" in /*) ;; *) _pw_dns_helper_error 1 dns_dep_argument; return ;; esac
	[ -x "$dnsmasq" ] && [ -f "$dnsmasq" ] || { _pw_dns_helper_error 2 dns_dep_tool_missing; return; }
	[ -f "$base" ] && [ -r "$base" ] || { _pw_dns_helper_error 2 dns_dep_config_invalid; return; }
	passwall_snapshot_check "$snapshot" || { _pw_dns_helper_error 1 dns_dep_stale_generation; return; }
	dir=$(umask 077; mktemp -d "$TMP_PATH/dns-helper.XXXXXX") || {
		_pw_dns_helper_error 1 dns_dep_config_invalid; return;
	}
	# Capture the directory identity before any file creation. Missing receipts
	# are not repaired by guessing ownership, even after a failed first write.
	receipt=$(stat -c '%d:%i:%u' "$dir") || receipt=
	if ! _pw_dns_helper_config_owned "$dir" "$receipt"; then
		_pw_dns_helper_error 1 dns_dep_identity
		PW_DNS_HELPER_CONFIG_DIR=$dir
		PW_DNS_HELPER_CONFIG_PHASE=receipt
		return 1
	fi
	if (
		umask 077
		mkdir "$dir/input" "$dir/cache" || exit 1
		printf '%s\n' "$request" > "$dir/request.json" || exit 1
		printf '%s\n' capture > "$dir/phase" || exit 1
		lua "$PW_DNSMASQ_GENERATOR" isolated_capture -ISOLATED_ROOT "$dir" -SNAPSHOT "$snapshot" -BASE_CONF "$base" > "$dir/generator.log" 2>&1 || exit 1
		md5sum < "$dir/inputs.json" > "$dir/inputs.md5" || exit 1
		printf '%s\n' generate > "$dir/phase" || exit 1
		lua "$PW_DNSMASQ_GENERATOR" isolated_generate -ISOLATED_ROOT "$dir" -SNAPSHOT "$snapshot" >> "$dir/generator.log" 2>&1 || exit 1
		# Hash every generated rule as well as the main config: its conf-dir is
		# part of the actual proposed configuration, not a reduced syntax probe.
		lua "$PW_DNSMASQ_GENERATOR" isolated_verify -ISOLATED_ROOT "$dir" -SNAPSHOT "$snapshot" -SEAL_CONFIG 1 >> "$dir/generator.log" 2>&1 || exit 1
		md5sum < "$dir/config.md5" > "$dir/config-seal.md5" || exit 1
		printf '%s\n' test > "$dir/phase" || exit 1
		status=0
		"$dnsmasq" --test --conf-file="$dir/dnsmasq.conf" > "$dir/dnsmasq-test.log" 2>&1 || status=$?
		printf '%s\n' "$status" > "$dir/dnsmasq-test.status" || exit 1
		[ "$status" = 0 ] || exit 1
		# Configuration syntax success is not a helper/DNS/forwarding success.
		printf '%s\n' verify > "$dir/phase" || exit 1
		lua "$PW_DNSMASQ_GENERATOR" isolated_verify -ISOLATED_ROOT "$dir" -SNAPSHOT "$snapshot" >> "$dir/generator.log" 2>&1 || exit 1
		[ "$(md5sum < "$dir/config.md5")" = "$(cat "$dir/config-seal.md5")" ] || exit 1
		[ "$(md5sum < "$dir/inputs.json")" = "$(cat "$dir/inputs.md5")" ] || exit 1
	); then
		if ! _pw_dns_helper_config_owned "$dir" "$receipt"; then
			reason=dns_dep_identity; rc=1
		elif passwall_snapshot_check "$snapshot"; then
			PW_DNS_HELPER_INPUT_MD5=$(_pw_snapshot_digest "$dir/inputs.json") &&
				PW_DNS_HELPER_CONFIG_MD5=$(_pw_snapshot_digest "$dir/dnsmasq.conf") &&
				PW_DNS_HELPER_CONFIG_MANIFEST_MD5=$(_pw_snapshot_digest "$dir/config.md5") || {
				_pw_dns_helper_config_reset
				reason=dns_dep_config_invalid
			}
			if [ -n "$PW_DNS_HELPER_CONFIG_MD5" ]; then
				PW_DNS_HELPER_CONFIG_DIR=$dir
				PW_DNS_HELPER_CONFIG="$dir/dnsmasq.conf"
				PW_DNS_HELPER_CONFIG_CHECK_LOG="$dir/dnsmasq-test.log"
				PW_DNS_HELPER_CONFIG_PHASE=complete
				return 0
			fi
		else reason=dns_dep_stale_generation; rc=1; fi
	fi
	if ! passwall_snapshot_check "$snapshot"; then reason=dns_dep_stale_generation; rc=1; fi
	if _pw_dns_helper_config_owned "$dir" "$receipt"; then
		phase=$(cat "$dir/phase" 2>/dev/null) || phase=prepare
		case "$phase" in capture|generate|test|verify) ;; *) phase=prepare ;; esac
		if [ "$phase" = test ]; then detail=$(cat "$dir/dnsmasq-test.log" 2>/dev/null) || detail=
		else detail=$(sed -n '/^dns_dep_config_invalid: /p' "$dir/generator.log" 2>/dev/null) || detail=; fi
	else phase=cleanup; detail='private directory identity changed'; fi
	# Preserve only diagnostics in the caller's output; captured configs may
	# contain local hosts. Do not copy failure artifacts to a shared log/cache.
	_pw_dns_helper_reset
	_pw_dns_helper_config_reset
	if _pw_dns_helper_config_discard "$dir" "$receipt"; then
		_pw_dns_helper_error "$rc" "$reason"
	else
		_pw_dns_helper_error 1 dns_dep_identity
		PW_DNS_HELPER_CONFIG_DIR=$dir
	fi
	PW_DNS_HELPER_CONFIG_PHASE=$phase
	PW_DNS_HELPER_CONFIG_ERROR=$detail
	[ -z "$PW_DNS_HELPER_CONFIG_DIR" ] && [ "$rc" = 2 ] && return 2
	return 1
}
