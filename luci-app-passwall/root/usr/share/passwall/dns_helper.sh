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
		_pw_dns_helper_error 2 dns_dep_backend_unsupported; return;
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
			_pw_dns_helper_error 1 dns_dep_identity; return;
		}
	else
		observation=$(lua "$PW_DNS_HELPER_PROBE" observe "$PW_DNS_HELPER_JSON" "$7" "$8" "$9" "${10}" 2>/dev/null) || {
			_pw_dns_helper_error 1 dns_dep_identity; return;
		}
	fi
	passwall_check_dns_helper_candidate "$1" "$2" "$3" "$4" "$5" "$6" || return $?
	result=$(lua "$PW_DNS_HELPER_PROBE" check "$PW_DNS_HELPER_JSON" "$7" "$8" "$9" "${10}" "$observation" 2>/dev/null) || {
		_pw_dns_helper_error 1 dns_dep_identity; return;
	}
	passwall_snapshot_check "$1" || { _pw_dns_helper_error 1 dns_dep_stale_generation; return; }
	PW_DNS_HELPER_JSON=$result
}

# The launch and stop adapters are defined after the H3 configuration block
# below, because they consume its private capture/generate/verify entry.
# No production entry calls them; never pass a helper directory to the public
# bound.stop_owner (it requires binding.json/instance shapes a helper lacks).

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
	# Two private directory kinds exist: configuration/verification directories
	# and the single L3 attempt directory. Both are creation-local and neither
	# may be reclaimed by a later call.
	case "${dir##*/}" in dns-helper.*|dns-l3.*) ;; *) return 1 ;; esac
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

# ---------------------------------------------------------------------------
# DNS-H4-B1 minimal lifecycle.
#
# Stage A preflight -> frozen port/binding -> H3 fragment (L2) -> bound spawn ->
# identity/listener re-verification -> L1 real query plus helper->SOCKS outbound
# ownership -> identity-checked stop. L3 and dep_ready publication are out of
# scope. Definitions only: no production entry point calls these functions.
#
# Ownership is deliberately split:
#   * private creation receipt - this call's in-memory PID/birth plus the scope
#     directory d:ino:uid captured before any write. It authorizes rollback of
#     the attempt that created the process, and nothing else.
#   * public stop proof - the scope-directory helper.record, re-verified against
#     /proc before any signal. It authorizes later stops.
# Neither authorizes matching by process name or by listening port.
# ---------------------------------------------------------------------------

_pw_dns_helper_rec_reset() {
	PW_DNS_HELPER_REC_SCOPE= PW_DNS_HELPER_REC_GENERATION= PW_DNS_HELPER_REC_INSTANCE=
	PW_DNS_HELPER_REC_SOCKS_ADDR= PW_DNS_HELPER_REC_SOCKS_PORT= PW_DNS_HELPER_REC_REMOTE_DNS=
	PW_DNS_HELPER_REC_CACHE= PW_DNS_HELPER_REC_IDENTITY_MD5= PW_DNS_HELPER_REC_CONFIG_MD5=
	PW_DNS_HELPER_REC_PID= PW_DNS_HELPER_REC_BIRTH= PW_DNS_HELPER_REC_EXECUTABLE=
	PW_DNS_HELPER_REC_CMDLINE_MD5= PW_DNS_HELPER_REC_LISTEN_ADDR= PW_DNS_HELPER_REC_LISTEN_PORT=
	PW_DNS_HELPER_REC_CONFIG_DIR= PW_DNS_HELPER_REC_CONFIG_MD5_FILE=
}

_pw_dns_helper_l3_reset() {
	PW_DNS_HELPER_L3_PHASE= PW_DNS_HELPER_L3_ERROR= PW_DNS_HELPER_L3_EVIDENCE=
	PW_DNS_HELPER_L3_PORT= PW_DNS_HELPER_L3_PID= PW_DNS_HELPER_L3_QUERY_NAME=
	PW_DNS_HELPER_L3_SRC_PORT= PW_DNS_HELPER_L3_INODE=
	# Private resources of one L3 attempt; only its own cleanup may use them.
	_PW_DNS_HELPER_L3_TMP= _PW_DNS_HELPER_L3_RECEIPT= _PW_DNS_HELPER_L3_DNSMASQ_PID=
	_PW_DNS_HELPER_L3_TCPDUMP_PID= _PW_DNS_HELPER_L3_SAMPLER_PID=
}

_pw_dns_helper_start_reset() {
	PW_DNS_HELPER_BIN= PW_DNS_HELPER_SCOPE_DIR= PW_DNS_HELPER_BINDING= PW_DNS_HELPER_RECORD=
	PW_DNS_HELPER_LOG= PW_DNS_HELPER_LISTEN_ADDR= PW_DNS_HELPER_LISTEN_PORT= PW_DNS_HELPER_PID=
	PW_DNS_HELPER_BIRTH= PW_DNS_HELPER_OBSERVATION= PW_DNS_HELPER_OUTBOUND= PW_DNS_HELPER_QUERY_NAME=
	PW_DNS_HELPER_QUERY_RESULT= PW_DNS_HELPER_PHASE= PW_DNS_HELPER_FRAGMENT_RECEIPT=
	PW_DNS_HELPER_CMDLINE_MD5= PW_DNS_HELPER_DEP_READY=
	_pw_dns_helper_l3_reset
	_pw_dns_helper_rec_reset
}

# A failed attempt must never leave values that look like usable ownership.
_pw_dns_helper_start_error() {
	PW_DNS_HELPER_PID= PW_DNS_HELPER_BIRTH= PW_DNS_HELPER_RECORD= PW_DNS_HELPER_BINDING=
	PW_DNS_HELPER_OBSERVATION= PW_DNS_HELPER_OUTBOUND= PW_DNS_HELPER_CMDLINE_MD5=
	_pw_dns_helper_error "$1" "$2"
}

# Scope runtime directory (contract 5.2 item 2): never the published instance.
_pw_dns_helper_scope_dir() {
	[ -n "${TMP_ACL_PATH:-}" ] || return 1
	[ -d "$TMP_ACL_PATH" ] && [ ! -L "$TMP_ACL_PATH" ] &&
		[ "$(readlink -f "$TMP_ACL_PATH")" = "$TMP_ACL_PATH" ] || return 1
	case "$1" in
		global) printf '%s\n' "$TMP_ACL_PATH/default" ;;
		acl)
			case "${2:-}" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
			printf '%s\n' "$TMP_ACL_PATH/$2"
			;;
		*) return 1 ;;
	esac
}

_pw_dns_helper_scope_owned() {
	[ -n "${1:-}" ] && [ -d "$1" ] && [ ! -L "$1" ] &&
		[ "$(readlink -f "$1")" = "$1" ] || return 1
	[ "${1%/*}" = "${TMP_ACL_PATH:-}" ]
}

_pw_dns_helper_write_file() {
	local dir="$1" name="$2" body="$3" tmp
	tmp="$dir/.$name.tmp.$$"
	( umask 077; printf '%s\n' "$body" > "$tmp" ) || { rm -f -- "$tmp"; return 1; }
	mv -f -- "$tmp" "$dir/$name" || { rm -f -- "$tmp"; return 1; }
}

_pw_dns_helper_drop_records() {
	local dir="$1"
	[ -n "$dir" ] || return 1
	# A readiness claim never outlives the helper it describes. Only the claim is
	# removed here; ownership records are dropped by their own confirmation.
	rm -f -- "$dir/dep.ready" || return 1
	rm -f -- "$dir/helper.record" || return 1
	rm -f -- "$dir/helper.binding" || return 1
	[ ! -e "$dir/dep.ready" ] && [ ! -e "$dir/helper.record" ] && [ ! -e "$dir/helper.binding" ]
}

# The probe owns all JSON parsing; this reads its key=value form. A temp file is
# used because a pipeline would run the assignments in a subshell.
_pw_dns_helper_read_binding() {
	local candidate="$1" dir="$2" tmp="$2/.helper.bind.$$" line key value
	_pw_dns_helper_rec_reset
	lua "$PW_DNS_HELPER_PROBE" bind "$candidate" > "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 1; }
	while IFS= read -r line; do
		case "$line" in '') continue ;; esac
		key=${line%%=*}
		[ "$key" != "$line" ] || { rm -f -- "$tmp"; return 1; }
		value=${line#*=}
		[ -n "$value" ] || { rm -f -- "$tmp"; return 1; }
		case "$key" in
			scope) PW_DNS_HELPER_REC_SCOPE=$value ;;
			generation) PW_DNS_HELPER_REC_GENERATION=$value ;;
			instance_dir) PW_DNS_HELPER_REC_INSTANCE=$value ;;
			socks_addr) PW_DNS_HELPER_REC_SOCKS_ADDR=$value ;;
			socks_port) PW_DNS_HELPER_REC_SOCKS_PORT=$value ;;
			remote_dns) PW_DNS_HELPER_REC_REMOTE_DNS=$value ;;
			dns_cache) PW_DNS_HELPER_REC_CACHE=$value ;;
			identity_md5) PW_DNS_HELPER_REC_IDENTITY_MD5=$value ;;
			config_md5) PW_DNS_HELPER_REC_CONFIG_MD5=$value ;;
			*) rm -f -- "$tmp"; return 1 ;;
		esac
	done < "$tmp"
	rm -f -- "$tmp"
	[ -n "$PW_DNS_HELPER_REC_SCOPE" ] && [ -n "$PW_DNS_HELPER_REC_GENERATION" ] &&
		[ -n "$PW_DNS_HELPER_REC_INSTANCE" ] && [ -n "$PW_DNS_HELPER_REC_SOCKS_ADDR" ] &&
		[ -n "$PW_DNS_HELPER_REC_SOCKS_PORT" ] && [ -n "$PW_DNS_HELPER_REC_REMOTE_DNS" ] &&
		[ -n "$PW_DNS_HELPER_REC_CACHE" ] && [ -n "$PW_DNS_HELPER_REC_IDENTITY_MD5" ] &&
		[ -n "$PW_DNS_HELPER_REC_CONFIG_MD5" ]
}

# Strict key=value reader. Unknown or empty keys are rejected instead of being
# guessed, and the record is never eval'd.
_pw_dns_helper_record_read() {
	local file="$1/helper.record" line key value
	_pw_dns_helper_rec_reset
	[ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 1
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '') continue ;; esac
		key=${line%%=*}
		value=${line#*=}
		[ "$key" != "$line" ] && [ -n "$value" ] || return 1
		case "$key" in
			scope) PW_DNS_HELPER_REC_SCOPE=$value ;;
			generation) PW_DNS_HELPER_REC_GENERATION=$value ;;
			instance_dir) PW_DNS_HELPER_REC_INSTANCE=$value ;;
			listen_addr) PW_DNS_HELPER_REC_LISTEN_ADDR=$value ;;
			listen_port) PW_DNS_HELPER_REC_LISTEN_PORT=$value ;;
			pid) PW_DNS_HELPER_REC_PID=$value ;;
			birth) PW_DNS_HELPER_REC_BIRTH=$value ;;
			executable) PW_DNS_HELPER_REC_EXECUTABLE=$value ;;
			cmdline_md5) PW_DNS_HELPER_REC_CMDLINE_MD5=$value ;;
			identity_md5) PW_DNS_HELPER_REC_IDENTITY_MD5=$value ;;
			config_md5) PW_DNS_HELPER_REC_CONFIG_MD5=$value ;;
			helper_config_dir) PW_DNS_HELPER_REC_CONFIG_DIR=$value ;;
			helper_config_md5) PW_DNS_HELPER_REC_CONFIG_MD5_FILE=$value ;;
			*) return 1 ;;
		esac
	done < "$file"
	[ -n "$PW_DNS_HELPER_REC_SCOPE" ] && [ -n "$PW_DNS_HELPER_REC_GENERATION" ] &&
		[ -n "$PW_DNS_HELPER_REC_INSTANCE" ] && [ -n "$PW_DNS_HELPER_REC_LISTEN_ADDR" ] &&
		[ -n "$PW_DNS_HELPER_REC_LISTEN_PORT" ] && [ -n "$PW_DNS_HELPER_REC_PID" ] &&
		[ -n "$PW_DNS_HELPER_REC_BIRTH" ] && [ -n "$PW_DNS_HELPER_REC_EXECUTABLE" ] &&
		[ -n "$PW_DNS_HELPER_REC_CMDLINE_MD5" ]
}

# Private receipt only: the caller must have obtained this PID/birth itself.
_pw_dns_helper_stop_private() {
	[ -n "${1:-}" ] && [ -n "${2:-}" ] || return 1
	command -v _pw_global_ss_kill >/dev/null 2>&1 || return 1
	_pw_global_ss_kill "$1" "$2"
}

_pw_dns_helper_discard_fragment() {
	[ -n "${PW_DNS_HELPER_CONFIG_DIR:-}" ] && [ -n "${PW_DNS_HELPER_FRAGMENT_RECEIPT:-}" ] || return 0
	_pw_dns_helper_config_discard "$PW_DNS_HELPER_CONFIG_DIR" "$PW_DNS_HELPER_FRAGMENT_RECEIPT"
}

# Unique, uncacheable L1 probe name: RFC 2606 reserves .invalid, so a working
# forwarder must answer NXDOMAIN for it and no cache can hold a positive record.
_pw_dns_helper_probe_name() {
	local uuid= label=
	uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || uuid=
	label=${uuid%%-*}
	case "$label" in ''|*[!0-9a-fA-F]*) label=$$ ;; esac
	printf 'pw-%s.invalid\n' "$label"
}

# Classify one nslookup transcript for the exact probe name. Only an address
# answer or a reserved-name NXDOMAIN count as a round trip; REFUSED, SERVFAIL,
# connection refusal and timeouts stay failures and are never upgraded to PASS.
_pw_dns_helper_l1_classify() {
	local out="$1" rc="$2" name="$3"
	if [ "$rc" = 0 ] && grep -q '^Name:' "$out" && grep -Fq -- "$name" "$out" &&
		[ "$(sed -n '/^Name:/,$p' "$out" | grep -cE '^Address: [0-9a-fA-F]')" -gt 0 ]; then
		printf '%s\n' answer
	elif grep -Fq -- "can't find $name" "$out" && grep -Fq NXDOMAIN "$out"; then
		printf '%s\n' nxdomain
	else
		printf '%s\n' failed
	fi
}

# Stage A: only what this adapter itself executes. No port is allocated and no
# process is created here. rc 2 = missing dependency, rc 1 = unusable context.
_pw_dns_helper_preflight() {
	local dnsmasq="$1" tool bin dir receipt= rc=0
	for tool in lua md5sum stat readlink mktemp mkdir rm mv grep sed cat netstat sleep nslookup; do
		command -v "$tool" >/dev/null 2>&1 || return 2
	done
	command -v get_process_start_time >/dev/null 2>&1 || return 2
	command -v check_port_exists >/dev/null 2>&1 || return 2
	command -v first_type >/dev/null 2>&1 || return 2
	case "$dnsmasq" in /*) ;; *) return 1 ;; esac
	bin=$(first_type dns2socks) || return 2
	bin=$(readlink -f "$bin") || return 2
	[ -f "$bin" ] && [ -x "$bin" ] || return 2
	[ -f "$dnsmasq" ] && [ -x "$dnsmasq" ] || return 2
	[ -n "${TMP_PATH:-}" ] && [ -d "$TMP_PATH" ] &&
		[ "$(readlink -f "$TMP_PATH")" = "$TMP_PATH" ] || return 1
	dir=$(umask 077; mktemp -d "$TMP_PATH/dns-helper.XXXXXX") || return 1
	receipt=$(stat -c '%d:%i:%u' "$dir") || receipt=
	_pw_dns_helper_config_owned "$dir" "$receipt" || {
		rm -rf -- "$dir" 2>/dev/null
		return 1
	}
	# Port-independent capability probe: --test/--conf-file only, no helper
	# upstream and no listening socket, per contract 4.2 stage A.
	(
		umask 077
		printf '%s\n' no-resolv no-hosts bind-interfaces listen-address=127.0.0.1 > "$dir/probe.conf" &&
			"$dnsmasq" --test --conf-file="$dir/probe.conf" > "$dir/probe.log" 2>&1
	) || rc=$?
	_pw_dns_helper_config_discard "$dir" "$receipt" || return 1
	[ "$rc" = 0 ] || return 2
	PW_DNS_HELPER_BIN=$bin
}

# Reverse order rollback: stop the private process, then drop the fragment, then
# the records. An unconfirmable stop keeps every record and returns 1.
_pw_dns_helper_rollback() {
	local rc="$1" reason="$2" phase="$3"
	if [ -n "${PW_DNS_HELPER_PID:-}" ] && [ -n "${PW_DNS_HELPER_BIRTH:-}" ]; then
		_pw_dns_helper_stop_private "$PW_DNS_HELPER_PID" "$PW_DNS_HELPER_BIRTH" || {
			PW_DNS_HELPER_PHASE=$phase
			_pw_dns_helper_reset
			PW_DNS_HELPER_REASON=$reason
			return 1
		}
	fi
	_pw_dns_helper_discard_fragment
	[ -z "${PW_DNS_HELPER_SCOPE_DIR:-}" ] || _pw_dns_helper_drop_records "$PW_DNS_HELPER_SCOPE_DIR"
	_pw_dns_helper_start_error "$rc" "$reason"
	PW_DNS_HELPER_PHASE=$phase
	return "$rc"
}

# Callers must not reimplement allocation; the frozen value is then passed to
# passwall_start_dns_helper so -TUN_DNS can match it byte for byte.
passwall_alloc_dns_helper_port() {
	_pw_dns_helper_reset
	_pw_dns_helper_start_reset
	command -v get_new_port >/dev/null 2>&1 && command -v netstat >/dev/null 2>&1 || {
		_pw_dns_helper_error 2 dns_dep_tool_missing; return;
	}
	local port=
	port=$(get_new_port auto udp) || port=
	case "$port" in ''|*[!0-9]*) _pw_dns_helper_error 2 dns_dep_helper_start; return ;; esac
	PW_DNS_HELPER_LISTEN_ADDR=127.0.0.1
	PW_DNS_HELPER_LISTEN_PORT=$port
	printf '%s\n' "$port"
}

# True when the H3-verified fragment sends queries to the frozen helper endpoint.
# Two whole dnsmasq lines count, because both are legitimate frozen outputs:
#   server=127.0.0.1#<port>                    scope default upstream
#   server=/<domain>/127.0.0.1#<port>          domain split (proxy list)
# Address and port must match exactly, so a bare port, a longer port
# (`#153540`) or unrelated text cannot satisfy this. Only the generated main
# config and the conf-dir it names inside this same generation are read; a
# conf-dir pointing anywhere else is ignored instead of followed.
_pw_dns_helper_fragment_upstream() {
	local conf="$1" root="$2" port="$3" pattern line dir file
	[ -n "$conf" ] && [ -n "$root" ] && [ -n "$port" ] || return 1
	case "$port" in ''|*[!0-9]*) return 1 ;; esac
	[ -f "$conf" ] && [ ! -L "$conf" ] || return 1
	pattern="^server=(/[^#]*/)?127[.]0[.]0[.]1#${port}\$"
	grep -Eq "$pattern" "$conf" && return 0
	while IFS= read -r line; do
		case "$line" in conf-dir=*) ;; *) continue ;; esac
		dir=${line#conf-dir=}
		case "$dir" in "$root"/cache/dnsmasq_*) ;; *) continue ;; esac
		[ -d "$dir" ] && [ ! -L "$dir" ] || continue
		for file in "$dir"/*; do
			[ -f "$file" ] && [ ! -L "$file" ] || continue
			grep -Eq "$pattern" "$file" && return 0
		done
	done <<EOF
$(grep -E '^conf-dir=' "$conf" 2>/dev/null)
EOF
	return 1
}

# Choose a unique name from the sealed fragment's existing forwarding rules.
# A remote default can use .invalid; a direct default needs a child of an
# explicitly proxied suffix. Never add a probe-only server rule to the copy.
# Conflicting/local answers still have to pass the unchanged L3 forwarding,
# response and socket-ownership gates below (L1 keeps the helper/SOCKS proof).
_pw_dns_helper_l3_probe_name() {
	local conf="$1" root="$2" port="$3" name line dir file
	name=$(_pw_dns_helper_probe_name) || return 1
	{
		cat "$conf" || return 1
		while IFS= read -r line; do
			case "$line" in conf-dir=*) ;; *) continue ;; esac
			dir=${line#conf-dir=}
			case "$dir" in "$root"/cache/dnsmasq_*) ;; *) continue ;; esac
			[ -d "$dir" ] && [ ! -L "$dir" ] || continue
			for file in "$dir"/*; do
				[ -f "$file" ] && [ ! -L "$file" ] || continue
				cat "$file" || return 1
			done
		done <<EOF
$(grep -E '^conf-dir=' "$conf" 2>/dev/null)
EOF
	} | awk -v label="${name%%.*}" -v upstream="127.0.0.1#$port" '
		function valid(domain, parts, n, i) {
			if (length(domain) + length(label) + 1 > 253) return 0
			n = split(domain, parts, ".")
			for (i = 1; i <= n; i++)
				if (length(parts[i]) > 63 || parts[i] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0
			return n > 0
		}
		function routed(query, specificity, domain) {
			for (domain in other)
				if (length(domain) >= specificity && (domain == "" || query == domain ||
					substr(query, length(query) - length(domain)) == "." domain)) return 0
			return 1
		}
		/^(server|local|address)=/ {
			key = substr($0, 1, index($0, "=") - 1)
			value = substr($0, index($0, "=") + 1)
			if (value !~ /^\//) {
				if (key == "server") {
					if (value == upstream) remote_default = 1; else other_default = 1
				}
			} else {
				n = split(value, fields, "/")
				# IPv6-only address rules do not answer the A probe.
				if (key == "address" && fields[n] ~ /:/) next
				for (j = 2; j < n; j++) {
					domain = tolower(fields[j]); sub(/^\./, "", domain)
					if (domain == "#") domain = ""; else if (!valid(domain)) continue
					if (key == "server" && fields[n] == upstream) proxy[domain] = 1; else other[domain] = 1
				}
			}
		}
		END {
			if (remote_default && !other_default && routed(label ".invalid", 0)) { print label ".invalid"; exit }
			for (domain in proxy)
				if (routed(label "." (domain == "" ? "invalid" : domain), length(domain)) &&
					(!found || domain < chosen)) { chosen = domain; found = 1 }
			if (!found) exit 1
			print label "." (chosen == "" ? "invalid" : chosen)
		}'
}

# ---------------------------------------------------------------------------
# DNS-H4-F2-B: L3 end-to-end gate and the scope's dep_ready record.
#
# L3 drives one isolated dnsmasq instance from a one-time copy of the sealed H3
# fragment (only port/pid-file/log-facility differ) and requires: the fragment
# still sealed, dnsmasq --log-queries forwarding this attempt's unique probe to
# the frozen helper endpoint, a loopback capture of the UDP query and its
# response on the same source port, that source port's socket owned by the
# isolated PID (same-window /proc/net/udp + /proc/<pid>/fd), and the real helper
# logging the same probe. No production dnsmasq, /etc/config/dhcp or firewall
# path is read or written here.
# ---------------------------------------------------------------------------

# Sub-second sleep is not universal (BusyBox builds without fractional support
# reject it). A refused sleep falls back to one second, which only slows these
# bounded waits instead of turning them into busy loops.
_pw_dns_helper_pause() {
	sleep 0.1 2>/dev/null || sleep 1
}

# Stage a readable copy of every addn-hosts target the sealed fragment declares.
# dnsmasq drops to its unprivileged user before it reads hosts files, while the
# H3 capture keeps 0700 directories and 0600 assets owned by root, so the
# fragment's own targets are unreadable there. Only this attempt's directory is
# opened for traversal and only these copies become readable; the H3 root, its
# input directory and the captured assets keep their exact mode, owner and
# content. Every target must be a regular, non-symlink file inside the capture's
# input directory, and its digest is checked on both sides of the copy. Writes
# "SRC<TAB>COPY" to $4; an empty map means the fragment declares no hosts.
_pw_dns_helper_l3_stage_hosts() {
	local conf="$1" root="$2" tmp="$3" map="$4"
	local src= dst= before=
	[ -f "$conf" ] && [ ! -L "$conf" ] || return 1
	# The capture manifest is the seal for those assets; a changed one rejects.
	[ "$(md5sum < "$root/inputs.json" 2>/dev/null)" = "$(cat "$root/inputs.md5" 2>/dev/null)" ] || return 1
	( umask 077; mkdir "$tmp/ro" ) && chmod 0711 "$tmp/ro" || return 1
	: > "$map" || return 1
	while IFS= read -r src; do
		# The heredoc yields one empty line when the fragment declares no hosts;
		# an empty addn-hosts value is refused by the copy's coverage check.
		[ -n "$src" ] || continue
		case "$src" in "$root"/input/?*) ;; *) return 1 ;; esac
		[ -f "$src" ] && [ ! -L "$src" ] || return 1
		[ "$(readlink -f "$src")" = "$src" ] || return 1
		case "${src##*/}" in ''|.|..|*[!A-Za-z0-9._-]*) return 1 ;; esac
		dst="$tmp/ro/${src##*/}"
		[ ! -L "$dst" ] || return 1
		before=$(md5sum < "$src") || return 1
		if [ -e "$dst" ]; then
			[ "$(md5sum < "$dst")" = "$before" ] || return 1
		else
			cp -- "$src" "$dst" || return 1
			chmod 0644 "$dst" || return 1
			[ "$(md5sum < "$dst")" = "$before" ] || return 1
		fi
		[ "$(md5sum < "$src")" = "$before" ] || return 1
		printf '%s\t%s\n' "$src" "$dst" >> "$map" || return 1
	done <<EOF
$(sed -n 's/^addn-hosts=//p' "$conf")
EOF
	return 0
}

# Copy the sealed fragment once, rewriting exactly the three isolated fields and
# the addn-hosts targets covered by the staged map. Zero or multiple matches of a
# rewritten field fail, every staged target must be used, and every other line
# must stay byte-identical.
_pw_dns_helper_l3_copy() {
	local src="$1" dst="$2" port="$3" pidfile="$4" logfile="$5" map="$6"
	awk -v port="$port" -v pidfile="$pidfile" -v logfile="$logfile" -v map="$map" '
		BEGIN {
			while ((getline line < map) > 0) {
				split(line, field, "\t")
				if (field[1] != "" && field[2] != "") { staged[field[1]] = field[2]; total++ }
			}
			close(map)
		}
		/^port=/ { p++; print "port=" port; next }
		/^pid-file=/ { i++; print "pid-file=" pidfile; next }
		/^log-facility=/ { l++; print "log-facility=" logfile; next }
		/^addn-hosts=/ {
			hosts++
			if (!(substr($0, 12) in staged)) { bad = 1; exit 1 }
			print "addn-hosts=" staged[substr($0, 12)]
			next
		}
		{ print }
		END { if (bad || p != 1 || i != 1 || l != 1 || hosts != total) exit 1 }
	' "$src" > "$dst"
}

_pw_dns_helper_l3_run() {
	local conf="$1" root="$2" port="$3" dnsmasq="$4"
	local tmp= receipt= l3port= fport= pid= name= label= out= rc= result= src= inode= hex=
	local tcpdump_pid= sampler_pid= fwd= rep= qline= rline= payload= i= map=
	for i in tcpdump awk mktemp stat readlink md5sum cp chmod sed get_new_port check_port_exists; do
		command -v "$i" >/dev/null 2>&1 || {
			PW_DNS_HELPER_L3_PHASE=skip
			PW_DNS_HELPER_L3_ERROR="l3_tool_missing:$i"
			return 2
		}
	done
	if [ ! -f "$conf" ] || [ -L "$conf" ] || [ ! -f "$root/config.md5" ] ||
		[ ! -f "$root/config-seal.md5" ] || [ ! -f "$root/dnsmasq-test.status" ]; then
		PW_DNS_HELPER_L3_ERROR=l3_fragment_unsealed; return 2
	fi
	[ "$(md5sum < "$root/config.md5")" = "$(cat "$root/config-seal.md5")" ] || {
		PW_DNS_HELPER_L3_ERROR=l3_fragment_seal; return 2; }
	[ "$(cat "$root/dnsmasq-test.status")" = 0 ] || {
		PW_DNS_HELPER_L3_ERROR=l3_fragment_test; return 2; }
	_pw_dns_helper_fragment_upstream "$conf" "$root" "$port" || {
		PW_DNS_HELPER_L3_ERROR=l3_fragment_upstream; return 2; }
	name=$(_pw_dns_helper_l3_probe_name "$conf" "$root" "$port") && [ -n "$name" ] || {
		PW_DNS_HELPER_L3_ERROR=l3_probe_route; return 2; }

	tmp=$(umask 077; mktemp -d "$TMP_PATH/dns-l3.XXXXXX") || {
		PW_DNS_HELPER_L3_ERROR=l3_tempdir; return 1; }
	_PW_DNS_HELPER_L3_TMP=$tmp
	receipt=$(stat -c '%d:%i:%u' "$tmp") || receipt=
	_PW_DNS_HELPER_L3_RECEIPT=$receipt
	_pw_dns_helper_config_owned "$tmp" "$receipt" || {
		PW_DNS_HELPER_L3_ERROR=l3_tempdir_identity; return 1; }

	# dnsmasq drops to its unprivileged user before it reads hosts files, so the
	# path to the staged copies must be traversable by that user: TMP_PATH (last
	# octal digit = other's bits, x required) and this attempt's directory. Every
	# other file in here keeps its private mode; see the umask in
	# _pw_dns_helper_l3. A private TMP_PATH rejects here instead of degrading.
	case "$(stat -c '%a' "$TMP_PATH" 2>/dev/null)" in
		*[1357]) ;;
		*) PW_DNS_HELPER_L3_ERROR=l3_tempdir_mode; return 2 ;;
	esac
	chmod 0711 "$tmp" || { PW_DNS_HELPER_L3_ERROR=l3_tempdir_mode; return 2; }

	# The isolated instance never reuses the frozen helper port or the fragment's
	# own listen port. Reusing the latter would make the rewritten copy identical
	# and hide a wrong endpoint behind a no-op.
	fport=$(awk -F= '/^port=/ { print $2; exit }' "$conf" 2>/dev/null) || fport=
	case "$fport" in ''|*[!0-9]*) PW_DNS_HELPER_L3_ERROR=l3_fragment_port; return 2 ;; esac
	l3port=$(get_new_port 11400 tcp,udp) || l3port=
	case "$l3port" in ''|*[!0-9]*) PW_DNS_HELPER_L3_ERROR=l3_port; return 2 ;; esac
	if [ "$l3port" = "$port" ] || [ "$l3port" = "$fport" ]; then
		l3port=$(get_new_port $((fport + 1)) tcp,udp) || l3port=
		case "$l3port" in ''|*[!0-9]*) PW_DNS_HELPER_L3_ERROR=l3_port; return 2 ;; esac
	fi
	if [ "$l3port" = "$port" ] || [ "$l3port" = "$fport" ]; then
		PW_DNS_HELPER_L3_ERROR=l3_port; return 2
	fi
	PW_DNS_HELPER_L3_PORT=$l3port

	map="$tmp/hosts.map"
	_pw_dns_helper_l3_stage_hosts "$conf" "$root" "$tmp" "$map" || {
		PW_DNS_HELPER_L3_ERROR=l3_hosts_stage; return 2; }

	_pw_dns_helper_l3_copy "$conf" "$tmp/dnsmasq.conf" "$l3port" \
		"$tmp/dnsmasq.pid" "$tmp/dnsmasq.log" "$map" || {
		PW_DNS_HELPER_L3_ERROR=l3_fragment_copy; return 2; }
	# Prove the copy line by line with awk alone. `diff` is not part of every
	# BusyBox a target ships, and the sealed fragment must differ in exactly the
	# three rewritten fields plus one staged addn-hosts replacement per declared
	# hosts line and nothing else.
	awk -v port="$l3port" -v pidfile="$tmp/dnsmasq.pid" -v logfile="$tmp/dnsmasq.log" \
		-v map="$map" '
		BEGIN {
			while ((getline line < map) > 0) {
				split(line, field, "\t")
				if (field[1] != "" && field[2] != "") { stage[field[1]] = field[2]; staged++ }
			}
			close(map)
		}
		FNR == NR { src[FNR] = $0; n = FNR; next }
		{ dst[FNR] = $0; m = FNR }
		END {
			if (n == 0 || n != m) exit 1
			changed = 0; hosts = 0
			for (i = 1; i <= n; i++) {
				if (src[i] == dst[i]) continue
				changed++
				if (src[i] ~ /^port=/ && dst[i] == "port=" port) continue
				if (src[i] ~ /^pid-file=/ && dst[i] == "pid-file=" pidfile) continue
				if (src[i] ~ /^log-facility=/ && dst[i] == "log-facility=" logfile) continue
				if (src[i] ~ /^addn-hosts=/ &&
					dst[i] == "addn-hosts=" stage[substr(src[i], 12)]) { hosts++; continue }
				exit 1
			}
			if (changed != 3 + hosts || hosts != staged) exit 1
		}
	' "$conf" "$tmp/dnsmasq.conf" || {
		PW_DNS_HELPER_L3_ERROR=l3_fragment_diff; return 2; }

	"$dnsmasq" --keep-in-foreground --conf-file="$tmp/dnsmasq.conf" --log-queries \
		>> "$tmp/dnsmasq.out" 2>&1 &
	pid=$!
	_PW_DNS_HELPER_L3_DNSMASQ_PID=$pid
	# check_port_exists prints the number of matching listeners (0 = none), so
	# the count - not a command exit status - is what proves the bind. Wait for
	# the isolated instance to bind, then require it still alive and listening.
	i=0
	while [ "$i" -lt 50 ]; do
		kill -0 "$pid" 2>/dev/null || break
		[ "$(check_port_exists "$l3port" udp)" != 0 ] && break
		i=$((i + 1)); _pw_dns_helper_pause
	done
	{ kill -0 "$pid" 2>/dev/null && [ "$(check_port_exists "$l3port" udp)" != 0 ]; } || {
		PW_DNS_HELPER_L3_ERROR=l3_dnsmasq_start; return 2; }

	tcpdump -i lo -n -U -w "$tmp/cap.pcap" "udp and port $port" > "$tmp/tcpdump.out" 2>&1 &
	tcpdump_pid=$!
	_PW_DNS_HELPER_L3_TCPDUMP_PID=$tcpdump_pid
	i=0
	while [ "$i" -lt 50 ]; do
		kill -0 "$tcpdump_pid" 2>/dev/null || break
		[ -f "$tmp/cap.pcap" ] && break
		i=$((i + 1)); _pw_dns_helper_pause
	done
	{ kill -0 "$tcpdump_pid" 2>/dev/null && [ -f "$tmp/cap.pcap" ]; } || {
		PW_DNS_HELPER_L3_ERROR=l3_capture_unavailable; return 2; }
	_pw_dns_helper_pause

	# Same-window socket ownership sampler. A block is written only while the
	# isolated PID actually holds sockets, and it contains just that PID's fd
	# inodes plus the /proc/net/udp rows for those same inodes. A captured source
	# port can therefore be tied to the isolated instance without a transient ss
	# sample, and a query that never happens writes nothing instead of growing
	# the private directory.
	(
		i=0
		while [ ! -e "$tmp/stop" ] && [ "$i" -lt 20000 ]; do
			ls -l "/proc/$pid/fd" 2>/dev/null |
				sed -n 's/.*socket:\[\([0-9]*\)\].*/inode \1/p' > "$tmp/fd.now"
			if [ -s "$tmp/fd.now" ]; then
				printf '== %s\n' "$i" >> "$tmp/sample.txt"
				awk 'FNR == NR { want[$2] = 1; print; next } ($10 in want)' \
					"$tmp/fd.now" /proc/net/udp >> "$tmp/sample.txt" 2>/dev/null
			fi
			i=$((i + 1))
		done
	) &
	sampler_pid=$!
	_PW_DNS_HELPER_L3_SAMPLER_PID=$sampler_pid
	_pw_dns_helper_pause

	label=${name%%.*}
	PW_DNS_HELPER_L3_QUERY_NAME=$name
	out="$tmp/l3.out"
	rc=0
	nslookup -type=A "$name" "127.0.0.1:$l3port" > "$out" 2>&1 || rc=$?
	result=$(_pw_dns_helper_l1_classify "$out" "$rc" "$name")
	_pw_dns_helper_pause

	: > "$tmp/stop"
	wait "$sampler_pid" 2>/dev/null
	_PW_DNS_HELPER_L3_SAMPLER_PID=
	kill -TERM "$tcpdump_pid" 2>/dev/null
	wait "$tcpdump_pid" 2>/dev/null
	_PW_DNS_HELPER_L3_TCPDUMP_PID=

	[ "$result" != failed ] || { PW_DNS_HELPER_L3_ERROR=l3_response; return 2; }
	fwd=$(grep -c -F "forwarded $name to 127.0.0.1#$port" "$tmp/dnsmasq.log" 2>/dev/null) || fwd=0
	rep=$(grep -c -F "reply $name is" "$tmp/dnsmasq.log" 2>/dev/null) || rep=0
	{ [ "$fwd" -ge 1 ] && [ "$rep" -ge 1 ]; } || {
		PW_DNS_HELPER_L3_ERROR=l3_dnsmasq_forward; return 2; }
	# dnsmasq only logs an unreadable hosts file and keeps serving, so a missing
	# copy would pass every gate below while the fragment silently lost its local
	# names. The staged copies exist so this line must never appear.
	if grep -Fq 'failed to load names from' "$tmp/dnsmasq.log" 2>/dev/null; then
		PW_DNS_HELPER_L3_ERROR=l3_hosts_unreadable; return 2
	fi

	qline=$(tcpdump -nn -r "$tmp/cap.pcap" 2>/dev/null | grep -F "> 127.0.0.1.$port: UDP" | head -1)
	src=$(printf '%s\n' "$qline" | awk -v p="$port" '
		{ for (i = 1; i < NF; i++) if ($i == ">" && $(i + 1) == "127.0.0.1." p ":") {
			n = split($(i - 1), a, "."); if (n == 5) { print a[5]; exit } } }')
	case "$src" in ''|*[!0-9]*) PW_DNS_HELPER_L3_ERROR=l3_capture_query; return 2 ;; esac
	rline=$(tcpdump -nn -r "$tmp/cap.pcap" 2>/dev/null | grep -F "127.0.0.1.$port > 127.0.0.1.$src: UDP" | head -1)
	[ -n "$rline" ] || { PW_DNS_HELPER_L3_ERROR=l3_capture_response; return 2; }
	payload=$(tcpdump -nn -A -r "$tmp/cap.pcap" 2>/dev/null | grep -c -F "$label") || payload=0
	[ "$payload" -ge 1 ] || { PW_DNS_HELPER_L3_ERROR=l3_capture_payload; return 2; }

	hex=$(printf '%04X' "$src") || hex=
	case "$hex" in ''|*[!0-9A-F]*) PW_DNS_HELPER_L3_ERROR=l3_socket_port; return 2 ;; esac
	inode=$(awk -v p=":$hex" '$2 ~ p"$" { print $10; exit }' "$tmp/sample.txt" 2>/dev/null) || inode=
	case "$inode" in ''|*[!0-9]*) PW_DNS_HELPER_L3_ERROR=l3_socket_inode; return 2 ;; esac
	grep -Fqx "inode $inode" "$tmp/sample.txt" || {
		PW_DNS_HELPER_L3_ERROR=l3_socket_owner; return 2; }

	PW_DNS_HELPER_L3_PID=$pid
	PW_DNS_HELPER_L3_SRC_PORT=$src
	PW_DNS_HELPER_L3_INODE=$inode
	PW_DNS_HELPER_L3_PHASE=pass
	PW_DNS_HELPER_L3_EVIDENCE="forwarded=$fwd reply=$rep src=$src dst=127.0.0.1#$port inode=$inode payload=$payload port=$l3port isolated=$pid"
	return 0
}

# Stop this attempt's isolated processes and remove only its own directory. An
# unconfirmable stop or directory change keeps the private artifacts and fails.
_pw_dns_helper_l3_cleanup() {
	local tmp="$_PW_DNS_HELPER_L3_TMP" receipt="$_PW_DNS_HELPER_L3_RECEIPT"
	local pid="$_PW_DNS_HELPER_L3_DNSMASQ_PID" i=
	[ -n "$tmp" ] || return 0
	if [ -n "${_PW_DNS_HELPER_L3_SAMPLER_PID:-}" ]; then
		: > "$tmp/stop" 2>/dev/null
		wait "$_PW_DNS_HELPER_L3_SAMPLER_PID" 2>/dev/null
		_PW_DNS_HELPER_L3_SAMPLER_PID=
	fi
	if [ -n "${_PW_DNS_HELPER_L3_TCPDUMP_PID:-}" ]; then
		kill -TERM "$_PW_DNS_HELPER_L3_TCPDUMP_PID" 2>/dev/null
		wait "$_PW_DNS_HELPER_L3_TCPDUMP_PID" 2>/dev/null
		_PW_DNS_HELPER_L3_TCPDUMP_PID=
	fi
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null
		i=0
		while [ "$i" -lt 20 ]; do
			kill -0 "$pid" 2>/dev/null || break
			i=$((i + 1)); _pw_dns_helper_pause
		done
		kill -KILL "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		kill -0 "$pid" 2>/dev/null && return 1
		_PW_DNS_HELPER_L3_DNSMASQ_PID=
	fi
	_pw_dns_helper_config_discard "$tmp" "$receipt" || return 1
	_PW_DNS_HELPER_L3_TMP= _PW_DNS_HELPER_L3_RECEIPT=
}

# FRAGMENT CONF_ROOT HELPER_PORT DNSMASQ_BINARY
# 0=L3 passed, 2=rejected (no dep_ready), 1=cleanup unconfirmed.
_pw_dns_helper_l3() {
	local rc=0 saved_umask=
	_pw_dns_helper_l3_reset
	# This attempt's directory is made traversable for the unprivileged dnsmasq
	# user, so every artifact created inside it stays private by construction and
	# only the staged hosts copies are opened up afterwards.
	saved_umask=$(umask) || saved_umask=
	umask 077
	_pw_dns_helper_l3_run "$@" || rc=$?
	[ -n "$PW_DNS_HELPER_L3_PHASE" ] || PW_DNS_HELPER_L3_PHASE=fail
	if ! _pw_dns_helper_l3_cleanup; then
		[ -z "$saved_umask" ] || umask "$saved_umask"
		[ -n "$PW_DNS_HELPER_L3_ERROR" ] || PW_DNS_HELPER_L3_ERROR=l3_cleanup
		PW_DNS_HELPER_L3_PHASE=fail
		return 1
	fi
	[ -z "$saved_umask" ] || umask "$saved_umask"
	return "$rc"
}

# Publish this scope's dep_ready record. Only a helper that passed L1, L2, L3
# and the outer gate may reach here, and the record is bound to the helper
# identity this call created, the frozen endpoint and the published instance.
# PHASE=ready alone is never a DNS switch authorization.
_pw_dns_helper_publish_ready() {
	local dir="${PW_DNS_HELPER_SCOPE_DIR:-}" body= expected= actual=
	[ -n "$dir" ] && [ -n "${PW_DNS_HELPER_PID:-}" ] && [ -n "${PW_DNS_HELPER_BIRTH:-}" ] &&
		[ -n "${PW_DNS_HELPER_CMDLINE_MD5:-}" ] && [ -n "${PW_DNS_HELPER_BIN:-}" ] &&
		[ -n "${PW_DNS_HELPER_LISTEN_ADDR:-}" ] && [ -n "${PW_DNS_HELPER_LISTEN_PORT:-}" ] &&
		[ -n "${PW_DNS_HELPER_REC_INSTANCE:-}" ] && [ -n "${PW_DNS_HELPER_REC_SOCKS_PORT:-}" ] &&
		[ -n "${PW_DNS_HELPER_CONFIG_MD5:-}" ] || return 1
	[ "${PW_DNS_HELPER_PHASE:-}" = ready ] && [ "${PW_DNS_HELPER_L3_PHASE:-}" = pass ] || return 1
	[ "${PW_DNS_HELPER_QUERY_RESULT:-}" != failed ] || return 1
	body=$(printf '%s\n' \
		"scope=$PW_DNS_HELPER_REC_SCOPE" \
		"generation=$PW_DNS_HELPER_REC_GENERATION" \
		"instance_dir=$PW_DNS_HELPER_REC_INSTANCE" \
		"socks_addr=$PW_DNS_HELPER_REC_SOCKS_ADDR" \
		"socks_port=$PW_DNS_HELPER_REC_SOCKS_PORT" \
		"helper_pid=$PW_DNS_HELPER_PID" \
		"helper_birth=$PW_DNS_HELPER_BIRTH" \
		"helper_executable=$PW_DNS_HELPER_BIN" \
		"helper_cmdline_md5=$PW_DNS_HELPER_CMDLINE_MD5" \
		"listen_addr=$PW_DNS_HELPER_LISTEN_ADDR" \
		"listen_port=$PW_DNS_HELPER_LISTEN_PORT" \
		"identity_md5=$PW_DNS_HELPER_REC_IDENTITY_MD5" \
		"config_md5=$PW_DNS_HELPER_REC_CONFIG_MD5" \
		"helper_config_dir=$PW_DNS_HELPER_CONFIG_DIR" \
		"helper_config_md5=$PW_DNS_HELPER_CONFIG_MD5" \
		"l1=pass" "l2=pass" "l3=pass" "outer=pass")
	_pw_dns_helper_write_file "$dir" dep.ready "$body" || return 1
	expected=$(printf '%s\n' "$body" | md5sum) && actual=$(md5sum < "$dir/dep.ready") || return 1
	[ "${expected%% *}" = "${actual%% *}" ] || return 1
	PW_DNS_HELPER_DEP_READY=$dir/dep.ready
}

# SNAPSHOT ROLE SID PREFERENCE FAMILY CANDIDATE_JSON BASE_DNSMASQ_CONF
# DNSMASQ_BINARY LISTEN_PORT REQUEST_JSON
# LISTEN_PORT and REQUEST_JSON stay caller-supplied because the H3 generator
# requires the prospective helper port inside -TUN_DNS; the allocator above
# exists so the caller does not reimplement allocation.
passwall_start_dns_helper() {
	_pw_dns_helper_reset
	_pw_dns_helper_start_reset
	[ "$#" = 10 ] || { _pw_dns_helper_error 1 dns_dep_argument; return; }
	command -v _pw_bound_helper >/dev/null 2>&1 && [ -n "${PW_BOUND_HELPER:-}" ] &&
		command -v _pw_global_ss_kill >/dev/null 2>&1 || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	local snapshot="$1" role="$2" sid="$3" preference="$4" family="$5" candidate="$6"
	local base="$7" dnsmasq="$8" port="$9" request="${10}"
	local dir= receipt= rc=0 reason= phase=spawn pid= birth= name= out= result= rdns=

	passwall_check_dns_helper_candidate "$snapshot" "$role" "$sid" "$preference" "$family" "$candidate" || return $?

	_pw_dns_helper_preflight "$dnsmasq" || rc=$?
	case "$rc" in
		0) ;;
		2) _pw_dns_helper_error 2 dns_dep_tool_missing; return ;;
		*) _pw_dns_helper_error 1 dns_dep_argument; return ;;
	esac

	dir=$(_pw_dns_helper_scope_dir "$role" "$sid") || { _pw_dns_helper_start_error 1 dns_dep_argument; return; }
	_pw_dns_helper_scope_owned "$dir" || { _pw_dns_helper_start_error 1 dns_dep_identity; return; }
	receipt=$(stat -c '%d:%i:%u' "$dir") || receipt=
	[ -n "$receipt" ] || { _pw_dns_helper_start_error 1 dns_dep_identity; return; }

	case "$port" in ''|*[!0-9]*) _pw_dns_helper_start_error 1 dns_dep_argument; return ;; esac
	[ "$port" -ge 1025 ] && [ "$port" -le 49151 ] || {
		_pw_dns_helper_start_error 1 dns_dep_argument; return;
	}
	[ "$(check_port_exists "$port" udp)" = 0 ] || {
		_pw_dns_helper_start_error 2 dns_dep_helper_start; return;
	}

	_pw_dns_helper_read_binding "$candidate" "$dir" || {
		_pw_dns_helper_start_error 1 dns_dep_identity; return;
	}
	case "$role" in
		global) [ "$PW_DNS_HELPER_REC_SCOPE" = global ] || {
			_pw_dns_helper_start_error 1 dns_dep_identity; return; } ;;
		acl) [ "$PW_DNS_HELPER_REC_SCOPE" = "acl:$sid" ] || {
			_pw_dns_helper_start_error 1 dns_dep_identity; return; } ;;
	esac

	PW_DNS_HELPER_LISTEN_ADDR=127.0.0.1
	PW_DNS_HELPER_LISTEN_PORT=$port
	PW_DNS_HELPER_SCOPE_DIR=$dir
	PW_DNS_HELPER_BINDING=$dir/helper.binding
	PW_DNS_HELPER_RECORD=$dir/helper.record
	PW_DNS_HELPER_LOG=$dir/helper.log

	# A previous generation's claim never survives a new attempt: the record is
	# rewritten only after every gate below passes again.
	rm -f -- "$dir/dep.ready" || { _pw_dns_helper_start_error 1 dns_dep_identity; return; }
	[ ! -e "$dir/dep.ready" ] || { _pw_dns_helper_start_error 1 dns_dep_identity; return; }

	# Stage B step 2: freeze the scope binding before any fragment exists.
	_pw_dns_helper_write_file "$dir" helper.binding "$(printf '%s\n' \
		"scope=$PW_DNS_HELPER_REC_SCOPE" \
		"generation=$PW_DNS_HELPER_REC_GENERATION" \
		"instance_dir=$PW_DNS_HELPER_REC_INSTANCE" \
		"socks_addr=$PW_DNS_HELPER_REC_SOCKS_ADDR" \
		"socks_port=$PW_DNS_HELPER_REC_SOCKS_PORT" \
		"listen_addr=127.0.0.1" \
		"listen_port=$port" \
		"remote_dns=$PW_DNS_HELPER_REC_REMOTE_DNS" \
		"dns_cache=$PW_DNS_HELPER_REC_CACHE" \
		"identity_md5=$PW_DNS_HELPER_REC_IDENTITY_MD5" \
		"config_md5=$PW_DNS_HELPER_REC_CONFIG_MD5")" || {
		_pw_dns_helper_start_error 1 dns_dep_identity; return;
	}

	# Stage B steps 3-5: reuse H3 unchanged. It captures, generates, runs --test
	# and seals; a failure here leaves no helper process at all.
	passwall_generate_dns_helper_config "$snapshot" "$request" "$base" "$dnsmasq" || rc=$?
	if [ "$rc" != 0 ]; then
		reason=${PW_DNS_HELPER_REASON:-dns_dep_config_invalid}
		phase=fragment
		_pw_dns_helper_drop_records "$dir"
		_pw_dns_helper_start_error "$rc" "$reason"
		PW_DNS_HELPER_PHASE=$phase
		return "$rc"
	fi
	PW_DNS_HELPER_FRAGMENT_RECEIPT=$(stat -c '%d:%i:%u' "$PW_DNS_HELPER_CONFIG_DIR" 2>/dev/null) ||
		PW_DNS_HELPER_FRAGMENT_RECEIPT=

	# The generated fragment must route to the frozen binding byte for byte.
	# A domain-split upstream in the generated conf-dir is as frozen as the
	# scope default line: `use_default_dns=direct` puts the helper there.
	if ! _pw_dns_helper_fragment_upstream "$PW_DNS_HELPER_CONFIG" "$PW_DNS_HELPER_CONFIG_DIR" "$port"; then
		phase=fragment
		_pw_dns_helper_discard_fragment
		_pw_dns_helper_drop_records "$dir"
		_pw_dns_helper_start_error 2 dns_dep_config_invalid
		PW_DNS_HELPER_PHASE=$phase
		return 2
	fi

	# Stage B step 6: the same no-auth argv form the probe derives, launched by
	# the existing bound spawn (GID 9911 + returned PID). Never ln_run: it does
	# not return a PID, it execs through a symlink, and it sets no GID.
	rdns=$(printf '%s\n' "$PW_DNS_HELPER_REC_REMOTE_DNS" | sed 's/#/:/')
	set -- "$PW_DNS_HELPER_BIN"
	[ "$PW_DNS_HELPER_REC_CACHE" = 0 ] && set -- "$@" /d
	set -- "$@" "$PW_DNS_HELPER_REC_SOCKS_ADDR:$PW_DNS_HELPER_REC_SOCKS_PORT" "$rdns" "127.0.0.1:$port"
	: > "$PW_DNS_HELPER_LOG" || {
		phase=spawn
		_pw_dns_helper_discard_fragment
		_pw_dns_helper_drop_records "$dir"
		_pw_dns_helper_start_error 1 dns_dep_helper_start
		PW_DNS_HELPER_PHASE=$phase
		return 1
	}
	pid=$(_pw_bound_helper spawn "$PW_DNS_HELPER_LOG" "$@") || pid=
	if [ -z "$pid" ]; then
		phase=spawn
		_pw_dns_helper_discard_fragment
		_pw_dns_helper_drop_records "$dir"
		_pw_dns_helper_start_error 2 dns_dep_helper_start
		PW_DNS_HELPER_PHASE=$phase
		return 2
	fi
	birth=$(get_process_start_time "$pid") || birth=
	case "$birth" in ''|*[!0-9]*) birth= ;; esac
	if [ -z "$birth" ]; then
		# No birth means no ownership proof, so this PID is never signalled.
		# Keep the binding and the PID as precise retry information.
		_pw_dns_helper_discard_fragment
		PW_DNS_HELPER_PHASE=spawn
		PW_DNS_HELPER_PID=$pid
		_pw_dns_helper_reset
		PW_DNS_HELPER_REASON=dns_dep_helper_start
		return 1
	fi
	PW_DNS_HELPER_PID=$pid
	PW_DNS_HELPER_BIRTH=$birth

	# Persist ownership before any step that can fail. Every field is already
	# known here, and a record that exists before verification is what keeps the
	# attempt stoppable when verification (or a later caller) aborts. The record
	# never authorizes a signal on its own: passwall_stop_dns_helper re-verifies
	# PID, birth, executable and command line against /proc every time.
	PW_DNS_HELPER_CMDLINE_MD5=$(md5sum < "/proc/$pid/cmdline" 2>/dev/null) || PW_DNS_HELPER_CMDLINE_MD5=
	PW_DNS_HELPER_CMDLINE_MD5=${PW_DNS_HELPER_CMDLINE_MD5%% *}
	if [ -z "$PW_DNS_HELPER_CMDLINE_MD5" ] ||
		! _pw_dns_helper_write_file "$dir" helper.record "$(printf '%s\n' \
			"scope=$PW_DNS_HELPER_REC_SCOPE" \
			"generation=$PW_DNS_HELPER_REC_GENERATION" \
			"instance_dir=$PW_DNS_HELPER_REC_INSTANCE" \
			"listen_addr=127.0.0.1" \
			"listen_port=$port" \
			"pid=$pid" \
			"birth=$birth" \
			"executable=$PW_DNS_HELPER_BIN" \
			"cmdline_md5=$PW_DNS_HELPER_CMDLINE_MD5" \
			"identity_md5=$PW_DNS_HELPER_REC_IDENTITY_MD5" \
			"config_md5=$PW_DNS_HELPER_REC_CONFIG_MD5" \
			"helper_config_dir=$PW_DNS_HELPER_CONFIG_DIR" \
			"helper_config_md5=$PW_DNS_HELPER_CONFIG_MD5")"; then
		# Without a usable record this PID must not outlive the attempt, so it is
		# stopped while this call still holds its PID and birth.
		_pw_dns_helper_rollback 1 dns_dep_identity record
		return $?
	fi

	# Identity and listener ownership, before any outer connection or query.
	passwall_observe_dns_helper "$snapshot" "$role" "$sid" "$preference" "$family" "$candidate" \
		"$pid" "$birth" "$PW_DNS_HELPER_BIN" "$port" || rc=$?
	if [ "$rc" != 0 ]; then
		reason=${PW_DNS_HELPER_REASON:-dns_dep_identity}
		_pw_dns_helper_rollback "$rc" "$reason" identity
		return $?
	fi
	PW_DNS_HELPER_OBSERVATION=$PW_DNS_HELPER_JSON

	# L1: one query, one explicitly named server, no fallback resolver. A helper
	# that cannot be reached must not silently borrow a public resolver.
	name=$(_pw_dns_helper_probe_name)
	PW_DNS_HELPER_QUERY_NAME=$name
	out="$dir/helper.l1.log"
	rc=0
	nslookup -type=A "$name" "127.0.0.1:$port" > "$out" 2>&1 || rc=$?
	result=$(_pw_dns_helper_l1_classify "$out" "$rc" "$name")
	PW_DNS_HELPER_QUERY_RESULT=$result
	[ "$result" != failed ] || {
		_pw_dns_helper_rollback 2 dns_dep_dns_query l1
		return $?
	}

	# Outer evidence (3.3 step 7 limited clause): dns2socks has no direct egress,
	# so its only upstream is the frozen SOCKS endpoint in argv. A query this
	# helper actually received can therefore only be answered through that
	# instance. The helper's stdout/stderr sink is truncated above and bound to
	# this PID at spawn, and the probe name is unique to this attempt, so a line
	# naming it can only come from this attempt's helper. This proves receipt
	# only; the response half is judged independently by L1 above.
	grep -Fq -- "$name" "$PW_DNS_HELPER_LOG" 2>/dev/null || {
		_pw_dns_helper_rollback 2 dns_dep_outer outer
		return $?
	}

	# L3: the sealed fragment itself must drive an isolated dnsmasq to this
	# helper. L1 above never substitutes for it, and an unverifiable L3 (missing
	# capture tooling) rejects publication instead of being reported as pass.
	# rc is reset first: nslookup reports NXDOMAIN as a non-zero exit, so the L1
	# status above must never be read back as this gate's result.
	rc=0
	_pw_dns_helper_l3 "$PW_DNS_HELPER_CONFIG" "$PW_DNS_HELPER_CONFIG_DIR" "$port" "$dnsmasq" || rc=$?
	if [ "$rc" != 0 ]; then
		reason=dns_dep_dns_query
		[ "$rc" = 1 ] || rc=2
		_pw_dns_helper_rollback "$rc" "$reason" l3
		return $?
	fi

	PW_DNS_HELPER_PHASE=ready
	# Stage B step 9: publish the scope's dep_ready record. Failing here leaves
	# no claim and no helper process behind.
	_pw_dns_helper_publish_ready || {
		_pw_dns_helper_rollback 1 dns_dep_identity publish
		return $?
	}
}

# SNAPSHOT ROLE SID
# Idempotent: no record means this adapter owns nothing here. Every signal is
# gated by the record's PID/birth/executable/command-line digest; an unreadable
# or mismatching record refuses instead of falling back to port or name matching.
# "Nothing owned" is decided before the process helpers are required, so a
# caller may use this as an idempotent pre-delete hook for any scope: an absent
# directory, an absent record and a directory without a record all return 0.
passwall_stop_dns_helper() {
	_pw_dns_helper_reset
	_pw_dns_helper_start_reset
	[ "$#" = 3 ] || { _pw_dns_helper_error 1 dns_dep_argument; return; }
	local role="$2" sid="$3" dir=
	dir=$(_pw_dns_helper_scope_dir "$role" "$sid") || { _pw_dns_helper_error 1 dns_dep_argument; return; }
	# Without an ownership record no claim here can still describe a live helper.
	[ -e "$dir/helper.record" ] || [ -L "$dir/helper.record" ] || {
		rm -f -- "$dir/dep.ready"
		return 0
	}
	command -v _pw_global_ss_kill >/dev/null 2>&1 &&
		command -v _pw_global_ss_state >/dev/null 2>&1 || {
		_pw_dns_helper_error 1 dns_dep_argument; return;
	}
	_pw_dns_helper_scope_owned "$dir" || { _pw_dns_helper_error 1 dns_dep_identity; return; }
	# A stop attempt invalidates this scope's readiness claim immediately, even
	# when the stop itself cannot be confirmed: a claim must never be reused
	# after anyone tried to release the helper it describes. The ownership
	# records stay, because they are what authorizes the retry.
	rm -f -- "$dir/dep.ready" || { _pw_dns_helper_error 1 dns_dep_identity; return; }
	PW_DNS_HELPER_SCOPE_DIR=$dir
	_pw_dns_helper_record_read "$dir" || { _pw_dns_helper_error 1 dns_dep_identity; return; }

	# Triple condition for locating this helper: the scope directory it was read
	# from, its generation and its instance path.
	case "$role" in
		global) [ "$PW_DNS_HELPER_REC_SCOPE" = global ] ;;
		acl) [ "$PW_DNS_HELPER_REC_SCOPE" = "acl:$sid" ] ;;
		*) false ;;
	esac || { _pw_dns_helper_error 1 dns_dep_identity; return; }
	case "$PW_DNS_HELPER_REC_GENERATION" in
		generation.*) ;;
		*) _pw_dns_helper_error 1 dns_dep_identity; return ;;
	esac
	case "$PW_DNS_HELPER_REC_INSTANCE" in
		/*) ;;
		*) _pw_dns_helper_error 1 dns_dep_identity; return ;;
	esac
	[ "$PW_DNS_HELPER_REC_LISTEN_ADDR" = 127.0.0.1 ] ||
		{ _pw_dns_helper_error 1 dns_dep_identity; return; }

	case "$(_pw_global_ss_state "$PW_DNS_HELPER_REC_PID" "$PW_DNS_HELPER_REC_BIRTH")" in
		exited|reused|zombie) ;;   # already gone: only stale records remain
		alive)
			lua "$PW_DNS_HELPER_PROBE" identity "$PW_DNS_HELPER_REC_PID" "$PW_DNS_HELPER_REC_BIRTH" \
				"$PW_DNS_HELPER_REC_EXECUTABLE" "$PW_DNS_HELPER_REC_CMDLINE_MD5" >/dev/null 2>&1 || {
				_pw_dns_helper_error 1 dns_dep_identity; return;
			}
			_pw_global_ss_kill "$PW_DNS_HELPER_REC_PID" "$PW_DNS_HELPER_REC_BIRTH" || {
				_pw_dns_helper_error 1 dns_dep_identity; return;
			}
			;;
		*) _pw_dns_helper_error 1 dns_dep_identity; return ;;
	esac

	# Listener must be released before the record is dropped.
	[ "$(check_port_exists "$PW_DNS_HELPER_REC_LISTEN_PORT" udp)" = 0 ] || {
		_pw_dns_helper_error 1 dns_dep_identity; return;
	}
	_pw_dns_helper_drop_records "$dir" || { _pw_dns_helper_error 1 dns_dep_identity; return; }
	PW_DNS_HELPER_PHASE=stopped
}

# ---------------------------------------------------------------------------
# DNS-H4-F2-B-R2: consume-before-use validity of this scope's dep_ready claim.
#
# dep_ready records the state at publication time and is never an authorization
# on its own (contract 3.5). This entry re-reads it and rejects it unless every
# dependency it names still exists, still belongs to the same generation and the
# published instance, and is still owned by the processes the records name. A
# live helper is not evidence that its SOCKS instance is usable, so the
# instance's own receipt and listening socket are checked separately.
#
# Read-only: no record is rewritten or removed and no process is signalled. A
# rejected claim is left in place; reclaiming it stays the stop path's job.
#
# ROLE SID SNAPSHOT
# 0 = the claim describes a usable dependency at this instant.
# 1 = it does not; PW_DNS_HELPER_CHECK_DETAIL names the first failed check.
# A successful result describes this instant only and promises nothing later.
# ---------------------------------------------------------------------------
_pw_dns_helper_claim_reset() {
	PW_DNS_HELPER_CLAIM_SCOPE= PW_DNS_HELPER_CLAIM_GENERATION= PW_DNS_HELPER_CLAIM_INSTANCE=
	PW_DNS_HELPER_CLAIM_SOCKS_ADDR= PW_DNS_HELPER_CLAIM_SOCKS_PORT=
	PW_DNS_HELPER_CLAIM_PID= PW_DNS_HELPER_CLAIM_BIRTH= PW_DNS_HELPER_CLAIM_EXECUTABLE=
	PW_DNS_HELPER_CLAIM_CMDLINE_MD5= PW_DNS_HELPER_CLAIM_LISTEN_ADDR= PW_DNS_HELPER_CLAIM_LISTEN_PORT=
	PW_DNS_HELPER_CHECK_DETAIL= PW_DNS_HELPER_CHECK_INSTANCE= PW_DNS_HELPER_CHECK_SOCKS_PID=
}

# A claim that cannot be checked is invalid, never "probably fine".
_pw_dns_helper_check_fail() {
	PW_DNS_HELPER_CHECK_DETAIL=$1
	_pw_dns_helper_error 1 "${2:-dns_dep_identity}"
	return 1
}

# Strict key=value reader for the claim. Unknown, empty or duplicated keys are
# rejected instead of guessed, and the file is never eval'd.
_pw_dns_helper_claim_read() {
	local file="$1/dep.ready" line key value
	_pw_dns_helper_claim_reset
	[ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 1
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '') continue ;; esac
		key=${line%%=*}
		value=${line#*=}
		[ "$key" != "$line" ] && [ -n "$value" ] || return 1
		case "$key" in
			scope) PW_DNS_HELPER_CLAIM_SCOPE=$value ;;
			generation) PW_DNS_HELPER_CLAIM_GENERATION=$value ;;
			instance_dir) PW_DNS_HELPER_CLAIM_INSTANCE=$value ;;
			socks_addr) PW_DNS_HELPER_CLAIM_SOCKS_ADDR=$value ;;
			socks_port) PW_DNS_HELPER_CLAIM_SOCKS_PORT=$value ;;
			helper_pid) PW_DNS_HELPER_CLAIM_PID=$value ;;
			helper_birth) PW_DNS_HELPER_CLAIM_BIRTH=$value ;;
			helper_executable) PW_DNS_HELPER_CLAIM_EXECUTABLE=$value ;;
			helper_cmdline_md5) PW_DNS_HELPER_CLAIM_CMDLINE_MD5=$value ;;
			listen_addr) PW_DNS_HELPER_CLAIM_LISTEN_ADDR=$value ;;
			listen_port) PW_DNS_HELPER_CLAIM_LISTEN_PORT=$value ;;
			identity_md5|config_md5|helper_config_dir|helper_config_md5) ;;
			l1|l2|l3|outer) [ "$value" = pass ] || return 1 ;;
			*) return 1 ;;
		esac
	done < "$file"
	[ -n "$PW_DNS_HELPER_CLAIM_SCOPE" ] && [ -n "$PW_DNS_HELPER_CLAIM_GENERATION" ] &&
		[ -n "$PW_DNS_HELPER_CLAIM_INSTANCE" ] && [ -n "$PW_DNS_HELPER_CLAIM_SOCKS_ADDR" ] &&
		[ -n "$PW_DNS_HELPER_CLAIM_SOCKS_PORT" ] && [ -n "$PW_DNS_HELPER_CLAIM_PID" ] &&
		[ -n "$PW_DNS_HELPER_CLAIM_BIRTH" ] && [ -n "$PW_DNS_HELPER_CLAIM_EXECUTABLE" ] &&
		[ -n "$PW_DNS_HELPER_CLAIM_CMDLINE_MD5" ] && [ -n "$PW_DNS_HELPER_CLAIM_LISTEN_ADDR" ] &&
		[ -n "$PW_DNS_HELPER_CLAIM_LISTEN_PORT" ]
}

passwall_check_dns_helper_ready() {
	local role="${1:-}" sid="${2:-}" snapshot="${3:-}"
	local dir= instance= socks= spid= sbirth=
	# Only this entry's own scratch is cleared: a read-only check must not wipe
	# the start outputs a caller may still be holding.
	_pw_dns_helper_reset
	_pw_dns_helper_rec_reset
	_pw_dns_helper_claim_reset
	# Only the canonical Global scope has an unambiguous published-instance
	# pointer. An ACL scope is refused here rather than verified by assumption.
	[ "$#" = 3 ] && [ "$role" = global ] ||
		{ _pw_dns_helper_check_fail argument dns_dep_argument; return 1; }
	[ -n "$snapshot" ] && [ "${snapshot%/*}" != "$snapshot" ] ||
		{ _pw_dns_helper_check_fail snapshot_argument dns_dep_argument; return 1; }
	# Every mechanism below already exists; if one is absent the claim cannot be
	# checked, so it is not accepted.
	command -v _pw_global_ss_state >/dev/null 2>&1 &&
		command -v _pw_global_ss_alive >/dev/null 2>&1 &&
		command -v _pw_global_ss_socket >/dev/null 2>&1 &&
		command -v get_cache_var >/dev/null 2>&1 &&
		command -v get_process_start_time >/dev/null 2>&1 &&
		command -v passwall_snapshot_check >/dev/null 2>&1 &&
		[ -n "${GLOBAL_ACL_PATH:-}" ] &&
		[ -n "${PW_DNS_HELPER_PROBE:-}" ] && [ -f "$PW_DNS_HELPER_PROBE" ] ||
		{ _pw_dns_helper_check_fail tool dns_dep_identity; return 1; }

	dir=$(_pw_dns_helper_scope_dir "$role" "$sid") ||
		{ _pw_dns_helper_check_fail scope dns_dep_identity; return 1; }
	_pw_dns_helper_scope_owned "$dir" ||
		{ _pw_dns_helper_check_fail scope dns_dep_identity; return 1; }
	_pw_dns_helper_claim_read "$dir" ||
		{ _pw_dns_helper_check_fail claim dns_dep_identity; return 1; }
	[ "$PW_DNS_HELPER_CLAIM_SCOPE" = global ] ||
		{ _pw_dns_helper_check_fail claim_scope dns_dep_identity; return 1; }

	# 1a. The claim's generation must still be the live one, and that snapshot
	# must still verify; a superseded generation invalidates the claim.
	passwall_snapshot_check "$snapshot" ||
		{ _pw_dns_helper_check_fail generation_stale dns_dep_stale_generation; return 1; }
	[ "$PW_DNS_HELPER_CLAIM_GENERATION" = "${snapshot##*/}" ] ||
		{ _pw_dns_helper_check_fail generation_mismatch dns_dep_stale_generation; return 1; }

	# 1b. The claim must still name the instance that is actually published now.
	instance=$(get_cache_var ACL_GLOBAL_TCP_instance) || instance=
	case "$instance" in
		"${GLOBAL_ACL_PATH}"/split/instance.*/config.json) ;;
		*) _pw_dns_helper_check_fail instance_pointer dns_dep_identity; return 1 ;;
	esac
	instance=${instance%/config.json}
	[ "$PW_DNS_HELPER_CLAIM_INSTANCE" = "$instance" ] ||
		{ _pw_dns_helper_check_fail instance_mismatch dns_dep_identity; return 1; }
	[ -d "$instance" ] && [ ! -L "$instance" ] ||
		{ _pw_dns_helper_check_fail instance_missing dns_dep_identity; return 1; }

	# 2. The instance's own published endpoint must still be the claim's endpoint.
	socks=$(cat "$instance/socks_port" 2>/dev/null) || socks=
	case "$socks" in
		''|*[!0-9]*) _pw_dns_helper_check_fail instance_endpoint dns_dep_identity; return 1 ;;
	esac
	[ "$PW_DNS_HELPER_CLAIM_SOCKS_ADDR" = 127.0.0.1 ] &&
		[ "$PW_DNS_HELPER_CLAIM_SOCKS_PORT" = "$socks" ] ||
		{ _pw_dns_helper_check_fail instance_endpoint dns_dep_identity; return 1; }
	PW_DNS_HELPER_CHECK_INSTANCE=$instance

	# 3. The instance's SOCKS receipt must still describe the live process.
	spid= sbirth=
	{ IFS= read -r spid; IFS= read -r sbirth; } < "$instance/socks/process" 2>/dev/null || :
	case "$spid" in ''|*[!0-9]*) spid= ;; esac
	case "$sbirth" in ''|*[!0-9]*) sbirth= ;; esac
	[ -n "$spid" ] && [ -n "$sbirth" ] ||
		{ _pw_dns_helper_check_fail instance_process dns_dep_identity; return 1; }
	_pw_global_ss_alive "$spid" "$sbirth" ||
		{ _pw_dns_helper_check_fail instance_process dns_dep_identity; return 1; }
	PW_DNS_HELPER_CHECK_SOCKS_PID=$spid

	# 4+5. That process must still hold the LISTEN socket on that port, and the
	# socket inode must be one of its own fds (never matched by port alone).
	_pw_global_ss_socket "$spid" tcp "$socks" ||
		{ _pw_dns_helper_check_fail socks_listener dns_dep_identity; return 1; }

	# 6. Helper identity and listener ownership, through the same record and
	# probe the stop path uses. Claim and record must describe one helper.
	_pw_dns_helper_record_read "$dir" ||
		{ _pw_dns_helper_check_fail helper_record dns_dep_identity; return 1; }
	[ "$PW_DNS_HELPER_REC_SCOPE" = "$PW_DNS_HELPER_CLAIM_SCOPE" ] &&
		[ "$PW_DNS_HELPER_REC_GENERATION" = "$PW_DNS_HELPER_CLAIM_GENERATION" ] &&
		[ "$PW_DNS_HELPER_REC_INSTANCE" = "$PW_DNS_HELPER_CLAIM_INSTANCE" ] &&
		[ "$PW_DNS_HELPER_REC_PID" = "$PW_DNS_HELPER_CLAIM_PID" ] &&
		[ "$PW_DNS_HELPER_REC_BIRTH" = "$PW_DNS_HELPER_CLAIM_BIRTH" ] &&
		[ "$PW_DNS_HELPER_REC_EXECUTABLE" = "$PW_DNS_HELPER_CLAIM_EXECUTABLE" ] &&
		[ "$PW_DNS_HELPER_REC_CMDLINE_MD5" = "$PW_DNS_HELPER_CLAIM_CMDLINE_MD5" ] &&
		[ "$PW_DNS_HELPER_REC_LISTEN_ADDR" = "$PW_DNS_HELPER_CLAIM_LISTEN_ADDR" ] &&
		[ "$PW_DNS_HELPER_REC_LISTEN_PORT" = "$PW_DNS_HELPER_CLAIM_LISTEN_PORT" ] ||
		{ _pw_dns_helper_check_fail helper_record dns_dep_identity; return 1; }
	[ "$PW_DNS_HELPER_CLAIM_LISTEN_ADDR" = 127.0.0.1 ] ||
		{ _pw_dns_helper_check_fail helper_listen dns_dep_identity; return 1; }
	case "$(_pw_global_ss_state "$PW_DNS_HELPER_CLAIM_PID" "$PW_DNS_HELPER_CLAIM_BIRTH")" in
		alive) ;;
		*) _pw_dns_helper_check_fail helper_process dns_dep_identity; return 1 ;;
	esac
	lua "$PW_DNS_HELPER_PROBE" identity "$PW_DNS_HELPER_CLAIM_PID" "$PW_DNS_HELPER_CLAIM_BIRTH" \
		"$PW_DNS_HELPER_CLAIM_EXECUTABLE" "$PW_DNS_HELPER_CLAIM_CMDLINE_MD5" >/dev/null 2>&1 ||
		{ _pw_dns_helper_check_fail helper_identity dns_dep_identity; return 1; }
	_pw_global_ss_socket "$PW_DNS_HELPER_CLAIM_PID" udp "$PW_DNS_HELPER_CLAIM_LISTEN_PORT" ||
		{ _pw_dns_helper_check_fail helper_listen dns_dep_identity; return 1; }
	return 0
}
