#!/bin/sh
# B2 definitions only. NOT sourced/called by app.sh, init, ACL or firewall.
# Caller supplies existing app.sh/utils.sh functions and the B1 parser.
# Calls must be serialized by the service lifecycle lock when integrated.

_pw_split_node_get() {
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then passwall_snapshot_uci "$PW_BOUND_SNAPSHOT" get "$1.$2"
	else config_n_get "$@"; fi
}

_pw_split_node_snapshot() {
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then passwall_snapshot_uci "$PW_BOUND_SNAPSHOT" show "$1"
	else uci -q show "$CONFIG.$1"; fi
}

_pw_split_node_supported() {
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then
		[ "$(passwall_snapshot_uci "$PW_BOUND_SNAPSHOT" get "$1")" = nodes ] || return 1
		case "$(_pw_split_node_get "$1" type)" in SS|Hysteria) return 0 ;; *) return 1 ;; esac
	else check_node_supported "$1" && [ "$(config_get_type "$1")" = nodes ]; fi
}

_pw_global_ss_alive() {
	local state
	case "$1:$2" in *[!0-9:]*|:*) return 1 ;; esac
	[ -n "$2" ] && [ "$(get_process_start_time "$1")" = "$2" ] || return 1
	# A zombie has a start time too, but cannot own a usable listener.
	state=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d ' ' -f 1)
	[ -n "$state" ] && [ "$state" != Z ]
}

_pw_global_ss_socket() {
	# Optional family 4/6 narrows B3.1 checks; omitted retains B2's dual-family query.
	local pid="$1" proto="$2" port="$3" fd link inode owned=' ' hex files=
	for fd in /proc/"$pid"/fd/*; do
		link=$(readlink "$fd") || continue
		case "$link" in socket:\[*\]) inode=${link#'socket:['}; inode=${inode%']'}; owned="$owned$inode " ;; esac
	done
	hex=$(printf '%04X' "$port") || return 1
	[ "${4:-}" = 6 ] || [ ! -r "/proc/net/$proto" ] || files="/proc/net/$proto"
	[ "${4:-}" = 4 ] || [ ! -r "/proc/net/${proto}6" ] || files="$files /proc/net/${proto}6"
	[ -n "$files" ] || return 1
	awk -v owned="$owned" -v port="$hex" -v proto="$proto" '
		$2 ~ ":" port "$" && index(owned, " " $10 " ") && (proto == "udp" || $4 == "0A") {found=1}
		END {exit !found}
	' $files
}

_pw_global_ss_ready() {
	local instance="$1" pid birth tcp udp
	{ IFS= read -r pid; IFS= read -r birth; } < "$instance/process" || return 1
	_pw_global_ss_alive "$pid" "$birth" || return 1
	tcp=$(sed -n '3p' "$instance/meta") || return 1
	udp=$(sed -n '4p' "$instance/meta") || return 1
	[ -z "$tcp" ] || _pw_global_ss_socket "$pid" tcp "$tcp" || return 1
	[ -z "$udp" ] || _pw_global_ss_socket "$pid" udp "$udp" || return 1
	_pw_global_ss_alive "$pid" "$birth"
}

_pw_global_ss_state() {
	# Stop-only observation. Lua 5.1 io.open returns errno separately: a failed
	# read is not proof of exit. No UCI, binding freshness or persistent state.
	lua - "$1" "${2:-}" <<'LUA'
local function result(s) print(s) end
local pid, birth = arg[1], arg[2]
if not pid or not pid:match("^%d+$") or tonumber(pid) <= 0 or
 not birth or (birth ~= "" and not birth:match("^%d+$")) then result("unknown"); return end
local self = io.open("/proc/self/stat", "r")
if not self then result("unknown"); return end
local visible = self:read("*a"); local closed = self:close()
if not visible or not closed or not visible:match("^%d+ ") then result("unknown"); return end
local f, _, errno = io.open("/proc/" .. pid .. "/stat", "r")
if not f then result(errno == 2 and "exited" or "unknown"); return end
local data = f:read("*a"); closed = f:close()
if not data or not closed then result("unknown"); return end
local actual, rest = data:match("^(%d+) .*%) (.*)$")
local fields = {}; for v in (rest or ""):gmatch("%S+") do fields[#fields + 1] = v end
if actual ~= pid or not fields[1] or not fields[1]:match("^[A-Za-z]$") or
 not fields[20] or not fields[20]:match("^%d+$") or birth == "" then result("unknown")
elseif fields[20] ~= birth then result("reused")
elseif fields[1] == "Z" then result("zombie")
else result("alive") end
LUA
}

_pw_global_ss_kill() {
	local pid="$1" birth="$2" i
	case "$(_pw_global_ss_state "$pid" "$birth")" in
		alive) ;; exited|reused|zombie) return 0 ;; *) return 1 ;;
	esac
	kill -TERM "$pid" 2>/dev/null || :
	for i in 1 2 3 4 5 6 7 8 9 10; do
		case "$(_pw_global_ss_state "$pid" "$birth")" in
			alive) ;; exited|reused|zombie) return 0 ;; *) return 1 ;;
		esac
		sleep 0.1
	done
	case "$(_pw_global_ss_state "$pid" "$birth")" in
		alive) ;; exited|reused|zombie) return 0 ;; *) return 1 ;;
	esac
	kill -KILL "$pid" 2>/dev/null || :
	for i in 1 2 3 4 5 6 7 8 9 10; do
		case "$(_pw_global_ss_state "$pid" "$birth")" in
			alive) ;; exited|reused|zombie) return 0 ;; *) return 1 ;;
		esac
		sleep 0.1
	done
	return 1
}

_pw_global_instance_stop() {
	local instance="$1" core pid= birth=
	# The caller's runtime context is independent of the instance's binding.
	[ ! -e "$instance/binding.json" ] && [ ! -L "$instance/binding.json" ] ||
		_pw_bound_helper owner "$instance" stop "$TMP_PATH" || return 1
	core=$(sed -n '1p' "$instance/meta") || return 1
	case "$core" in
		Hysteria) lua "$HYSTERIA_RUNTIME" stop client "$instance/config.json" || return 1 ;;
		SS)
			# The existing owner/stop gate above checks both sealed identities.
			# Stop the dependent listener first; any unknown result retains both records.
			if [ -e "$instance/socks" ] || [ -L "$instance/socks" ]; then
				[ -f "$instance/binding.json" ] || return 1
				{ IFS= read -r pid; IFS= read -r birth; } < "$instance/socks/process" || return 1
				_pw_global_ss_kill "$pid" "$birth" || return 1
				pid= birth=
			fi
			if [ -s "$instance/process" ]; then
				{ IFS= read -r pid; IFS= read -r birth; } < "$instance/process" || birth=
			fi
			# Public stop uses only the instance record, never a creation receipt.
			case "$pid:$birth" in *[!0-9:]*|:*)
				[ ! -e "$instance/core" ] && [ ! -L "$instance/core" ] || return 1
				;;
			esac
			[ -z "$pid" ] || _pw_global_ss_kill "$pid" "$birth" || return 1
			;;
		*) return 1 ;;
	esac
	rm -rf "$instance"
}

# 0=in use, 1=unreferenced, 2=cannot establish ownership safely.
_pw_global_instance_referenced() {
	local instance="$1" keys key value
	[ -d "$TMP_PATH" ] && [ -r "$TMP_PATH" ] && [ -x "$TMP_PATH" ] || return 2
	[ ! -L "$TMP_PATH/var" ] || return 2
	[ -e "$TMP_PATH/var" ] || return 1
	[ -f "$TMP_PATH/var" ] && [ -r "$TMP_PATH/var" ] || return 2
	/bin/sh -n "$TMP_PATH/var" 2>/dev/null || return 2
	keys=$(sed -n 's/^\([A-Za-z0-9_]*_instance\)=.*/\1/p' "$TMP_PATH/var") || return 2
	for key in $keys; do
		value=$(get_cache_var "$key") || return 2
		[ "$value" != "$instance/config.json" ] || return 0
	done
	return 1
}

passwall_stop_global_nodes() {
	local instance status=0 referenced=0
	[ -n "$TMP_PATH" ] && [ -n "$GLOBAL_ACL_PATH" ] || return 1
	case "$GLOBAL_ACL_PATH" in "$TMP_PATH"/*) ;; *) return 1 ;; esac
	# No legacy node/port/DNS/SOCKS keys are changed. Atomic removal first:
	# if it fails, keep the still-published listeners alive and report failure.
	set_cache_vars ACL_GLOBAL_TCP_node '' ACL_GLOBAL_TCP_redir_port '' ACL_GLOBAL_TCP_instance '' \
		ACL_GLOBAL_UDP_node '' ACL_GLOBAL_UDP_redir_port '' ACL_GLOBAL_UDP_instance '' || return 1
	for instance in "$GLOBAL_ACL_PATH"/split/instance.*; do
		[ -d "$instance" ] && [ ! -L "$instance" ] || continue
		referenced=0
		_pw_global_instance_referenced "$instance" || referenced=$?
		case "$referenced" in
			0) continue ;;
			1) _pw_global_instance_stop "$instance" || status=1 ;;
			*) status=1 ;;
		esac
	done
	[ "$status" = 0 ] || echolog 'Split global cleanup pending; instance records retained.'
	return "$status"
}

_pw_global_instance_ready() {
	local instance="$1" core tcp udp
	core=$(sed -n '1p' "$instance/meta") || return 1
	case "$core" in
		SS) _pw_global_ss_ready "$instance" ;;
		Hysteria)
			tcp=$(sed -n '3p' "$instance/meta") || return 1
			udp=$(sed -n '4p' "$instance/meta") || return 1
			lua "$HYSTERIA_RUNTIME" ready client "$instance/config.json" "$tcp" "$udp"
			;;
		*) return 1 ;;
	esac
	[ "$?" = 0 ] || return 1
	[ ! -f "$instance/binding.json" ] || _pw_bound_ready "$instance"
}

passwall_global_node_ready() {
	local proto="$1" node port config instance actual_port
	case "$proto" in TCP|UDP) ;; *) return 1 ;; esac
	node=$(get_cache_var "ACL_GLOBAL_${proto}_node") || return 1
	port=$(get_cache_var "ACL_GLOBAL_${proto}_redir_port") || return 1
	config=$(get_cache_var "ACL_GLOBAL_${proto}_instance") || return 1
	case "$config" in "$GLOBAL_ACL_PATH"/split/instance.*/config.json) ;; *) return 1 ;; esac
	instance=${config%/config.json}
	[ -n "$node" ] && [ -n "$port" ] && [ "$(sed -n '2p' "$instance/meta")" = "$node" ] || return 1
	if [ "$proto" = TCP ]; then actual_port=$(sed -n '3p' "$instance/meta"); else actual_port=$(sed -n '4p' "$instance/meta"); fi
	[ "$port" = "$actual_port" ] || return 1
	_pw_global_instance_ready "$instance"
}

# New SS instances use the existing foreground `ss-redir -c ... -v` command
# and PID/start-time/command record format. No monitor or other instance is touched.
_pw_global_ss_start() {
	local instance="$1" log="$2" bin pid birth i
	bin=$(first_type ss-redir) || return 1
	[ -x "$bin" ] && ln -s "$bin" "$instance/core" || return 1
	PW_GLOBAL_NEW_STARTED=1
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then
		pid=$(_pw_bound_helper spawn "$log" "$instance/core" -c "$instance/config.json" -v) || return 1
	else
		"$instance/core" -c "$instance/config.json" -v > "$log" 2>&1 &
		pid=$!
	fi
	birth=$(get_process_start_time "$pid")
	PW_GLOBAL_NEW_PID=$pid; PW_GLOBAL_NEW_BIRTH=$birth
	PW_GLOBAL_NEW_PROCESS="$pid
$birth
$(shell_quote "$instance/core") -c $(shell_quote "$instance/config.json") -v
"
	if ! printf '%s' "$PW_GLOBAL_NEW_PROCESS" > "$instance/process"; then
		PW_GLOBAL_NEW_WRITE_FAILED=1
		_pw_global_ss_kill "$pid" "$birth" || { PW_GLOBAL_PRIVATE_STOP_FAILED=1; return 1; }
		return 1
	fi
	for i in $(seq 1 100); do
		_pw_global_ss_alive "$pid" "$birth" || return 1
		if _pw_global_ss_ready "$instance"; then
			sleep 0.1
			_pw_global_ss_ready "$instance"
			return
		fi
		sleep 0.1
	done
	return 1
}

# Internal TCP SOCKS only, attached to the same frozen Global SS instance.
# Keep the existing PID/birth/command receipt and stop observer, not ln_run's
# unrelated process registry or the live-UCI run_socks path.
_pw_global_ss_socks_ready() {
	local instance="$1" pid birth port
	{ IFS= read -r pid; IFS= read -r birth; } < "$instance/socks/process" || return 1
	port=$(cat "$instance/socks_port") || return 1
	_pw_global_ss_alive "$pid" "$birth" && _pw_global_ss_socket "$pid" tcp "$port" 4
}

_pw_global_ss_socks_start() {
	local instance="$1" log="$2" bin pid birth i
	bin=$(first_type ss-local) || return 1
	[ -x "$bin" ] && ln -s "$bin" "$instance/socks/core" || return 1
	[ "$log" = /dev/null ] || log="$instance/socks/node.log"
	PW_GLOBAL_NEW_SOCKS_STARTED=1
	pid=$(_pw_bound_helper spawn "$log" "$instance/socks/core" -c "$instance/socks/config.json" -v) || return 1
	birth=$(get_process_start_time "$pid")
	PW_GLOBAL_NEW_SOCKS_PID=$pid; PW_GLOBAL_NEW_SOCKS_BIRTH=$birth
	PW_GLOBAL_NEW_SOCKS_PROCESS="$pid
$birth
$(shell_quote "$instance/socks/core") -c $(shell_quote "$instance/socks/config.json") -v
"
	if ! printf '%s' "$PW_GLOBAL_NEW_SOCKS_PROCESS" > "$instance/socks/process"; then
		PW_GLOBAL_NEW_SOCKS_WRITE_FAILED=1
		_pw_global_ss_kill "$pid" "$birth" || { PW_GLOBAL_PRIVATE_STOP_FAILED=1; return 1; }
		return 1
	fi
	for i in $(seq 1 100); do
		_pw_global_ss_ready "$instance" && _pw_global_ss_alive "$pid" "$birth" || break
		if _pw_global_ss_socks_ready "$instance"; then
			sleep 0.1
			if _pw_global_ss_ready "$instance" && _pw_global_ss_socks_ready "$instance"; then return 0; fi
			break
		fi
		sleep 0.1
	done
	# This receipt belongs only to this private launch, before any publication.
	_pw_global_ss_kill "$pid" "$birth" || { PW_GLOBAL_PRIVATE_STOP_FAILED=1; return 1; }
	return 1
}

_pw_global_prepare_private() {
	# Capture the directory created by this call before configuration/receipt
	# preparation. This carries no process ownership or stop permission.
	PW_GLOBAL_PRIVATE_DIRECTORY=$(_pw_bound_helper private-directory "$2" "$TMP_PATH" "$PW_BOUND_SNAPSHOT") || return 1
	[ -n "$PW_GLOBAL_PRIVATE_DIRECTORY" ] || return 1
	_pw_bound_prepare "$@" || return 1
	# Held only in this creation call, before either launch or publication.
	if ! PW_GLOBAL_PRIVATE_RECEIPT=$(_pw_bound_helper private-receipt "$2" "$TMP_PATH" "$PW_BOUND_SNAPSHOT") ||
		[ -z "$PW_GLOBAL_PRIVATE_RECEIPT" ]; then
		PW_GLOBAL_PRIVATE_RECEIPT_FAILED=1
		return 1
	fi
}

_pw_global_hysteria_private() {
	local result status=0
	PW_GLOBAL_NEW_STARTED=1
	# A failed start already ran the manager's own cleanup. Do not retry it.
	result=$(PW_BOUND_PRIVATE_CREATION="$PW_GLOBAL_PRIVATE_RECEIPT" \
		PW_BOUND_PRIVATE_DIRECTORY="$PW_GLOBAL_PRIVATE_DIRECTORY" _pw_bound_hysteria "$@") || status=$?
	case "$status" in
		0) ;;
		2)
			[ -n "$result" ] || { PW_GLOBAL_PRIVATE_STOP_FAILED=1; return 1; }
			PW_GLOBAL_HYSTERIA_RELEASE=$result
			return 2
			;;
		*) PW_GLOBAL_PRIVATE_STOP_FAILED=1; return 1 ;;
	esac
	# Capture only a successful launch. A missing/unreadable manager receipt
	# cannot authorize this caller to stop or reclaim the instance.
	PW_GLOBAL_HYSTERIA_RECEIPT=$(_pw_bound_helper private-hysteria "$1") || return 1
}

_pw_global_private_hysteria_released() {
	local instance="$1"
	[ "${publish:-1}" = 0 ] && [ "$PW_GLOBAL_NEW_INSTANCE" = "$instance" ] &&
		[ "$PW_GLOBAL_NEW_STARTED:$PW_GLOBAL_NEW_SOCKS_STARTED:$PW_GLOBAL_PRIVATE_STOP_FAILED" = 1:0:0 ] &&
		[ -n "$PW_GLOBAL_PRIVATE_RECEIPT" ] && [ -n "$PW_GLOBAL_PRIVATE_DIRECTORY" ] &&
		[ -n "$PW_GLOBAL_HYSTERIA_RELEASE" ] || return 1
	_pw_bound_helper private-hysteria-released-owner "$instance" "$TMP_PATH" "$PW_GLOBAL_PRIVATE_RECEIPT" \
		"$PW_GLOBAL_PRIVATE_DIRECTORY" "$PW_GLOBAL_HYSTERIA_RELEASE" || return 1
	# The manager already released this call. No second stop or shared cleanup.
	rm -rf "$instance" || return 1
	PW_GLOBAL_NEW_INSTANCE=
	return 0
}

_pw_global_private_rollback() {
	local instance="$1" core
	# publish is the creating caller's local flag. A later stop/retry cannot
	# acquire this exception by observing a missing seal or an empty cache.
	[ "${publish:-1}" = 0 ] && [ "$PW_GLOBAL_NEW_INSTANCE" = "$instance" ] &&
		[ "${PW_GLOBAL_PRIVATE_STOP_FAILED:-1}" = 0 ] && [ -n "${PW_GLOBAL_PRIVATE_RECEIPT:-}" ] || return 1
	_pw_bound_helper private-owner "$instance" "$TMP_PATH" "$PW_GLOBAL_PRIVATE_RECEIPT" \
		"$PW_GLOBAL_NEW_STARTED" "$PW_GLOBAL_NEW_PID" "$PW_GLOBAL_NEW_BIRTH" \
		"$PW_GLOBAL_NEW_SOCKS_STARTED" "$PW_GLOBAL_NEW_SOCKS_PID" "$PW_GLOBAL_NEW_SOCKS_BIRTH" \
		"$PW_GLOBAL_HYSTERIA_RECEIPT" "$PW_GLOBAL_NEW_PROCESS" "$PW_GLOBAL_NEW_WRITE_FAILED" \
		"$PW_GLOBAL_NEW_SOCKS_PROCESS" "$PW_GLOBAL_NEW_SOCKS_WRITE_FAILED" || return 1
	core=$(sed -n '1p' "$instance/meta") || return 1
	case "$core" in
		SS)
			[ "$PW_GLOBAL_NEW_SOCKS_STARTED" = 0 ] ||
				_pw_global_ss_kill "$PW_GLOBAL_NEW_SOCKS_PID" "$PW_GLOBAL_NEW_SOCKS_BIRTH" || return 1
			[ "$PW_GLOBAL_NEW_STARTED" = 0 ] ||
				_pw_global_ss_kill "$PW_GLOBAL_NEW_PID" "$PW_GLOBAL_NEW_BIRTH" || return 1
			;;
		Hysteria)
			[ "$PW_GLOBAL_NEW_STARTED" = 0 ] ||
				lua "$HYSTERIA_RUNTIME" stop client "$instance/config.json" || return 1
			;;
		*) return 1 ;;
	esac
	rm -rf "$instance" || return 1
	PW_GLOBAL_NEW_INSTANCE= PW_GLOBAL_NEW_PID= PW_GLOBAL_NEW_BIRTH=
	return 0
}

_pw_global_private_discard() {
	local instance="$1"
	# Positive no-launch facts from this creation call are required in addition
	# to the directory check. A missing receipt alone never reaches deletion.
	[ "${publish:-1}" = 0 ] && [ "$PW_GLOBAL_NEW_INSTANCE" = "$instance" ] &&
		[ "$PW_GLOBAL_PRIVATE_RECEIPT_FAILED" = 1 ] && [ -n "$PW_GLOBAL_PRIVATE_DIRECTORY" ] &&
		[ "$PW_GLOBAL_NEW_STARTED:$PW_GLOBAL_NEW_SOCKS_STARTED:$PW_GLOBAL_PRIVATE_STOP_FAILED" = 0:0:0 ] &&
		[ "$PW_GLOBAL_NEW_WRITE_FAILED:$PW_GLOBAL_NEW_SOCKS_WRITE_FAILED" = 0:0 ] &&
		[ -z "$PW_GLOBAL_NEW_PID$PW_GLOBAL_NEW_BIRTH$PW_GLOBAL_NEW_SOCKS_PID$PW_GLOBAL_NEW_SOCKS_BIRTH$PW_GLOBAL_HYSTERIA_RECEIPT$PW_GLOBAL_NEW_PROCESS$PW_GLOBAL_NEW_SOCKS_PROCESS" ] || return 1
	_pw_bound_helper private-discard-owner "$instance" "$TMP_PATH" "$PW_GLOBAL_PRIVATE_DIRECTORY" "$PW_BOUND_SNAPSHOT" || return 1
	# No process stop, manager call or shared snapshot removal on this path.
	rm -rf "$instance" || return 1
	PW_GLOBAL_NEW_INSTANCE=
	return 0
}

# 0=published; 2=failed attempt safely reclaimed; 1=cleanup/state unsafe.
_pw_global_start_redir() {
	local node="$1" proto="$2" base="$3" core port instance tcp= udp= socks= socks_key mode log failure=0 publish=0 refs=0
	local PW_GLOBAL_PRIVATE_RECEIPT= PW_GLOBAL_NEW_STARTED=0 PW_GLOBAL_NEW_SOCKS_STARTED=0
	local PW_GLOBAL_NEW_SOCKS_PID= PW_GLOBAL_NEW_SOCKS_BIRTH= PW_GLOBAL_HYSTERIA_RECEIPT= PW_GLOBAL_PRIVATE_STOP_FAILED=0
	local PW_GLOBAL_NEW_PROCESS= PW_GLOBAL_NEW_WRITE_FAILED=0 PW_GLOBAL_NEW_SOCKS_PROCESS= PW_GLOBAL_NEW_SOCKS_WRITE_FAILED=0
	local PW_GLOBAL_PRIVATE_DIRECTORY= PW_GLOBAL_PRIVATE_RECEIPT_FAILED=0
	local PW_GLOBAL_HYSTERIA_RELEASE=
	PW_GLOBAL_NEW_INSTANCE= PW_GLOBAL_NEW_PID= PW_GLOBAL_NEW_BIRTH=
	case "$node" in ''|*[!a-zA-Z0-9_-]*) echolog 'Split global: invalid node ID.'; return 2 ;; esac
	if ! _pw_split_node_supported "$node"; then
		echolog "Split global: node $node does not exist or is not a proxy node."
		return 2
	fi
	core=$(_pw_split_node_get "$node" type)
	case "$core" in SS|Hysteria) ;; *) echolog "Split global: unsupported core $core."; return 2 ;; esac
	case "$proto" in TCP) mode=tcp_only ;; UDP) mode=udp_only ;; TCP_UDP) mode=tcp_and_udp ;; *) return 1 ;; esac
	if [ "$proto" != UDP ]; then
		case "$TCP_PROXY_WAY" in redirect|tproxy) ;; *) return 2 ;; esac
	fi
	if [ "$proto" = TCP_UDP ]; then port=$(get_new_port "$base" tcp,udp) || return 2; else port=$(get_new_port "$base" "$proto") || return 2; fi
	case "$port" in ''|*[!0-9]*) return 2 ;; esac
	[ "$port" -gt 0 ] && [ "$port" -le 65535 ] || return 2
	[ "$proto" = UDP ] || tcp=$port
	[ "$proto" = TCP ] || udp=$port
	# Only new frozen TCP-capable instances get an internal loopback SOCKS
	# listener. No production GLOBAL_SOCKS_server or UDP TCP capability is published.
	if [ -n "${PW_BOUND_SNAPSHOT:-}" ] && [ -n "$tcp" ]; then
		[ "$core" != SS ] || { [ -x "$(first_type ss-local)" ] || return 2; }
		socks=$(get_new_port 1070 tcp) || return 2
		case "$socks" in ''|*[!0-9]*) return 2 ;; esac
		if [ "$socks" = "$port" ]; then socks=$(get_new_port "$((socks + 1))" tcp) || return 2; fi
		case "$socks" in ''|*[!0-9]*) return 2 ;; esac
		[ "$socks" -gt 0 ] && [ "$socks" -le 65535 ] && [ "$socks" != "$port" ] || return 2
	fi
	mkdir -p "$GLOBAL_ACL_PATH/split" || return 1
	instance=$(mktemp -d "$GLOBAL_ACL_PATH/split/instance.XXXXXX") || return 1
	PW_GLOBAL_NEW_INSTANCE=$instance
	if ! printf '%s\n' "$core" "$node" "$tcp" "$udp" > "$instance/meta"; then
		rm -rf "$instance" || return 1
		return 2
	fi
	log=/dev/null
	[ "$(config_n_get @global[0] log_node 1)" != 1 ] || log="$instance/node.log"
	json_init
	json_add_string node "$node"
	if [ -n "$socks" ]; then
		printf '%s\n' "$socks" > "$instance/socks_port" || return 1
		socks_key=socks_tcp_socket; [ "$core" != SS ] || socks_key=ss_socks_tcp_socket
		json_add_object "$socks_key"
		json_add_string address 127.0.0.1
		json_add_string protocol tcp
		json_add_string family 4
		json_add_int port "$socks"
		json_close_object
	fi
	case "$core" in
		SS)
			json_add_string local_addr 0.0.0.0
			json_add_string local_port "$port"
			json_add_string mode "$mode"
			[ -z "$tcp" ] || [ "$TCP_PROXY_WAY" != tproxy ] || json_add_string tcp_tproxy true
			if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then _pw_global_prepare_private "$node" "$instance" "$(json_dump)"
			else gen_ss_config "$(json_dump)" "$instance/config.json"; fi && _pw_global_ss_start "$instance" "$log" &&
				{ [ -z "$socks" ] || _pw_global_ss_socks_start "$instance" "$log"; } &&
				{ [ -z "${PW_BOUND_SNAPSHOT:-}" ] || _pw_bound_seal "$instance"; } &&
				{ publish=1; _pw_global_publish "$node" "$tcp" "$udp" "$instance"; } && return 0
			failure=$?
			;;
		Hysteria)
			[ -z "$tcp" ] || json_add_string local_tcp_redir_port "$tcp"
			[ -z "$udp" ] || json_add_string local_udp_redir_port "$udp"
			json_add_string tcp_proxy_way "$TCP_PROXY_WAY"
			json_add_string proxy_ipv6 "${PROXY_IPV6:-0}"
			if [ -n "$socks" ]; then
				json_add_string local_socks_address 127.0.0.1
				json_add_string local_socks_port "$socks"
			fi
			if [ -n "${PW_BOUND_SNAPSHOT:-}" ]; then
				_pw_global_prepare_private "$node" "$instance" "$(json_dump)" && _pw_global_hysteria_private "$instance" "$log" "$(config_n_get @global[0] loglevel warn)"
			else gen_hysteria_config "$(json_dump)" "$instance/config.json" &&
				start_hysteria "$instance/config.json" "$log" "$(config_n_get @global[0] loglevel warn)"; fi &&
				{ [ -z "${PW_BOUND_SNAPSHOT:-}" ] || _pw_bound_seal "$instance"; } &&
				{ publish=1; _pw_global_publish "$node" "$tcp" "$udp" "$instance"; } && return 0
			failure=$?
			;;
	esac
	# Publication succeeded but its subsequent readiness check failed, and the
	# published tuple could not be withdrawn. Retain ownership records for retry.
	[ "$failure" != 3 ] || { echolog "Split global unpublish pending: $instance"; return 1; }
	# A private attempt has never exposed its unique directory. Once publish
	# was entered, only a trusted no-reference result permits rollback killing.
	if [ "$publish" = 1 ]; then
		_pw_global_instance_referenced "$instance" || refs=$?
		[ "$refs" = 1 ] || { echolog "Split global rollback references pending: $instance"; return 1; }
	elif [ -n "${PW_BOUND_SNAPSHOT:-}" ] && [ "$PW_GLOBAL_PRIVATE_RECEIPT_FAILED" = 1 ]; then
		_pw_global_private_discard "$instance" || { echolog "Split global pre-launch discard pending: $instance"; return 1; }
		return 2
	elif [ -n "${PW_BOUND_SNAPSHOT:-}" ] && [ -n "$PW_GLOBAL_HYSTERIA_RELEASE" ]; then
		_pw_global_private_hysteria_released "$instance" || { echolog "Split global Hysteria release pending: $instance"; return 1; }
		return 2
	elif [ -n "${PW_BOUND_SNAPSHOT:-}" ] && [ -n "$PW_GLOBAL_PRIVATE_RECEIPT" ]; then
		_pw_global_private_rollback "$instance" || { echolog "Split global private rollback pending: $instance"; return 1; }
		return 2
	fi
	echolog "Split global $node/$proto failed; reclaiming only $instance."
	_pw_global_instance_stop "$instance" || { echolog "Split global rollback pending: $instance"; return 1; }
	return 2
}

_pw_global_publish() {
	local node="$1" tcp="$2" udp="$3" instance="$4"
	_pw_global_instance_ready "$instance" || return 1
	# Only the new-instance creation path seals. Publication/republication
	# checks the existing seal without repairing or upgrading its records.
	[ -z "${PW_BOUND_SNAPSHOT:-}" ] || _pw_bound_reference "$instance" || return 1
	set --
	[ -z "$tcp" ] || set -- "$@" ACL_GLOBAL_TCP_node "$node" ACL_GLOBAL_TCP_redir_port "$tcp" ACL_GLOBAL_TCP_instance "$instance/config.json"
	[ -z "$udp" ] || set -- "$@" ACL_GLOBAL_UDP_node "$node" ACL_GLOBAL_UDP_redir_port "$udp" ACL_GLOBAL_UDP_instance "$instance/config.json"
	set_cache_vars "$@" || return 1
	# A process can exit while the cache file is being prepared/renamed. Do not
	# report that attempt as successful. Withdraw only this attempt's protocols;
	# the other protocol and ACL/SOCKS bindings are outside its ownership.
	if ! { _pw_global_instance_ready "$instance" && { [ -z "${PW_BOUND_SNAPSHOT:-}" ] || _pw_bound_reference "$instance"; }; }; then
		set --
		[ -z "$tcp" ] || set -- "$@" ACL_GLOBAL_TCP_node '' ACL_GLOBAL_TCP_redir_port '' ACL_GLOBAL_TCP_instance ''
		[ -z "$udp" ] || set -- "$@" ACL_GLOBAL_UDP_node '' ACL_GLOBAL_UDP_redir_port '' ACL_GLOBAL_UDP_instance ''
		set_cache_vars "$@" || return 3
		return 1
	fi
	# The in-memory PID is only for the current, not-yet-published attempt.
	PW_GLOBAL_NEW_INSTANCE= PW_GLOBAL_NEW_PID= PW_GLOBAL_NEW_BIRTH=
	return 0
}

passwall_start_global_nodes() {
	local status=0 result=0
	passwall_resolve_node_pair "$@" || return 1
	passwall_stop_global_nodes || return 1
	case "$PW_NODE_LAYOUT" in
		closed) return 0 ;;
		combined) _pw_global_start_redir "$PW_NODE_TCP" TCP_UDP 1041 || status=$? ;;
		*)
			if [ -n "$PW_NODE_TCP" ]; then
				_pw_global_start_redir "$PW_NODE_TCP" TCP 1041 || status=$?
				[ "$status" != 1 ] || return 1
			fi
			if [ -n "$PW_NODE_UDP" ]; then
				_pw_global_start_redir "$PW_NODE_UDP" UDP 1051 || result=$?
				[ "$result" != 1 ] || return 1
				[ "$result" = 0 ] || status=$result
			fi
			;;
	esac
	return "$status"
}
