#!/bin/sh
# B3.1 definitions only. No caller in app.sh, init, LuCI or either firewall.
# Requires B1/B2 and existing app.sh/utils.sh helpers. Caller holds lifecycle lock.

_pw_acl_context() {
	[ -n "$TMP_PATH" ] && [ -n "$TMP_ACL_PATH" ] && [ -n "$GLOBAL_ACL_PATH" ] || return 1
	case "$TMP_ACL_PATH:$GLOBAL_ACL_PATH" in "$TMP_PATH"/*:"$TMP_ACL_PATH"/*) return 0 ;; esac
	return 1
}

_pw_acl_id() {
	case "$1" in ''|*[!a-zA-Z0-9_]*) return 1 ;; esac
}

_pw_acl_node_supported() {
	case "$1" in ''|*[!a-zA-Z0-9_-]*) return 1 ;; esac
	check_node_supported "$1" && [ "$(config_get_type "$1")" = nodes ] || return 1
	case "$(config_n_get "$1" type)" in SS|Hysteria) return 0 ;; *) return 1 ;; esac
}

# Location check also accepts already removed instances in a release retry list.
_pw_acl_location() {
	_pw_acl_context || return 1
	case "${1%/*}" in
		"$TMP_ACL_PATH"/split-acl|"$GLOBAL_ACL_PATH"/split)
			case "${1##*/}" in instance.*) ;; *) return 1 ;; esac
			case "${1##*/}" in *[!a-zA-Z0-9_.]*) return 1 ;; esac
			;;
		*) return 1 ;;
	esac
}

# All resource operations accept only private B2 or B3.1 instance directories.
_pw_acl_path() {
	_pw_acl_location "$1" && [ -d "$1" ] && [ ! -L "$1" ]
}

_pw_acl_process_ready() {
	local dir="$1" tcp="$2" udp="$3" ipv6="${4:-0}" pid birth proto port
	{ IFS= read -r pid; IFS= read -r birth; } < "$dir/process" || return 1
	_pw_global_ss_alive "$pid" "$birth" || return 1
	for proto in tcp udp; do
		if [ "$proto" = tcp ]; then port=$tcp; else port=$udp; fi
		[ -n "$port" ] || continue
		_pw_global_ss_socket "$pid" "$proto" "$port" 4 || return 1
		[ "$ipv6" != 1 ] || _pw_global_ss_socket "$pid" "$proto" "$port" 6 || return 1
	done
	_pw_global_ss_alive "$pid" "$birth"
}

_pw_acl_instance_ready() {
	local instance="$1" core tcp udp socks ipv6
	_pw_acl_path "$instance" || return 1
	case "$instance" in "$GLOBAL_ACL_PATH"/split/*) _pw_global_instance_ready "$instance"; return ;; esac
	core=$(sed -n '1p' "$instance/meta") || return 1
	tcp=$(sed -n '3p' "$instance/meta") || return 1
	udp=$(sed -n '4p' "$instance/meta") || return 1
	[ -n "$tcp$udp" ] || return 1
	case "$core" in
		Hysteria) _pw_global_instance_ready "$instance" ;;
		SS)
			socks=$(cat "$instance/socks_port") || return 1
			ipv6=$(sed -n '2p' "$instance/context") || return 1
			# Even UDP-only ipt2socks needs the SOCKS TCP control connection.
			_pw_acl_process_ready "$instance" "$socks" "${udp:+$socks}" || return 1
			_pw_acl_process_ready "$instance/relay" "$tcp" "$udp" "$ipv6"
			;;
		*) return 1 ;;
	esac
}

passwall_acl_node_ready() {
	local sid="$1" proto="$2" node port config instance actual
	_pw_acl_id "$sid" || return 1
	case "$proto" in tcp|udp) ;; *) return 1 ;; esac
	node=$(get_cache_var "ACL_${sid}_${proto}_node") || return 1
	port=$(get_cache_var "ACL_${sid}_${proto}_redir_port") || return 1
	config=$(get_cache_var "ACL_${sid}_${proto}_instance") || return 1
	instance=${config%/config.json}
	[ "$config" = "$instance/config.json" ] && _pw_acl_path "$instance" || return 1
	[ -n "$node" ] && [ -n "$port" ] && [ "$(sed -n '2p' "$instance/meta")" = "$node" ] || return 1
	if [ "$proto" = tcp ]; then actual=$(sed -n '3p' "$instance/meta"); else actual=$(sed -n '4p' "$instance/meta"); fi
	[ "$port" = "$actual" ] && _pw_acl_instance_ready "$instance"
}

# B3.2 supplies the resolved effective request from THIS ACL initialization.
# Never derive CLOSED from a missing endpoint, or infer inheritance on failure.
# stdout=closed/failed/ready, status=0; invalid/contradictory cache -> status=1.
passwall_acl_protocol_state() {
	local sid="$1" proto="$2" requested="$3" node= port= config=
	[ "$#" = 3 ] && _pw_acl_id "$sid" && _pw_acl_context || return 1
	case "$proto" in tcp|udp) ;; *) return 1 ;; esac
	case "$requested" in *[!a-zA-Z0-9_-]*) return 1 ;; esac
	[ ! -e "$TMP_PATH/var" ] || [ -r "$TMP_PATH/var" ] || return 1
	if [ -s "$TMP_PATH/var" ]; then
		node=$(get_cache_var "ACL_${sid}_${proto}_node") || return 1
		port=$(get_cache_var "ACL_${sid}_${proto}_redir_port") || return 1
		config=$(get_cache_var "ACL_${sid}_${proto}_instance") || return 1
	fi
	if [ -z "$requested" ]; then
		[ -z "$node$port$config" ] || return 1
		echo closed
	elif [ -z "$node$port$config" ]; then
		echo failed
	else
		[ -n "$node" ] && [ -n "$port" ] && [ -n "$config" ] && [ "$node" = "$requested" ] || return 1
		if passwall_acl_node_ready "$sid" "$proto"; then echo ready; else echo failed; fi
	fi
}

# Foreground SS-local/ipt2socks commands, using Lite's PID/birth/command record.
# Memory ownership exists only for a just-launched process whose record may fail.
_pw_acl_launch() {
	local dir="$1" log="$2" bin="$3" pid birth arg
	shift 3
	[ -x "$bin" ] && ln -s "$bin" "$dir/core" || return 1
	"$dir/core" "$@" > "$log" 2>&1 &
	pid=$!; birth=$(get_process_start_time "$pid")
	PW_ACL_NEW_DIR=$dir; PW_ACL_NEW_PID=$pid; PW_ACL_NEW_BIRTH=$birth
	{
		printf '%s\n' "$pid" "$birth" && printf '%s' "$(shell_quote "$dir/core")" || return 1
		for arg in "$@"; do printf ' %s' "$(shell_quote "$arg")" || return 1; done
		printf '\n'
	} > "$dir/process" || return 1
}

_pw_acl_stop_process() {
	local dir="$1" pid= birth=
	if [ "${PW_ACL_NEW_DIR:-}" = "$dir" ]; then
		pid=$PW_ACL_NEW_PID; birth=$PW_ACL_NEW_BIRTH
	elif [ -e "$dir/process" ]; then
		{ IFS= read -r pid; IFS= read -r birth; } < "$dir/process" || return 1
	elif [ ! -e "$dir/core" ]; then return 0
	else return 1
	fi
	case "$pid:$birth" in *[!0-9:]*|:*) return 1 ;; esac
	if [ -z "$birth" ]; then [ ! -e "/proc/$pid" ]; return; fi
	# An unreadable identity is not proof that the owned process has exited.
	if [ -d "/proc/$pid" ] && [ -z "$(get_process_start_time "$pid")" ]; then return 1; fi
	_pw_global_ss_kill "$pid" "$birth"
}

_pw_acl_instance_stop() {
	local instance="$1" status=0
	_pw_acl_path "$instance" || return 1
	case "$instance" in "$GLOBAL_ACL_PATH"/split/*) _pw_global_instance_stop "$instance"; return ;; esac
	case "$(sed -n '1p' "$instance/meta")" in
		Hysteria) _pw_global_instance_stop "$instance" ;;
		SS)
			_pw_acl_stop_process "$instance/relay" || status=1
			_pw_acl_stop_process "$instance" || status=1
			[ "$status" = 0 ] && rm -rf "$instance"
			;;
		*) return 1 ;;
	esac
}

# Do not reclaim another ACL's pending attempt, even if it has no binding yet.
_pw_acl_collect() {
	local sid="$1" released="$2" instance owner refs status=0 visited=' '
	for instance in "$TMP_ACL_PATH"/split-acl/instance.* $released; do
		case "$visited" in *" $instance "*) continue ;; esac
		visited="$visited$instance "
		[ -d "$instance" ] || continue
		_pw_acl_path "$instance" || return 1
		owner=$(sed -n '5p' "$instance/meta") || return 1
		if [ "$owner" != "$sid" ]; then
			case " $released " in *" $instance "*) ;; *) continue ;; esac
		fi
		refs=0; _pw_global_instance_referenced "$instance" || refs=$?
		case "$refs" in
			0) ;;
			1) _pw_acl_instance_stop "$instance" || status=1 ;;
			*) status=1 ;;
		esac
	done
	[ "$status" = 0 ] || echolog "Split ACL $sid cleanup pending; ownership records retained."
	return "$status"
}

passwall_stop_acl_nodes() {
	local sid="$1" proto config instance released= saved= pending candidate
	_pw_acl_id "$sid" && _pw_acl_context || return 1
	pending="$TMP_ACL_PATH/split-acl/release.$sid"
	if [ -e "$pending" ]; then
		[ ! -L "$pending" ] || return 1
		saved=$(tr '\n' ' ' < "$pending") || return 1
	fi
	for proto in tcp udp; do
		config=$(get_cache_var "ACL_${sid}_${proto}_instance") || { [ ! -s "$TMP_PATH/var" ] || return 1; }
		[ -n "$config" ] || continue
		instance=${config%/config.json}
		[ "$config" = "$instance/config.json" ] && _pw_acl_path "$instance" || return 1
		released="$released $instance"
	done
	released="$saved$released"
	# Persist exact release responsibility BEFORE unpublishing. A last consumer
	# may not be the creator; failed global-instance cleanup needs the path too.
	if [ -n "$released" ]; then
		mkdir -p "$TMP_ACL_PATH/split-acl" || return 1
		candidate=$(mktemp "$pending.XXXXXX") || return 1
		if ! (
			set -f
			written=' '
			for instance in $released; do
				case "$written" in *" $instance "*) continue ;; esac
				_pw_acl_location "$instance" && printf '%s\n' "$instance" || exit 1
				written="$written$instance "
			done
		) > "$candidate" || ! mv -f "$candidate" "$pending"; then
			rm -f "$candidate" || echolog "Split ACL $sid release-list temporary cleanup pending: $candidate"
			return 1
		fi
	fi
	set_cache_vars "ACL_${sid}_tcp_node" '' "ACL_${sid}_tcp_redir_port" '' "ACL_${sid}_tcp_instance" '' "ACL_${sid}_tcp_default" '' \
		"ACL_${sid}_udp_node" '' "ACL_${sid}_udp_redir_port" '' "ACL_${sid}_udp_instance" '' "ACL_${sid}_udp_default" '' \
		"ACL_${sid}_split_failed" '' || return 1
	_pw_acl_collect "$sid" "$released" || return 1
	[ ! -e "$pending" ] || rm -f "$pending"
}

# 0=found, 2=no compatible binding, 1=ownership/cache cannot be read safely.
_pw_acl_find() {
	local node="$1" tcp="$2" udp="$3" log="$4" level="$5" keys key config instance snapshot context prefix bound_node bound_port actual
	PW_ACL_REUSE=
	[ -e "$TMP_PATH/var" ] || return 2
	keys=$(sed -n 's/^\(ACL_[A-Za-z0-9_]*_instance\)=.*/\1/p' "$TMP_PATH/var") || return 1
	snapshot=$(uci -q show "$CONFIG.$node") || return 1
	context=$(printf '%s\n' "$TCP_PROXY_WAY" "${PROXY_IPV6:-0}" "$log" "$level")
	for key in $keys; do
		config=$(get_cache_var "$key") || return 1
		instance=${config%/config.json}
		# Independent ACLs reuse only ACL-owned, context-compatible instances.
		case "$instance" in "$TMP_ACL_PATH"/split-acl/instance.*) ;; *) continue ;; esac
		[ "$config" = "$instance/config.json" ] && _pw_acl_path "$instance" || continue
		prefix=${key%_instance}
		bound_node=$(get_cache_var "${prefix}_node") || return 1
		bound_port=$(get_cache_var "${prefix}_redir_port") || return 1
		[ "$bound_node" = "$node" ] && [ -n "$bound_port" ] || continue
		case "$prefix" in
			*_tcp) actual=$(sed -n '3p' "$instance/meta") || return 1 ;;
			*_udp) actual=$(sed -n '4p' "$instance/meta") || return 1 ;;
			*) continue ;;
		esac
		[ "$bound_port" = "$actual" ] || continue
		[ "$(sed -n '2p' "$instance/meta")" = "$node" ] || continue
		[ "$(cat "$instance/context")" = "$context" ] && [ "$(cat "$instance/node.snapshot")" = "$snapshot" ] || continue
		[ "$tcp" = 0 ] || [ -n "$(sed -n '3p' "$instance/meta")" ] || continue
		[ "$udp" = 0 ] || [ -n "$(sed -n '4p' "$instance/meta")" ] || continue
		_pw_acl_instance_ready "$instance" || continue
		PW_ACL_REUSE=$instance
		return 0
	done
	return 2
}

# Publish a complete protocol tuple + inheritance flag together. 3 is private:
# cache withdrawal failed; caller must retain the instance and return hard error.
_pw_acl_publish() {
	local sid="$1" instance="$2" tcp="$3" udp="$4" inherit="$5" node tport uport
	_pw_acl_instance_ready "$instance" || return 1
	node=$(sed -n '2p' "$instance/meta") || return 1
	tport=$(sed -n '3p' "$instance/meta") || return 1
	uport=$(sed -n '4p' "$instance/meta") || return 1
	set --
	[ "$tcp" = 0 ] || { [ -n "$tport" ] && set -- "$@" "ACL_${sid}_tcp_node" "$node" "ACL_${sid}_tcp_redir_port" "$tport" "ACL_${sid}_tcp_instance" "$instance/config.json" "ACL_${sid}_tcp_default" "$inherit"; } || return 1
	[ "$udp" = 0 ] || { [ -n "$uport" ] && set -- "$@" "ACL_${sid}_udp_node" "$node" "ACL_${sid}_udp_redir_port" "$uport" "ACL_${sid}_udp_instance" "$instance/config.json" "ACL_${sid}_udp_default" "$inherit"; } || return 1
	set_cache_vars "$@" || return 1
	_pw_acl_instance_ready "$instance" && return 0
	set --
	[ "$tcp" = 0 ] || set -- "$@" "ACL_${sid}_tcp_node" '' "ACL_${sid}_tcp_redir_port" '' "ACL_${sid}_tcp_instance" '' "ACL_${sid}_tcp_default" ''
	[ "$udp" = 0 ] || set -- "$@" "ACL_${sid}_udp_node" '' "ACL_${sid}_udp_redir_port" '' "ACL_${sid}_udp_instance" '' "ACL_${sid}_udp_default" ''
	set_cache_vars "$@" || return 3
	return 1
}

_pw_acl_create() {
	local sid="$1" node="$2" tcp="$3" udp="$4" log="$5" level="$6" core port socks mode bin i logfile
	PW_ACL_CREATED= PW_ACL_NEW_DIR= PW_ACL_NEW_PID= PW_ACL_NEW_BIRTH=
	_pw_acl_node_supported "$node" || return 2
	core=$(config_n_get "$node" type)
	case "$core" in SS|Hysteria) ;; *) return 2 ;; esac
	[ "$tcp" = 0 ] || { case "$TCP_PROXY_WAY" in redirect|tproxy) ;; *) return 2 ;; esac; }
	if [ "$tcp:$udp" = 1:1 ]; then port=$(get_new_port 11200 tcp,udp)
	elif [ "$tcp" = 1 ]; then port=$(get_new_port 11200 tcp)
	else port=$(get_new_port 11200 udp); fi
	case "$port" in ''|*[!0-9]*) return 2 ;; esac
	[ "$port" -gt 0 ] && [ "$port" -le 65535 ] || return 2
	socks=$(get_new_port 11100 tcp,udp) || return 2
	case "$socks" in ''|*[!0-9]*) return 2 ;; esac
	[ "$socks" -gt 0 ] && [ "$socks" -le 65535 ] || return 2
	mkdir -p "$TMP_ACL_PATH/split-acl" || return 1
	PW_ACL_CREATED=$(mktemp -d "$TMP_ACL_PATH/split-acl/instance.XXXXXX") || return 1
	local instance=$PW_ACL_CREATED
	if ! {
		printf '%s\n' "$core" "$node" "$( [ "$tcp" = 1 ] && echo "$port" )" "$( [ "$udp" = 1 ] && echo "$port" )" "$sid" > "$instance/meta" &&
		printf '%s\n' "$TCP_PROXY_WAY" "${PROXY_IPV6:-0}" "$log" "$level" > "$instance/context" &&
		uci -q show "$CONFIG.$node" > "$instance/node.snapshot" &&
		printf '%s\n' "$socks" > "$instance/socks_port"
	}; then
		rm -rf "$instance" || return 1
		PW_ACL_CREATED=
		return 2
	fi
	logfile=/dev/null; [ "$log" = 0 ] || logfile="$instance/node.log"
	json_init; json_add_string node "$node"
	case "$core" in
		Hysteria)
			[ "$tcp" = 0 ] || json_add_string local_tcp_redir_port "$port"
			[ "$udp" = 0 ] || json_add_string local_udp_redir_port "$port"
			json_add_string local_socks_address 127.0.0.1; json_add_string local_socks_port "$socks"
			json_add_string tcp_proxy_way "$TCP_PROXY_WAY"; json_add_string proxy_ipv6 "${PROXY_IPV6:-0}"
			gen_hysteria_config "$(json_dump)" "$instance/config.json" && start_hysteria "$instance/config.json" "$logfile" "$level" || return 2
			;;
		SS)
			mode=tcp_only; [ "$udp" = 0 ] || mode=tcp_and_udp
			json_add_string local_addr 127.0.0.1; json_add_string local_port "$socks"; json_add_string mode "$mode"
			gen_ss_config "$(json_dump)" "$instance/config.json" || return 2
			bin=$(first_type ss-local) && _pw_acl_launch "$instance" "$logfile" "$bin" -c "$instance/config.json" -v || return 2
			mkdir "$instance/relay" || return 1
			set -- -l "$port" -b 0.0.0.0 -B :: -s 127.0.0.1 -p "$socks" -o 60 -n 65535 -v
			[ "$TCP_PROXY_WAY" != redirect ] || set -- "$@" -R
			[ "$tcp:$udp" != 1:0 ] || set -- "$@" -T
			[ "$tcp:$udp" != 0:1 ] || set -- "$@" -U
			bin=$(first_type ipt2socks) && _pw_acl_launch "$instance/relay" "$logfile" "$bin" "$@" || return 2
			;;
	esac
	for i in $(seq 1 100); do
		if _pw_acl_instance_ready "$instance"; then sleep 0.1; _pw_acl_instance_ready "$instance"; return; fi
		sleep 0.1
	done
	return 2
}

_pw_acl_acquire() {
	local sid="$1" node="$2" tcp="$3" udp="$4" log="$5" level="$6" found=0 result=0 instance refs=0
	_pw_acl_node_supported "$node" || return 2
	_pw_acl_find "$node" "$tcp" "$udp" "$log" "$level" || found=$?
	case "$found" in
		0) _pw_acl_publish "$sid" "$PW_ACL_REUSE" "$tcp" "$udp" ''; result=$?; [ "$result" = 0 ] && return 0; [ "$result" != 3 ] || return 1; return 2 ;;
		1) return 1 ;;
	esac
	_pw_acl_create "$sid" "$node" "$tcp" "$udp" "$log" "$level" || result=$?
	instance=$PW_ACL_CREATED
	if [ "$result" = 0 ]; then _pw_acl_publish "$sid" "$instance" "$tcp" "$udp" '' || result=$?; fi
	[ "$result" != 0 ] || { PW_ACL_NEW_DIR= PW_ACL_NEW_PID= PW_ACL_NEW_BIRTH=; return 0; }
	echolog "Split ACL $sid/$node failed: instance=$instance status=$result"
	[ "$result" != 3 ] || return 1
	if [ -n "$instance" ]; then
		_pw_global_instance_referenced "$instance" || refs=$?
		[ "$refs" = 1 ] && _pw_acl_instance_stop "$instance" || return 1
	fi
	return 2
}

# sid, effective mode, use_global_config, canonical selectors, log flag, level.
# Transparent capabilities only: no source/DNS/rule/overall-enabled publication.
passwall_start_acl_nodes() {
	local sid="$1" mode="$2" inherit="$3" tcp="$4" udp="$5" log="$6" level="$7" gt= gu= status=0 result=0 found=0
	[ "$#" = 7 ] && _pw_acl_id "$sid" && _pw_acl_context || return 1
	passwall_stop_acl_nodes "$sid" || return 1
	passwall_resolve_acl_node_pair "$mode" "$inherit" "$tcp" "$udp" '' '' || return 1
	[ "${mode:-0}" != 0 ] || return 0
	case "$log" in 0|1) ;; *) return 1 ;; esac
	case "$level" in trace|debug|info|warn|error|fatal|panic) ;; *) return 1 ;; esac
	if [ "$PW_NODE_INHERIT" = 1 ]; then
		if passwall_global_node_ready TCP; then gt=$(get_cache_var ACL_GLOBAL_TCP_node) || return 1; fi
		if passwall_global_node_ready UDP; then gu=$(get_cache_var ACL_GLOBAL_UDP_node) || return 1; fi
		passwall_resolve_acl_node_pair "$mode" "$inherit" '' '' "$gt" "$gu" || return 1
		tcp=$PW_NODE_TCP; udp=$PW_NODE_UDP
		if [ -n "$tcp" ]; then
			_pw_acl_publish "$sid" "$(get_cache_var ACL_GLOBAL_TCP_instance | sed 's,/config.json$,,')" 1 0 1 || status=$?
		fi
		[ "$status" != 3 ] || return 1
		if [ -n "$udp" ]; then
			_pw_acl_publish "$sid" "$(get_cache_var ACL_GLOBAL_UDP_instance | sed 's,/config.json$,,')" 0 1 1 || result=$?
		fi
		[ "$result" != 3 ] || return 1
		[ "$status:$result" = 0:0 ] || status=2
	else
		tcp=$PW_NODE_TCP; udp=$PW_NODE_UDP
		if [ -n "$tcp" ] && [ "$tcp" = "$udp" ] && _pw_acl_node_supported "$tcp"; then
			_pw_acl_find "$tcp" 1 1 "$log" "$level" || found=$?
			[ "$found" != 1 ] || return 1
			if [ "$found" = 2 ]; then
				found=0
				_pw_acl_find "$tcp" 1 0 "$log" "$level" || found=$?
				[ "$found" != 1 ] || return 1
				if [ "$found" = 2 ]; then found=0; _pw_acl_find "$udp" 0 1 "$log" "$level" || found=$?; fi
			fi
			[ "$found" != 1 ] || return 1
			if [ "$found" = 2 ] || { [ "$found" = 0 ] && [ -n "$(sed -n '3p' "$PW_ACL_REUSE/meta")" ] && [ -n "$(sed -n '4p' "$PW_ACL_REUSE/meta")" ]; }; then
				_pw_acl_acquire "$sid" "$tcp" 1 1 "$log" "$level" || status=$?
				tcp= udp=
			fi
		fi
		[ "$status" != 1 ] || return 1
		if [ -n "$tcp" ]; then _pw_acl_acquire "$sid" "$tcp" 1 0 "$log" "$level" || status=$?; fi
		[ "$status" != 1 ] || return 1
		if [ -n "$udp" ]; then _pw_acl_acquire "$sid" "$udp" 0 1 "$log" "$level" || result=$?; fi
		[ "$result" != 1 ] || return 1
		[ "$result" = 0 ] || status=2
	fi
	if [ "$status" != 0 ]; then
		echolog "Split ACL $sid: failed protocol safely isolated; other ready bindings retained."
		set_cache_vars "ACL_${sid}_split_failed" 1 || return 1
	fi
	return "$status"
}
