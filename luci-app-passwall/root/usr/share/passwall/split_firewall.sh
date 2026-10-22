#!/bin/sh
# B3.2 definitions only. No production caller or hook installation.
# Requires B2/B3.1, the cache API, lua and the lifecycle lock.

_pw_fw_error() {
	PW_FW_FAILED="${PW_FW_FAILED:-} $1 "
	printf '%s\n' "$2" >> "$1/error" || :
	echolog "Split firewall: $2"
	return 1
}

_pw_fw_dir() {
	[ -n "$TMP_PATH" ] || return 1
	[ "${1%/*}" = "$TMP_PATH/split-fw" ] || return 1
	case "${1##*/}" in generation.*) ;; *) return 1 ;; esac
	case "${1##*/}" in *[!a-zA-Z0-9_.]*) return 1 ;; esac
	[ -d "$1" ] && [ ! -L "$1" ] && [ -s "$1/context" ]
}

_pw_fw_port() {
	case "$1" in ''|*[!0-9]*) return 1 ;; esac
	[ "${#1}" -le 5 ] && [ "$1" -gt 0 ] && [ "$1" -le 65535 ]
}

_pw_fw_ports() {
	local item low high rest="$1"
	[ "$rest" != disable ] || return 0
	[ -n "$rest" ] || return 1
	while :; do
		item=${rest%%,*}; low=${item%%:*}; high=${item#*:}
		_pw_fw_port "$low" && _pw_fw_port "$high" && [ "$low" -le "$high" ] || return 1
		[ "$rest" != "${rest#*,}" ] || break
		rest=${rest#*,}
	done
}

_pw_fw_selectors() {
	case "$1$2" in *[!a-zA-Z0-9_-]*) return 1 ;; esac
}

# Policy snapshot uses the existing port/list semantics. Sets are supplied by
# the existing set/DNS layer; no set, DNS chain or UCI configuration is changed.
_pw_fw_policy() {
	local dir="$1" sid="$2" v
	_pw_fw_dir "$dir" && [ "$#" = 18 ] && _pw_acl_id "$sid" || return 1
	[ ! -e "$dir/sealed" ] && [ ! -e "$dir/global" ] && [ ! -e "$dir/error" ] || return 1
	shift 2
	for v in "$1" "$2" "$3" "$4" "$5" "$6"; do
		_pw_fw_ports "$v" || { _pw_fw_error "$dir" 'invalid port policy'; return 1; }
	done
	for v in "$7" "$8" "$9" "${10}"; do
		case "$v" in 0|1) ;; *) _pw_fw_error "$dir" 'invalid list flag'; return 1 ;; esac
	done
	case "${11}" in 0|direct|proxy) ;; *) _pw_fw_error "$dir" 'invalid China policy'; return 1 ;; esac
	for v in "${12}" "${13}"; do
		case "$v" in proxy|disable) ;; *) _pw_fw_error "$dir" 'invalid proxy policy'; return 1 ;; esac
	done
	# Per-scope dynamic proxy/GFW sets; static rule sets retain existing names.
	for v in "${14}" "${15}" "${16}"; do
		case "$v" in ''|*[!a-zA-Z0-9_]*) _pw_fw_error "$dir" 'invalid set name'; return 1 ;; esac
	done
	printf '%s\n' "$@" > "$dir/policy.$sid" || _pw_fw_error "$dir" 'policy snapshot write failed'
}

passwall_fw_begin() {
	local backend="$1" way="$2" ipv6="$3" dir token
	PW_FW_DIR=
	[ "$#" = 3 ] && [ -n "$TMP_PATH" ] || return 1
	case "$backend:$way:$ipv6" in nft:redirect:[01]|nft:tproxy:[01]|iptables:redirect:[01]|iptables:tproxy:[01]) ;; *) return 1 ;; esac
	mkdir -p "$TMP_PATH/split-fw" || return 1
	dir=$(mktemp -d "$TMP_PATH/split-fw/generation.XXXXXX") || return 1
	token="PWL${dir##*.}"
	printf '%s\n' "$backend" "$way" "$ipv6" "$token" > "$dir/context" || return 1
	[ "$ipv6" != 1 ] || touch "$dir/need6" || return 1
	PW_FW_DIR=$dir
}

# One actual backend rule. These chains have no hooks and no external jumps.
# Source/destination/ports below are validated before reaching this renderer.
_pw_fw_rule() {
	local dir="$1" family="$2" table="$3" chain="$4" proto="$5" source="$6" dest="$7" ports="$8" action="$9" port="${10}"
	local backend token nf=ip match= target= item rest="$ports" prefix suffix
	backend=$(sed -n '1p' "$dir/context") || return 1
	token=$(sed -n '4p' "$dir/context") || return 1
	[ "$family" = 4 ] || nf=ip6
	[ "$ports" != disable ] || return 0
	while :; do
		item=${rest%%,*}; match=
		if [ "$backend" = nft ]; then
			match="meta nfproto ipv$family"
			[ -z "$proto" ] || match="$match meta l4proto $proto"
			[ -z "${PW_FW_DEVICE:-}" ] || match="$match iifname \"$PW_FW_DEVICE\""
			case "$source" in
				ip:*) match="$match $nf saddr ${source#*:}" ;;
				mac:*) match="$match ether saddr ${source#*:}" ;;
				set:*) match="$match $nf saddr @${source#*:}" ;;
				range:*) match="$match $nf saddr ${source#*:}" ;;
				lo) match="$match iifname \"lo\" meta mark 0x50535731" ;;
				loopback) match="$match iifname \"lo\"" ;;
				*) ;;
			esac
			case "$dest" in
				set:*) match="$match $nf daddr @${dest#*:}" ;;
				ip:*) match="$match $nf daddr ${dest#*:}" ;;
				mark) match="$match meta mark & 0xff == 0xff" ;;
				reply) match="$match ct direction reply" ;;
				outlo) match="$match oifname \"lo\"" ;;
			esac
			[ -z "$item" ] || [ "$item" = 1:65535 ] || match="$match $proto dport ${item%:*}${item#${item%:*}}"
			# nft intervals use '-', iptables intervals use ':'.
			match=$(printf '%s' "$match" | sed 's/ dport \([0-9]*\):/ dport \1-/') || return 1
			case "$action" in
				return|drop|accept) target="counter $action" ;;
				redirect) target="counter redirect to :$port" ;;
				tproxy) target="counter meta mark set 0x50535731 ct mark set meta mark tproxy $nf to :$port accept" ;;
				mark) target='counter meta mark set 0x50535731 ct mark set meta mark accept' ;;
				*) return 1 ;;
			esac
			printf 'add rule inet passwall %s%s%s %s %s\n' "$token" "$chain" "$family" "$match" "$target" >> "$dir/$family.$table" || return 1
			# nft tproxy is non-terminal and issues NFT_BREAK without a usable
			# transparent socket. Success ACCEPTs; failure must not reach RETURN.
			[ "$action" != tproxy ] || printf 'add rule inet passwall %s%s%s %s counter drop\n' "$token" "$chain" "$family" "$match" >> "$dir/$family.$table" || return 1
		else
			[ -z "$proto" ] || match="-p $proto"
			[ -z "${PW_FW_DEVICE:-}" ] || match="$match -i $PW_FW_DEVICE"
			case "$source" in
				ip:*) match="$match -s ${source#*:}" ;;
				mac:*) match="$match -m mac --mac-source ${source#*:}" ;;
				set:*) match="$match -m set --match-set ${source#*:} src" ;;
				range:*) match="$match -m iprange --src-range ${source#*:}" ;;
				lo) match="$match -i lo -m mark --mark 0x50535731" ;;
				loopback) match="$match -i lo" ;;
			esac
			case "$dest" in
				set:*) match="$match -m set --match-set ${dest#*:} dst" ;;
				ip:*) match="$match -d ${dest#*:}" ;;
				mark) match="$match -m mark --mark 0xff/0xff" ;;
				reply) match="$match -m conntrack --ctdir REPLY" ;;
				outlo) match="$match -o lo" ;;
			esac
			[ -z "$item" ] || [ "$item" = 1:65535 ] || match="$match --dport $item"
			case "$action" in
				return) target='-j RETURN' ;;
				drop) target='-j DROP' ;;
				accept) target='-j ACCEPT' ;;
				redirect) target="-j REDIRECT --to-ports $port" ;;
				tproxy)
					printf -- '-A %s%s%s %s -j MARK --set-xmark 0x50535731/0xffffffff\n' "$token" "$chain" "$family" "$match" >> "$dir/$family.$table" &&
						printf -- '-A %s%s%s %s -j CONNMARK --save-mark\n' "$token" "$chain" "$family" "$match" >> "$dir/$family.$table" || return 1
					target="-j TPROXY --on-port $port --tproxy-mark 0x50535731/0xffffffff"
					;;
				mark)
					printf -- '-A %s%s%s %s -j MARK --set-xmark 0x50535731/0xffffffff\n' "$token" "$chain" "$family" "$match" >> "$dir/$family.$table" || return 1
					printf -- '-A %s%s%s %s -j CONNMARK --save-mark\n' "$token" "$chain" "$family" "$match" >> "$dir/$family.$table" || return 1
					target='-j ACCEPT'
					;;
				*) return 1 ;;
			esac
			printf -- '-A %s%s%s %s %s\n' "$token" "$chain" "$family" "$match" "$target" >> "$dir/$family.$table" || return 1
		fi
		[ "$rest" != "${rest#*,}" ] || break
		rest=${rest#*,}
	done
	if [ "$backend" = nft ]; then
		suffix=; [ "$family" = 4 ] || suffix=6
		case "$dest" in
			set:psw_white|set:psw_white6) prefix=white ;;
			set:psw_block|set:psw_block6) prefix=block ;;
			set:*_black|set:*_black6) prefix=black ;;
			set:psw_chn|set:psw_chn6) prefix=chn ;;
			*) return 0 ;;
		esac
		_pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" "set:psw_${prefix}${suffix}_static" "$ports" "$action" "$port" || return 1
	fi
}

_pw_fw_base() {
	local dir="$1" family="$2" suffix= chain table set
	[ "$family" = 4 ] || suffix=6
	for chain in P O N R; do
		case "$chain" in N|R) [ "$family" = 4 ] || continue; table=nat ;; *) table=mangle ;; esac
		for set in local lan wan; do
			_pw_fw_rule "$dir" "$family" "$table" "$chain" '' '' "set:psw_$set$suffix" '' return '' || return 1
		 done
		_pw_fw_rule "$dir" "$family" "$table" "$chain" '' '' reply '' return '' || return 1
		case "$chain" in O|R)
			_pw_fw_rule "$dir" "$family" "$table" "$chain" '' '' mark '' return '' &&
			_pw_fw_rule "$dir" "$family" "$table" "$chain" '' '' outlo '' return '' || return 1
			;;
		esac
	done
}

# Read one complete successful tuple; no port-only or node-ID-only reuse.
_pw_fw_state() {
	local role="$1" sid="$2" proto="$3" requested="$4" key actual state
	PW_FW_STATE= PW_FW_NODE= PW_FW_PORT= PW_FW_CONFIG=
	if [ "$role" = acl ]; then
		state=$(passwall_acl_protocol_state "$sid" "$proto" "$requested") || return 1
		key="ACL_${sid}_${proto}"
	else
		key="ACL_GLOBAL_$(printf '%s' "$proto" | tr 'a-z' 'A-Z')"
		actual=
		[ ! -e "$TMP_PATH/var" ] || { [ -f "$TMP_PATH/var" ] && [ -r "$TMP_PATH/var" ]; } || return 1
		if [ -s "$TMP_PATH/var" ]; then
			actual=$(get_cache_var "${key}_node") || return 1
			PW_FW_PORT=$(get_cache_var "${key}_redir_port") || return 1
			PW_FW_CONFIG=$(get_cache_var "${key}_instance") || return 1
		fi
		if [ -z "$requested" ]; then
			[ -z "$actual$PW_FW_PORT$PW_FW_CONFIG" ] || return 1
			state=closed
		elif [ -z "$actual$PW_FW_PORT$PW_FW_CONFIG" ]; then state=failed
		else
			[ "$actual" = "$requested" ] && [ -n "$PW_FW_PORT" ] && [ -n "$PW_FW_CONFIG" ] || return 1
			state=failed
			passwall_global_node_ready "${key#ACL_GLOBAL_}" && state=ready
		fi
	fi
	case "$state" in closed|failed) PW_FW_STATE=$state; return 0 ;; ready) ;; *) return 1 ;; esac
	PW_FW_NODE=$(get_cache_var "${key}_node") && PW_FW_PORT=$(get_cache_var "${key}_redir_port") &&
		PW_FW_CONFIG=$(get_cache_var "${key}_instance") || return 1
	[ "$PW_FW_NODE" = "$requested" ] && _pw_fw_port "$PW_FW_PORT" && [ -f "$PW_FW_CONFIG" ] || return 1
	PW_FW_STATE=ready
}

# Endpoints come from the running instance JSON, not possibly edited UCI.
# Domain endpoints are deferred until startup supplies a pinned resolution.
_pw_fw_remote() {
	local dir="$1" proto="$2" config="$3" endpoint host port stream addr family found=0
	[ -n "$PW_FW_ENDPOINT_HELPER" ] || return 1
	endpoint=$(lua "$PW_FW_ENDPOINT_HELPER" "$config" "$proto") || return 1
	read -r host port stream <<-EOF
	$endpoint
	EOF
	_pw_fw_port "$port" || return 1
	case "$stream" in tcp|udp) ;; *) return 1 ;; esac
	for family in 4 6; do
		case "$host" in
			*:*) [ "$family" = 6 ] || continue; addr=$host ;;
			*)
				if printf '%s' "$host" | grep -Eq '^[0-9.]+$'; then [ "$family" = 4 ] || continue; addr=$host
				else
					# A separate first-address lookup cannot prove the core chose
					# that A/AAAA, or will keep using it after retry. Do not guess.
					echolog 'Split firewall: unpinned domain endpoint requires the B3.3/B4 startup/resolution contract.'
					return 1
				fi
				;;
		esac
		[ -n "$addr" ] || continue
		case "$addr" in *[!0-9a-fA-F:.]*) return 1 ;; esac
		[ "$family" != 6 ] || touch "$dir/need6" || return 1
		printf '%s %s %s %s\n' "$family" "$stream" "$addr" "$port" >> "$dir/remotes" || return 1
		found=1
	done
	[ "$found" = 1 ]
}

_pw_fw_family_ready() {
	local config="$1" proto="$2" port="$3" family="$4" record pid birth
	if [ -f "${config%/config.json}/binding.json" ]; then
		# Strict diagnostics also prove IPv4 ability of a V6ONLY=0 socket.
		# /proc/net/tcp alone would incorrectly reject that verified capability.
		_pw_bound_helper verify "${config%/config.json}" "$family" "$proto" "$port"
		return
	fi
	record=$(lua "$PW_FW_ENDPOINT_HELPER" "$config" owner) || return 1
	read -r pid birth <<-EOF
	$record
	EOF
	_pw_global_ss_alive "$pid" "$birth" && _pw_global_ss_socket "$pid" "$proto" "$port" "$family" &&
		_pw_global_ss_alive "$pid" "$birth"
}

_pw_fw_families() {
	local dir="$1" proto="$2"
	PW_FW_F4_STATE=$PW_FW_STATE; PW_FW_F6_STATE=$PW_FW_STATE
	if [ "$PW_FW_STATE" = ready ]; then
		_pw_fw_family_ready "$PW_FW_CONFIG" "$proto" "$PW_FW_PORT" 4 || PW_FW_F4_STATE=failed
		_pw_fw_family_ready "$PW_FW_CONFIG" "$proto" "$PW_FW_PORT" 6 || PW_FW_F6_STATE=failed
	fi
	[ "$(sed -n '3p' "$dir/context")" = 1 ] || PW_FW_F6_STATE=closed
}

# md5sum is already required by api.md5_file/md5_string and the Hysteria registry.
# This detects a changed private JSON snapshot; it is not a security signature.
_pw_fw_signature() {
	local sum
	sum=$(md5sum < "$1") || return 1
	sum=${sum%% *}
	[ "${#sum}" = 32 ] || return 1
	case "$sum" in *[!a-fA-F0-9]*) return 1 ;; esac
	printf '%s' "$sum"
}

_pw_fw_record() {
	local dir="$1" role="$2" sid="$3" proto="$4" requested="$5" sum=-
	_pw_fw_families "$dir" "$proto" || return 1
	if [ "$PW_FW_STATE" = ready ] && { [ "$PW_FW_F4_STATE" != ready ] || { [ "$(sed -n '3p' "$dir/context")" = 1 ] && [ "$PW_FW_F6_STATE" != ready ]; }; }; then
		echolog "Split firewall: $role/$sid/$proto address-family listener missing; corresponding family is isolated."
	fi
	if [ "$PW_FW_STATE" = ready ]; then
		sum=$(_pw_fw_signature "$PW_FW_CONFIG") || return 1
	fi
	printf '%s %s %s %s %s %s %s %s %s %s\n' "$role" "$sid" "$proto" "${requested:--}" "$PW_FW_STATE" "${PW_FW_PORT:--}" "${PW_FW_CONFIG:--}" "$PW_FW_F4_STATE" "$PW_FW_F6_STATE" "$sum" >> "$dir/checks"
}

# A protocol scope ends with RETURN, even when closed. Failed scopes DROP in
# mangle before NAT (DROP is not a valid iptables nat target). Local sets precede
# these scopes so LAN DNS, local SRV/KMS and local listeners remain reachable.
_pw_fw_scope() {
	local dir="$1" sid="$2" proto="$3" state="$4" port="$5" source="$6" output="$7"
	local state4=$PW_FW_F4_STATE state6=$PW_FW_F6_STATE
	local no_t no_u drop_t drop_u redir_t redir_u direct proxy block gfw chn mode_t mode_u black black6 gset
	local family suffix chain table way action no drop redir mode set target dest stages selected
	{
		read -r no_t; read -r no_u; read -r drop_t; read -r drop_u; read -r redir_t; read -r redir_u
		read -r direct; read -r proxy; read -r block; read -r gfw; read -r chn; read -r mode_t; read -r mode_u
		read -r black; read -r black6; read -r gset
	} < "$dir/policy.$sid" || return 1
	way=$(sed -n '2p' "$dir/context") || return 1
	if [ "$proto" = tcp ]; then no=$no_t; drop=$drop_t; redir=$redir_t; mode=$mode_t
	else no=$no_u; drop=$drop_u; redir=$redir_u; mode=$mode_u; fi
	for family in 4 6; do
		[ "$family" = 4 ] || [ "$(sed -n '3p' "$dir/context")" = 1 ] || continue
		suffix=; [ "$family" = 4 ] || suffix=6
		state=$state4; [ "$family" = 4 ] || state=$state6
		case "$source" in
			ip:*) case "${source#*:}" in *:*) [ "$family" = 6 ] || continue ;; *) [ "$family" = 4 ] || continue ;; esac ;;
			range:*) [ "$family" = 4 ] || continue ;;
		esac
		chain=P; [ "$output" = 0 ] || chain=O
		# Closed/failed match in mangle AND return from the IPv4 NAT chain.
		if [ "$state" != ready ]; then
			action=return; [ "$state" != failed ] || action=drop
			_pw_fw_rule "$dir" "$family" mangle "$chain" "$proto" "$source" '' '' "$action" '' || return 1
			if [ "$family" = 4 ] && [ "$proto" = tcp ] && [ "$way" = redirect ]; then
				chain=N; [ "$output" = 0 ] || chain=R
				_pw_fw_rule "$dir" 4 nat "$chain" tcp "$source" '' '' return '' || return 1
			fi
			continue
		fi
		stages=mangle
		[ "$proto:$family:$way" != tcp:4:redirect ] || stages='mangle nat'
		for table in $stages; do
		chain=P; [ "$output" = 0 ] || chain=O
		action=tproxy
		if [ "$proto:$family:$way" = tcp:4:redirect ]; then
			action=return
			if [ "$table" = nat ]; then chain=N; [ "$output" = 0 ] || chain=R; action=redirect; fi
		elif [ "$output" = 1 ]; then action=mark; fi
		_pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" '' "$no" return '' || return 1
		[ "$block" = 0 ] || _pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" "set:psw_block$suffix" '' "$( [ "$table" = nat ] && echo return || echo drop )" '' || return 1
		[ "$direct" = 0 ] || _pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" "set:psw_white$suffix" '' return '' || return 1
		# Dynamic and static sets are distinct on nft; ipset already combines them.
		for set in "$( [ "$family" = 4 ] && echo "$black" || echo "$black6" )" "${gset}$suffix" "psw_chn$suffix" all; do
			selected=1
			case "$set" in
				"$black"|"$black6") [ "$proxy" = 1 ] || continue; target=$action ;;
				"${gset}$suffix") [ "$gfw" = 1 ] || continue; target=$action ;;
				"psw_chn$suffix") [ "$chn" != 0 ] || continue; target=return; selected=0; [ "$chn" != proxy ] || { target=$action; selected=1; } ;;
				all) [ "$mode" != disable ] || continue; target=$action ;;
			esac
			dest="set:$set"; [ "$set" != all ] || dest=
			if [ "$selected" = 1 ]; then
				# Drop ports share the same destination selection as proxy ports.
				[ "$table" = nat ] || _pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" "$dest" "$drop" drop '' || return 1
			fi
			_pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" "$dest" "$redir" "$target" "$port" || return 1
		done
		_pw_fw_rule "$dir" "$family" "$table" "$chain" "$proto" "$source" '' '' return '' || return 1
		done
	done
}

# Order calls as ACLs first, then exactly one global scope. Resolved selectors
# are the B1 snapshot retained by the caller, NOT inferred from successful ports.
_pw_fw_acl() {
	local dir="$1" sid="$2" enabled="$3" mode="$4" status="$5" tcp="$6" udp="$7" source="$8" proto requested
	local PW_FW_DEVICE="${9:-}"
	_pw_fw_dir "$dir" && { [ "$#" = 8 ] || [ "$#" = 9 ]; } && _pw_acl_id "$sid" || return 1
	case "$PW_FW_DEVICE" in *[!a-zA-Z0-9_.@-]*) return 1 ;; esac
	[ ! -e "$dir/sealed" ] && [ ! -e "$dir/global" ] && [ ! -e "$dir/error" ] || return 1
	[ "$enabled" != 0 ] || return 0
	[ "$enabled" = 1 ] || { _pw_fw_error "$dir" 'invalid ACL enabled'; return 1; }
	case "$mode:$status" in [01]:0|[01]:2) ;; *) _pw_fw_error "$dir" 'untrusted ACL initialization'; return 1 ;; esac
	case "$source" in
		any) ;;
		ip:*) printf '%s' "${source#*:}" | grep -Eq '^[0-9a-fA-F:.]+(/[0-9]{1,3})?$' || return 1 ;;
		mac:*) printf '%s' "${source#*:}" | grep -Eq '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$' || return 1 ;;
		iprange:*) source="range:${source#*:}"; printf '%s' "${source#*:}" | grep -Eq '^[0-9.]+-[0-9.]+$' || return 1 ;;
		set:*) case "${source#*:}" in ''|*[!a-zA-Z0-9_]*) return 1 ;; esac ;;
		*) _pw_fw_error "$dir" 'unsupported ACL source'; return 1 ;;
	esac
	[ "$mode" != 0 ] || { tcp=; udp=; }
	_pw_fw_selectors "$tcp" "$udp" || return 1
	for proto in tcp udp; do
		requested=$tcp; [ "$proto" = tcp ] || requested=$udp
		if [ "$mode" = 0 ]; then PW_FW_STATE=closed; PW_FW_PORT=; PW_FW_CONFIG=; PW_FW_NODE=
		else _pw_fw_state acl "$sid" "$proto" "$requested" || { _pw_fw_error "$dir" 'ACL capability query failed'; return 1; }; fi
		if [ "$PW_FW_STATE" = ready ]; then
			_pw_fw_remote "$dir" "$proto" "$PW_FW_CONFIG" || { _pw_fw_error "$dir" 'ACL endpoint unresolved'; return 1; }
		fi
		_pw_fw_record "$dir" "$( [ "$mode" = 0 ] && echo closed || echo acl )" "$sid" "$proto" "$requested" || return 1
		_pw_fw_scope "$dir" "$sid" "$proto" "$PW_FW_STATE" "$PW_FW_PORT" "$source" 0 || { _pw_fw_error "$dir" 'ACL render failed'; return 1; }
	done
}

_pw_fw_global() {
	local dir="$1" status="$2" tcp="$3" udp="$4" client="$5" output="$6" proto requested family port way
	_pw_fw_dir "$dir" && [ "$#" = 6 ] || return 1
	[ ! -e "$dir/sealed" ] && [ ! -e "$dir/global" ] && [ ! -e "$dir/error" ] || return 1
	case "$status:$client:$output" in [02]:[01]:[01]) ;; *) _pw_fw_error "$dir" 'untrusted global initialization'; return 1 ;; esac
	_pw_fw_selectors "$tcp" "$udp" || return 1
	way=$(sed -n '2p' "$dir/context") || return 1
	for proto in tcp udp; do
		requested=$tcp; [ "$proto" = tcp ] || requested=$udp
		_pw_fw_state global GLOBAL "$proto" "$requested" || { _pw_fw_error "$dir" 'global capability query failed'; return 1; }
		_pw_fw_record "$dir" global GLOBAL "$proto" "$requested" || return 1
		if [ "$PW_FW_STATE" = ready ]; then
			_pw_fw_remote "$dir" "$proto" "$PW_FW_CONFIG" || { _pw_fw_error "$dir" 'global endpoint unresolved'; return 1; }
			if [ "$output" = 1 ]; then
				for family in 4 6; do
					[ "$family" = 4 ] || [ "$(sed -n '3p' "$dir/context")" = 1 ] || continue
					[ "$proto:$family:$way" != tcp:4:redirect ] || continue
					case "$family:$PW_FW_F4_STATE:$PW_FW_F6_STATE" in 4:ready:*|6:*:ready) ;; *) continue ;; esac
					_pw_fw_rule "$dir" "$family" mangle L "$proto" lo '' '' tproxy "$PW_FW_PORT" || return 1
				done
			fi
		fi
		[ "$client" = 0 ] || _pw_fw_scope "$dir" global "$proto" "$PW_FW_STATE" "$PW_FW_PORT" any 0 || { _pw_fw_error "$dir" 'default client render failed'; return 1; }
		[ "$output" = 0 ] || _pw_fw_scope "$dir" global "$proto" "$PW_FW_STATE" "$PW_FW_PORT" any 1 || { _pw_fw_error "$dir" 'OUTPUT render failed'; return 1; }
	done
	printf '%s\n' "$output" > "$dir/output" && touch "$dir/global" || _pw_fw_error "$dir" 'global completion write failed'
}

# Public entry points poison an incomplete candidate on ANY error. An omitted
# ACL after a failed append must never silently fall through to the global rule.
passwall_fw_policy() { _pw_fw_policy "$@" || { _pw_fw_dir "$1" && _pw_fw_error "$1" 'policy rejected'; return 1; }; }
passwall_fw_acl() { _pw_fw_acl "$@" || { _pw_fw_dir "$1" && _pw_fw_error "$1" 'ACL candidate rejected'; return 1; }; }
passwall_fw_global() { _pw_fw_global "$@" || { _pw_fw_dir "$1" && _pw_fw_error "$1" 'global candidate rejected'; return 1; }; }

# Optional direct dependency check for the later DNS integration. It neither
# starts a helper nor claims that a DNS helper is ready. The caller must supply
# the actual DNS transport, never substitute a transparent port for a DNS port.
passwall_fw_check_dns() {
	local dir="$1" role="$2" sid="$3" via="$4" requested="$5" family="${6:-4}" proto port
	_pw_fw_dir "$dir" && { [ "$#" = 5 ] || [ "$#" = 6 ]; } || return 1
	case "$family" in 4|6) ;; *) return 1 ;; esac
	case "$role" in acl|global) ;; *) return 1 ;; esac
	[ "$via" != local ] || return 0
	case "$via" in
		tcp|udp)
			_pw_fw_state "$role" "$sid" "$via" "$requested" && [ "$PW_FW_STATE" = ready ] &&
				_pw_fw_family_ready "$PW_FW_CONFIG" "$via" "$PW_FW_PORT" "$family" && return 0
			;;
		socks)
			for proto in tcp udp; do
				_pw_fw_state "$role" "$sid" "$proto" "$requested" || continue
				[ "$PW_FW_STATE" = ready ] || continue
				# Only B3.1 private instances create/verify this native listener.
				[ -s "${PW_FW_CONFIG%/*}/socks_port" ] || continue
				port=$(cat "${PW_FW_CONFIG%/*}/socks_port") && _pw_fw_port "$port" && return 0
			done
			;;
	esac
	_pw_fw_error "$dir" "DNS dependency unavailable: $role/$sid via $via; B4 must provide a verified native SOCKS/DNS path."
}

_pw_fw_validate() {
	local dir="$1" role sid proto request state port config state4 state6 signature sum globals=' '
	[ ! -e "$dir/error" ] && [ -e "$dir/global" ] || return 1
	case "${PW_FW_FAILED:-}" in *" $dir "*) return 1 ;; esac
	while read -r role sid proto request state port config state4 state6 signature; do
		case "$role:$proto" in acl:tcp|acl:udp|closed:tcp|closed:udp|global:tcp|global:udp) ;; *) return 1 ;; esac
		if [ "$role" = global ]; then
			case "$globals" in *" $proto "*) return 1 ;; esac
			globals="$globals$proto "
		fi
		[ "$request" != - ] || request=
		if [ "$role" = closed ]; then PW_FW_STATE=closed; PW_FW_CONFIG=; PW_FW_PORT=
		else _pw_fw_state "$role" "$sid" "$proto" "$request" || return 1; fi
		[ "$PW_FW_STATE" = "$state" ] || return 1
		_pw_fw_families "$dir" "$proto" || return 1
		[ "$state4:$state6" = "$PW_FW_F4_STATE:$PW_FW_F6_STATE" ] || return 1
		if [ "$state" = ready ]; then
			[ "$PW_FW_PORT" = "$port" ] && [ "$PW_FW_CONFIG" = "$config" ] || return 1
			sum=$(_pw_fw_signature "$config") || return 1
			[ "$sum" = "$signature" ] || return 1
		fi
	done < "$dir/checks"
	[ "$globals" = ' tcp udp ' ] && _pw_fw_output_safe "$dir"
}

# Router OUTPUT cannot distinguish a core's outer connection from arbitrary
# local traffic by destination tuple alone. Refuse the unsafe intersection;
# per-core marks/credentials require later startup integration, not a guess here.
_pw_fw_output_safe() {
	local dir="$1" role sid proto request state port config state4 state6 signature family rfamily stream addr remote_port output
	output=$(cat "$dir/output") || return 1
	case "$output" in 0) return 0 ;; 1) ;; *) return 1 ;; esac
	[ -f "$dir/remotes" ] || return 0
	while read -r role sid proto request state port config state4 state6 signature; do
		[ "$role" = global ] || continue
		for family in 4 6; do
			case "$family:$state4:$state6" in 4:failed:*|6:*:failed) ;; *) continue ;; esac
			while read -r rfamily stream addr remote_port; do
				if [ "$rfamily:$stream" = "$family:$proto" ]; then
					_pw_fw_error "$dir" 'OUTPUT failure isolation conflicts with a core outer-transport exemption; later integration must distinguish core sockets.'
					return 1
				fi
			done < "$dir/remotes"
		done
	done < "$dir/checks"
}

# Prepare complete batches before a single firewall command runs. L rules (the
# marked OUTPUT loopback) precede LAN ACLs; remote bypasses precede all OUTPUT
# selection. A caller must not link any of these chains before apply succeeds.
_pw_fw_seal_files() {
	local dir="$1" backend token family table chain part remote_family stream addr port
	backend=$(sed -n '1p' "$dir/context") && token=$(sed -n '4p' "$dir/context") || return 1
	for family in 4 6; do
		[ "$family" = 4 ] || [ -e "$dir/need6" ] || continue
		for table in mangle nat; do
			[ "$family:$table" != 6:nat ] || continue
			part="$dir/$family.$table"
			[ ! -e "$part" ] || mv "$part" "$part.scope" || return 1
		done
		_pw_fw_base "$dir" "$family" || return 1
		if [ -e "$dir/remotes" ]; then
			sort -u "$dir/remotes" > "$dir/remotes.sorted" || return 1
			while read -r remote_family stream addr port; do
				[ "$remote_family" = "$family" ] || continue
				_pw_fw_rule "$dir" "$family" mangle O "$stream" '' "ip:$addr" "$port" return '' || return 1
				[ "$family:$stream" != 4:tcp ] || _pw_fw_rule "$dir" 4 nat R tcp '' "ip:$addr" "$port" return '' || return 1
			done < "$dir/remotes.sorted"
		fi
		if [ -s "$dir/$family.mangle.scope" ]; then
			awk -v l="$token"L"$family " -v p="$token"P"$family " 'index($0,l) {sub(l,p);print}' "$dir/$family.mangle.scope" >> "$dir/$family.mangle" || return 1
		fi
		_pw_fw_rule "$dir" "$family" mangle P '' loopback '' '' return '' || return 1
		for table in mangle nat; do
			[ "$family:$table" != 6:nat ] || continue
			if [ -s "$dir/$family.$table.scope" ]; then
				awk -v l="$token"L"$family " '!index($0,l)' "$dir/$family.$table.scope" >> "$dir/$family.$table" || return 1
			fi
			if [ "$backend" = nft ]; then
				: > "$dir/$family.$table.batch" || return 1
				for chain in $( [ "$table" = nat ] && echo 'N R' || echo 'P O' ); do
					printf 'create chain inet passwall %s%s%s\n' "$token" "$chain" "$family" >> "$dir/$family.$table.batch" || return 1
				done
				cat "$dir/$family.$table" >> "$dir/$family.$table.batch" || return 1
			else
				printf '*%s\n' "$table" > "$dir/$family.$table.batch" || return 1
				for chain in $( [ "$table" = nat ] && echo 'N R' || echo 'P O' ); do
					printf ':%s%s%s - [0:0]\n' "$token" "$chain" "$family" >> "$dir/$family.$table.batch" || return 1
				done
				cat "$dir/$family.$table" >> "$dir/$family.$table.batch" && printf 'COMMIT\n' >> "$dir/$family.$table.batch" || return 1
			fi
		done
	done
	cat "$dir"/*.batch > "$dir/nft.batch"
}

passwall_fw_seal() {
	local dir="$1"
	_pw_fw_dir "$dir" && [ ! -e "$dir/pending" ] && [ ! -e "$dir/sealed" ] || return 1
	_pw_fw_validate "$dir" && _pw_fw_seal_files "$dir" && touch "$dir/sealed" || {
		_pw_fw_error "$dir" 'sealing failed: changed capabilities or incomplete batch'; return 1
	}
}

_pw_fw_ipt() {
	local family="$1" restore="$2" name=iptables legacy
	[ "$family" = 4 ] || name=ip6tables
	legacy=$(command -v "$name-legacy")
	[ -z "$legacy" ] || name="$name-legacy"
	[ "$restore" = 0 ] || name="$name-restore"
	command -v "$name"
}

# Full successful inventories distinguish absent chains from a query failure.
# Never treat arbitrary nft/xtables errors as 'not found'.
_pw_fw_inventory() {
	local dir="$1" backend="$2" family="$3" table="$4" bin
	if [ "$backend" = nft ]; then
		nft list table inet passwall > "$dir/inventory" || return 1
		sed -n 's/^[[:space:]]*chain \([^[:space:]]*\).*/\1/p' "$dir/inventory"
	else
		bin=$(_pw_fw_ipt "$family" 0) || return 1
		"$bin" -w 5 -t "$table" -S > "$dir/inventory" || return 1
		sed -n 's/^-N //p' "$dir/inventory"
	fi
}

passwall_fw_discard() {
	local dir="$1" backend token family table chain inventory bin status=0
	_pw_fw_dir "$dir" || return 1
	[ -e "$dir/pending" ] || return 0
	# Withdraw the completion receipt before any destructive operation. A retry
	# must never mistake partly deleted chains for a complete installation.
	rm -f "$dir/installed" || { echolog "Split firewall receipt cleanup pending: $dir"; return 1; }
	backend=$(sed -n '1p' "$dir/context") && token=$(sed -n '4p' "$dir/context") || return 1
	for family in 4 6; do
		[ "$family" = 4 ] || [ -e "$dir/need6" ] || continue
		for table in mangle nat; do
			[ "$family:$table" != 6:nat ] || continue
			inventory=$(_pw_fw_inventory "$dir" "$backend" "$family" "$table") || { status=1; continue; }
			for chain in $( [ "$table" = nat ] && echo 'N R' || echo 'P O' ); do
				chain="$token$chain$family"
				printf '%s\n' "$inventory" | grep -Fxq "$chain" || continue
				if [ "$backend" = nft ]; then
					nft "flush chain inet passwall $chain" && nft "delete chain inet passwall $chain" || status=1
				else
					bin=$(_pw_fw_ipt "$family" 0) || { status=1; continue; }
					"$bin" -w 5 -t "$table" -F "$chain" && "$bin" -w 5 -t "$table" -X "$chain" || status=1
				fi
			done
		done
	done
	[ "$status" = 0 ] || { echolog "Split firewall cleanup pending: $dir"; return 1; }
	rm -f "$dir/pending"
}

# 0=complete detached generation, 2=failed but completely reclaimed,
# 1=untrusted candidate/cleanup. No hook, policy route or old chain is touched.
passwall_fw_apply() {
	local dir="$1" backend token family table chain inventory bin status=0
	_pw_fw_dir "$dir" || return 1
	[ -e "$dir/sealed" ] && _pw_fw_validate "$dir" || {
		_pw_fw_error "$dir" 'apply rejected: incomplete candidate or changed capability/configuration snapshot'; return 1
	}
	# The receipt is not evidence of current kernel contents after fw4 reload or
	# an external flush. Do not turn a repeated call into a cached success.
	[ ! -e "$dir/pending" ] || { echolog "Split firewall already applied or cleanup pending; inspect/rebuild $dir"; return 1; }
	backend=$(sed -n '1p' "$dir/context") && token=$(sed -n '4p' "$dir/context") || return 1
	# Check EVERY owned chain before recording ownership or changing anything.
	for family in 4 6; do
		[ "$family" = 4 ] || [ -e "$dir/need6" ] || continue
		for table in mangle nat; do
			[ "$family:$table" != 6:nat ] || continue
			inventory=$(_pw_fw_inventory "$dir" "$backend" "$family" "$table") || return 1
			for chain in $( [ "$table" = nat ] && echo 'N R' || echo 'P O' ); do
				printf '%s\n' "$inventory" | grep -Fxq "$token$chain$family" && return 1
			done
		done
	done
	touch "$dir/pending" || return 1
	if [ "$backend" = nft ]; then nft -f "$dir/nft.batch" || status=1
	else
		for family in 4 6; do
			[ "$family" = 4 ] || [ -e "$dir/need6" ] || continue
			for table in mangle nat; do
				[ "$family:$table" != 6:nat ] || continue
				bin=$(_pw_fw_ipt "$family" 1) && "$bin" -w 5 --noflush < "$dir/$family.$table.batch" || { status=1; break; }
			done
			[ "$status" = 0 ] || break
		done
	fi
	if [ "$status" = 0 ] && _pw_fw_validate "$dir" && touch "$dir/installed"; then return 0; fi
	passwall_fw_discard "$dir" || return 1
	return 2
}
