#!/bin/sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
TMP_PATH="$work/runtime"
mkdir -p "$TMP_PATH"
fail() { echo "FAIL: $*" >&2; exit 1; }
# PRODUCTION_RESOLVER
# PRODUCTION_CACHE

pair() {
	passwall_resolve_node_pair "$1" "$2" || fail 'pair rejected'
	[ "$PW_NODE_TCP:$PW_NODE_UDP:$PW_NODE_LAYOUT:$PW_NODE_UDP_SELECTOR" = "$3:$4:$5:$2" ] || fail "pair $1/$2"
	[ "$PW_NODE_INHERIT" = 0 ] || fail 'pair inherited unexpectedly'
	passwall_resolve_acl_node_pair 1 0 "$1" "$2" unused unused || fail 'ACL pair rejected'
	[ "$PW_NODE_TCP:$PW_NODE_UDP:$PW_NODE_LAYOUT:$PW_NODE_UDP_SELECTOR:$PW_NODE_INHERIT" = "$3:$4:$5:$2:0" ] || fail "ACL pair $1/$2"
}
for core in ss_one hysteria_one; do
	pair "$core" tcp "$core" "$core" combined
	pair "$core" other "$core" other split
	pair "$core" '' "$core" '' tcp
	pair '' "$core" '' "$core" udp
	pair '' '' '' '' closed
	pair '' tcp '' '' closed
	pair "$core" "$core" "$core" "$core" combined
	[ "$PW_NODE_UDP_SELECTOR" = "$core" ] || fail 'explicit ID rewritten to follow'
	# A subsequent TCP change changes follow but not the explicit UDP ID.
	pair new_tcp tcp new_tcp new_tcp combined
	pair new_tcp "$core" new_tcp "$core" split
	for selection in tcp other '' "$core"; do
		passwall_resolve_acl_node_pair 1 0 "$core" "$selection" unused unused
		[ "$PW_NODE_TCP" = "$core" ] && [ "$PW_NODE_UDP_SELECTOR" = "$selection" ] || fail 'independent ACL changed'
	done
	passwall_resolve_acl_node_pair 1 0 '' "$core" unused unused
	[ "$PW_NODE_LAYOUT" = udp ] || fail 'UDP-only ACL rejected'
done
for tcp in ss_one hysteria_one; do
	for udp in ss_two hysteria_two; do pair "$tcp" "$udp" "$tcp" "$udp" split; done
done
passwall_resolve_node_pair '' ''
[ "$PW_NODE_LAYOUT" = closed ] || fail 'missing fields got defaults'
# Resolver has no section lookup; the independent SOCKS node is untouched.
node=independent_socks_node
tcp_selector=ss_one;udp_selector=tcp
passwall_resolve_node_pair "$tcp_selector" "$udp_selector"
[ "$tcp_selector:$udp_selector" = ss_one:tcp ] || fail 'persisted selection mutated'
[ "$node" = independent_socks_node ] || fail 'SOCKS node changed'
for unused in Xray missing sing-box; do
	passwall_resolve_acl_node_pair 0 1 "$unused" tcp ss_one hysteria_one
	[ "$PW_NODE_LAYOUT:$PW_NODE_INHERIT" = closed:0 ] || fail 'mode=0 inherited or validated unused nodes'
done
passwall_resolve_acl_node_pair '' '' stale stale ss_one hysteria_one
[ "$PW_NODE_LAYOUT" = closed ] || fail 'missing mode is not 0'
for global_pair in both tcp udp closed; do
	gt=ss_one;gu=hysteria_one
	case "$global_pair" in tcp) gu=;;udp) gt=;;closed) gt=;gu=;;esac
	passwall_resolve_acl_node_pair 1 1 stale_invalid stale_invalid "$gt" "$gu"
	[ "$PW_NODE_TCP:$PW_NODE_UDP:$PW_NODE_INHERIT" = "$gt:$gu:1" ] || fail 'global successful state not inherited'
done
# Check EVERY returned variable after a nonempty successful result. Otherwise
# stale selectors/inheritance, or a test seeded with closed state, can escape.
result() {
	[ "$PW_NODE_TCP" = "$1" ] || fail 'TCP result retained or changed'
	[ "$PW_NODE_UDP" = "$2" ] || fail 'UDP result retained or changed'
	[ "$PW_NODE_UDP_SELECTOR" = "$3" ] || fail 'UDP selector retained or changed'
	[ "$PW_NODE_LAYOUT" = "$4" ] || fail 'layout retained or changed'
	[ "$PW_NODE_INHERIT" = "$5" ] || fail 'inheritance retained or changed'
}
seed_result() {
	passwall_resolve_acl_node_pair 1 1 ignored ignored seed_tcp seed_udp
	result seed_tcp seed_udp seed_udp split 1
}
seed_result
passwall_resolve_node_pair '' tcp
result '' '' tcp closed 0
seed_result
passwall_resolve_node_pair ss_one tcp
result ss_one ss_one tcp combined 0
passwall_resolve_node_pair ss_one ss_one
result ss_one ss_one ss_one combined 0
passwall_resolve_node_pair hysteria_one ss_one
result hysteria_one ss_one ss_one split 0
passwall_resolve_node_pair hysteria_one tcp
result hysteria_one hysteria_one tcp combined 0
seed_result
passwall_resolve_acl_node_pair 1 0 '' hysteria_one unused unused
result '' hysteria_one hysteria_one udp 0
seed_result
passwall_resolve_acl_node_pair 1 0 '' '' unused unused
result '' '' '' closed 0
for inactive_flag in 0 1 invalid; do
	seed_result
	passwall_resolve_acl_node_pair 0 "$inactive_flag" retired_node tcp stale_global stale_global
	result '' '' '' closed 0
done
seed_result
passwall_resolve_acl_node_pair 1 1 ignored tcp '' hysteria_one
result '' hysteria_one hysteria_one udp 1
seed_result
passwall_resolve_acl_node_pair 1 1 ignored tcp '' ''
result '' '' '' closed 1
seed_result
passwall_resolve_acl_node_pair '' '' ignored tcp stale_global stale_global
result '' '' '' closed 0
for invalid_flag in invalid 2 01 true; do
	seed_result
	if passwall_resolve_acl_node_pair 1 "$invalid_flag" a b c d; then fail 'invalid inheritance accepted'; fi
	result '' '' '' closed 0
	seed_result
	if passwall_resolve_acl_node_pair "$invalid_flag" 0 a b c d; then fail 'invalid mode accepted'; fi
	result '' '' '' closed 0
done
for arity in zero short extra; do
	seed_result
	case "$arity" in
		zero) set -- ;;
		short) set -- a ;;
		extra) set -- a b c ;;
	esac
	if passwall_resolve_node_pair "$@"; then fail 'bad pair arity accepted'; fi
	result '' '' '' closed 0
	seed_result
	case "$arity" in
		zero) set -- ;;
		short) set -- 1 1 a b c ;;
		extra) set -- 1 1 a b c d extra ;;
	esac
	if passwall_resolve_acl_node_pair "$@"; then fail 'bad ACL arity accepted'; fi
	result '' '' '' closed 0
done
# Trap external reads at the OS boundary. This does not replace either resolver.
(
	unexpected_read() { echo "$1" > "$work/unexpected-read"; fail "$1"; }
	uci() { unexpected_read 'resolver read UCI'; }
	config_n_get() { unexpected_read 'resolver read a section'; }
	get_cache_var() { unexpected_read 'resolver read cache'; }
	check_node_supported() { unexpected_read 'resolver validated an inactive node'; }
	seed_result
	passwall_resolve_acl_node_pair 0 invalid retired tcp stale_global stale_global
	result '' '' '' closed 0
	passwall_resolve_acl_node_pair 1 1 retired tcp ss_one ''
	result ss_one '' '' tcp 1
)
[ ! -e "$work/unexpected-read" ] || fail 'resolver ignored an external read error'
echo 'PASS production resolver: five states, both cores, follow vs explicit, UDP-only, mode=0 and successful-global inheritance'
echo 'PASS production resolver: all five outputs reset across consecutive calls, invalid flags/arity and inactive fields; no UCI/cache reads'

if command -v uci >/dev/null 2>&1; then
	mkdir -p "$work/config" "$work/delta"
	package="pw_b1_${work##*.}"
	contract_uci() { uci -q -c "$work/config" -C "$work/config" -t "$work/delta" "$@"; }
	for core in SS Hysteria; do
		for layout in combined split tcp udp closed; do
			cat > "$work/config/$package" <<EOF
config global 'g'
config acl_rule 'a'
	option mode '1'
config nodes 'one'
	option type '$core'
config nodes 'two'
	option type '$core'
config socks 's'
	option node 'one'
EOF
			for sid in g a; do
				case "$layout" in
					combined) contract_uci set "$package.$sid.tcp_node=one";contract_uci set "$package.$sid.udp_node=tcp";et=one;eu=one ;;
					split) contract_uci set "$package.$sid.tcp_node=one";contract_uci set "$package.$sid.udp_node=two";et=one;eu=two ;;
					tcp) contract_uci set "$package.$sid.tcp_node=one";et=one;eu= ;;
					udp) contract_uci set "$package.$sid.udp_node=two";et=;eu=two ;;
					closed) et=;eu= ;;
				esac
			done
			contract_uci export "$package" > "$work/view-before"
			for sid in g a; do
				# Absence is intentional in these fixtures; never pass a get default.
				t=$(contract_uci get "$package.$sid.tcp_node" || :)
				u=$(contract_uci get "$package.$sid.udp_node" || :)
				pair "$t" "$u" "$et" "$eu" "$layout"
			done
			contract_uci export "$package" > "$work/view-after"
			cmp "$work/view-before" "$work/view-after" || fail 'resolver changed UCI view'
			[ "$(contract_uci get "$package.s.node")" = one ] || fail 'independent SOCKS section changed'
			rm -f "$work/delta/$package"
		done
	done
	echo 'PASS real UCI input: SS/Hysteria x five states x global/ACL, absent fields and independent SOCKS preserved'
else
	echo 'SKIP real UCI input fixtures (uci unavailable)'
fi

# Protocol tuples are the B2 contract. This fixture uses the REAL cache API;
# it does not stand in for an implemented listener readiness/ownership manager.
set_cache_vars ACL_GLOBAL_TCP_node ss_one ACL_GLOBAL_TCP_redir_port 1041 \
	ACL_GLOBAL_TCP_instance "$work/global_TCP.json" \
	ACL_a_tcp_node ss_one ACL_a_tcp_redir_port 1041 ACL_a_tcp_instance "$work/global_TCP.json" \
	ACL_keep_udp_node hysteria_one ACL_keep_udp_redir_port 1151 ACL_keep_udp_instance "$work/keep_UDP.json"
[ -z "$(get_cache_var ACL_GLOBAL_UDP_redir_port)" ] || fail 'TCP-only became UDP-ready'
# No implicit node-ID-to-capability conversion: same node can have another owner.
set_cache_vars ACL_b_udp_node ss_one ACL_b_udp_redir_port 1051 ACL_b_udp_instance "$work/ss_UDP.json"
[ "$(get_cache_var ACL_a_tcp_instance)" != "$(get_cache_var ACL_b_udp_instance)" ] || fail 'split instances conflated'
set_cache_vars ACL_c_tcp_node "$(get_cache_var ACL_a_tcp_node)" \
	ACL_c_tcp_redir_port "$(get_cache_var ACL_a_tcp_redir_port)" \
	ACL_c_tcp_instance "$(get_cache_var ACL_a_tcp_instance)"
[ "$(get_cache_var ACL_c_tcp_instance)" = "$(get_cache_var ACL_a_tcp_instance)" ] || fail 'ready TCP sharing failed'

fault_key=;fault_kind=
printf() {
	if [ "$1" = '%s=%s\n' ] && [ "$2" = "$fault_key" ]; then
		[ "$fault_kind" != partial ] || command printf "%s='unfinished" "$2"
		return 1
	fi
	command printf "$@"
}
mv() { [ "$fault_kind" != rename ] || return 1; command mv "$@"; }
for fault_kind in append partial rename; do
	for fault_key in ACL_d_udp_node ACL_d_udp_redir_port ACL_d_udp_instance; do
		cp "$TMP_PATH/var" "$work/before"
		ACL_d_udp_node=old_shell;ACL_d_udp_redir_port=old_shell;ACL_d_udp_instance=old_shell
		if set_cache_vars ACL_d_udp_node ss_one ACL_d_udp_redir_port 1061 ACL_d_udp_instance "$work/new_UDP.json"; then
			fail 'partial binding publication succeeded'
		fi
		cmp "$TMP_PATH/var" "$work/before" || fail 'failed publication changed cache'
		for part in node redir_port instance; do
			[ -z "$(get_cache_var "ACL_d_udp_$part")" ] || fail 'failed endpoint visible downstream'
		done
		[ "$ACL_d_udp_node:$ACL_d_udp_redir_port:$ACL_d_udp_instance" = old_shell:old_shell:old_shell ] || fail 'failed publication updated shell'
	done
done
fault_key=;fault_kind=
# Unbinding A removes only its references; B, C, global and another node remain.
set_cache_vars ACL_a_tcp_node '' ACL_a_tcp_redir_port '' ACL_a_tcp_instance ''
[ -z "$(get_cache_var ACL_a_tcp_instance)" ] || fail 'unbound instance still visible'
[ "$(get_cache_var ACL_c_tcp_instance)" = "$work/global_TCP.json" ] || fail 'other shared binding removed'
[ "$(get_cache_var ACL_GLOBAL_TCP_redir_port)" = 1041 ] || fail 'global removed'
[ "$(get_cache_var ACL_b_udp_redir_port)" = 1051 ] || fail 'other protocol removed'
[ "$(get_cache_var ACL_keep_udp_node)" = hysteria_one ] || fail 'different node removed'
passwall_resolve_acl_node_pair 1 1 ignored ignored \
	"$(get_cache_var ACL_GLOBAL_TCP_node)" "$(get_cache_var ACL_GLOBAL_UDP_node)"
[ "$PW_NODE_TCP:$PW_NODE_UDP:$PW_NODE_LAYOUT" = ss_one::tcp ] || fail 'inheritance invented missing UDP capability'
set_cache_vars ACL_d_udp_node ss_one ACL_d_udp_redir_port 1061 ACL_d_udp_instance "$work/new_UDP.json"
[ "$(get_cache_var ACL_d_udp_redir_port)" = 1061 ] || fail 'normal publication failed'
sed() {
	[ "$2" != '/^ACL_d_udp_redir_port=/d' ] || return 1
	command sed "$@"
}
if del_cache_var ACL_d_udp_redir_port; then fail 'cleanup error reported success'; fi
[ "$(get_cache_var ACL_d_udp_redir_port)" = 1061 ] || fail 'failed cleanup silently hid persisted state'
# A retained tuple after failed cleanup is NOT permission to keep generating
# rules. B2 must propagate the unsafe result; B1 does not implement that caller.
unset -f sed
del_cache_var ACL_d_udp_redir_port
[ -z "$(get_cache_var ACL_d_udp_redir_port)" ] || fail 'cleanup retry failed'
echo 'PASS production cache: protocol-specific sharing, atomic append/partial/rename failure and unrelated binding preservation'

# Real port allocator/checker; only netstat output is an OS-boundary fixture.
# utils.sh runs without nounset; its existing optional locals are not initialized.
# Keep that production shell mode for the allocator rather than changing utils.
set +u
netstat() {
	case "$1" in
		-tln) echo 'tcp 0 0 0.0.0.0:1041 0.0.0.0:* LISTEN' ;;
		-uln) echo 'udp 0 0 0.0.0.0:1042 0.0.0.0:*' ;;
		-tuln) echo 'tcp 0 0 0.0.0.0:1041 0.0.0.0:* LISTEN'; echo 'udp 0 0 0.0.0.0:1042 0.0.0.0:*' ;;
	esac
}
[ "$(get_new_port 1041 TCP)" = 1042 ] || fail 'TCP allocation'
[ "$(get_new_port 1041 UDP)" = 1041 ] || fail 'UDP allocation'
[ "$(get_new_port 1041 tcp,udp)" = 1043 ] || fail 'combined allocation ignored a protocol'
echo 'PASS production port allocator: TCP, UDP and combined occupancy'
