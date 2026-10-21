#!/bin/sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
TMP_PATH=$work/runtime
mkdir -p "$work/live" "$work/delta"
fault=
cat() {
	case "$fault:$*" in
		list:*'/global '*'/acls') return 1 ;;
	esac
	command cat "$@"
}
uci() {
	local conf="$work/live" state="$work/delta" raw= override= key
	while [ "$#" -gt 0 ]; do
		case "$1" in -q) shift ;; -N|-X) raw="$raw $1"; shift ;;
			-c) conf=$2; shift 2 ;; -C) override=$2; shift 2 ;; -t) state=$2; shift 2 ;; *) break ;; esac
	done
	key=${2:-}
	case "$fault:$1:$key" in export:export:passwall|read:get:*.tcp_node|show:show:passwall_contract_*) return 1 ;; esac
	case "$fault:$1:$key" in partial:get:passwall_contract_*.settings.tcp_node)
		printf 'untrusted-partial-output\n'; return 1 ;; esac
	command uci -q $raw -c "$conf" -C "${override:-$conf}" -t "$state" "$@" || return $?
	if [ "$fault:$1:$key" = edit:export:passwall ]; then
		command uci -q -c "$work/live" -t "$work/delta" set passwall.settings.tcp_node=changed
	fi
}
# PRODUCTION_HELPERS
cat > "$work/live/passwall" <<'UCI'
config global 'settings'
 option enabled '1'
 option acl_enable '1'
 option tcp_node 'hy'
 option udp_node 'tcp'
 option dns_mode 'dns2socks'
config nodes 'hy'
 option type 'Hysteria'
 option address 'server.example'
 option port '443'
 option hysteria_auth_password 'fixture-secret'
config nodes 'ss'
 option type 'SS'
 option address 'ss.example'
 option port '8443'
config acl_rule 'first'
 option enabled '1'
 option mode '1'
 option use_global_config '1'
 option tcp_node 'retired'
config socks 'independent'
 option node 'ss'
config acl_rule
 option enabled '1'
 option mode '1'
 option udp_node 'ss'
config acl_rule 'disabled'
 option enabled '0'
 option tcp_node 'missing'
config global_rules 'policy'
 list direct_dns '192.0.2.53'
 list direct_dns '2001:db8::53'
UCI
fail() { echo "FAIL snapshot: $*" >&2; exit 1; }
remember() { uci -N export passwall > "$work/before"; uci changes passwall > "$work/changes"; }
unchanged() { uci -N export passwall > "$work/after"; cmp "$work/before" "$work/after"; uci changes passwall > "$work/current"; cmp "$work/changes" "$work/current"; }
remember
passwall_snapshot_capture || fail capture
a=$PW_SNAPSHOT_DIR
[ "$(passwall_snapshot_uci "$a" get settings.dns_mode)" = dns2socks ] || fail dns-not-frozen
[ "$(passwall_snapshot_uci "$a" get hy.hysteria_auth_password)" = fixture-secret ] || fail node-not-frozen
[ "$(passwall_snapshot_uci "$a" get policy.direct_dns)" = '192.0.2.53 2001:db8::53' ] || fail policy-list-not-frozen
[ "$(ls -ld "$a" | awk '{print $1}')" = drwx------ ] || fail private-permissions
passwall_snapshot_check "$a" || fail fresh
passwall_snapshot_pair "$a" global || fail global
[ "$PW_SNAPSHOT_TCP_RAW:$PW_SNAPSHOT_UDP_RAW:$PW_SNAPSHOT_TCP:$PW_SNAPSHOT_UDP:$PW_SNAPSHOT_LAYOUT" = hy:tcp:hy:hy:combined ] || fail follow
passwall_snapshot_pair "$a" acl first || fail inherit
[ "$PW_SNAPSHOT_TCP_RAW:$PW_SNAPSHOT_UDP_RAW:$PW_SNAPSHOT_TCP:$PW_SNAPSHOT_UDP:$PW_SNAPSHOT_INHERIT" = retired::hy:hy:1 ] || fail intent
sid=$(sed -n '2p' "$a/acls")
passwall_snapshot_pair "$a" acl "$sid" || fail anonymous
[ "$PW_SNAPSHOT_TCP:$PW_SNAPSHOT_UDP:$PW_SNAPSHOT_LAYOUT" = :ss:udp ] || fail udp-only
passwall_snapshot_pair "$a" acl disabled || fail disabled
[ -z "$PW_SNAPSHOT_TCP$PW_SNAPSHOT_UDP" ] || fail disabled-ready
unchanged
cp "$a/sealed" "$work/manifest"
head -n 1 "$work/manifest" > "$a/sealed"
if passwall_snapshot_pair "$a" global; then fail truncated-manifest; fi
cp "$work/manifest" "$a/sealed"
fault=partial
if partial=$(passwall_snapshot_uci "$a" get settings.tcp_node); then fail partial-read; fi
[ -z "$partial" ] || fail partial-read-output
fault=
for fault in list export show; do
	before=$(find "$TMP_PATH/contracts" -mindepth 1 -maxdepth 1 -type d | sort)
	if passwall_snapshot_capture; then fail "$fault accepted"; fi
	[ -z "$PW_SNAPSHOT_DIR" ] || fail failed-publication
	after=$(find "$TMP_PATH/contracts" -mindepth 1 -maxdepth 1 -type d | sort)
	[ "$before" = "$after" ] || fail failed-capture-resource
done
fault=
uci set passwall.settings.udp_node=hy
if passwall_snapshot_check "$a"; then fail stale; fi
passwall_snapshot_capture || fail next
b=$PW_SNAPSHOT_DIR
[ "$a" != "$b" ] && [ -f "$a/sealed" ] || fail generation
passwall_snapshot_pair "$b" global || fail explicit
[ "$PW_SNAPSHOT_UDP_RAW" = hy ] || fail explicit-lost
[ "$(passwall_snapshot_uci "$a" get settings.udp_node)" = tcp ] || fail old-snapshot-mutated
[ "$(passwall_snapshot_uci "$b" get independent.node)" = ss ] || fail socks
remember
for fault in export show read; do
	if [ "$fault" = read ]; then
		if passwall_snapshot_pair "$b" global; then fail read-error; fi
		[ -z "$PW_SNAPSHOT_TCP$PW_SNAPSHOT_UDP$PW_SNAPSHOT_TCP_RAW$PW_SNAPSHOT_UDP_RAW" ] || fail stale-results
	else
		if passwall_snapshot_capture; then fail "$fault accepted"; fi
		[ -z "$PW_SNAPSHOT_DIR" ] || fail failed-publication
	fi
done
fault=; unchanged
fault=edit
if passwall_snapshot_capture; then fail concurrent-edit; fi
fault=
passwall_snapshot_capture || fail retry
c=$PW_SNAPSHOT_DIR
uci set passwall.settings.tcp_node=hy
# Frozen reads still describe the old generation; fresh check rejects reuse.
if passwall_snapshot_check "$c"; then fail edit-after-capture; fi
passwall_snapshot_pair "$c" global || fail frozen-read
[ "$PW_SNAPSHOT_TCP" = changed ] || fail reread-live
printf 'corrupt\n' >> "$b/acls"
if passwall_snapshot_pair "$b" global; then fail corrupt-index; fi
if passwall_snapshot_uci "$b" get hy.address; then fail corrupt-read; fi
[ -f "$a/sealed" ] && [ -f "$c/sealed" ] || fail cross-generation-cleanup
# Exercise all canonical states, without installing/migrating the configuration.
for core in hy ss; do
	for state in follow explicit tcp udp closed; do
		uci delete passwall.settings.tcp_node || :
		uci delete passwall.settings.udp_node || :
		case "$state" in follow|explicit|tcp) uci set "passwall.settings.tcp_node=$core" ;; esac
		case "$state" in follow) uci set passwall.settings.udp_node=tcp ;; explicit|udp) uci set "passwall.settings.udp_node=$core" ;; esac
		passwall_snapshot_capture && passwall_snapshot_pair "$PW_SNAPSHOT_DIR" global || fail "$core/$state"
		case "$state:$PW_SNAPSHOT_LAYOUT" in follow:combined|explicit:combined|tcp:tcp|udp:udp|closed:closed) ;; *) fail layout ;; esac
	done
done
uci set passwall.settings.udp_node=tcp
passwall_snapshot_capture && passwall_snapshot_pair "$PW_SNAPSHOT_DIR" global || fail missing-tcp-follow
[ "$PW_SNAPSHOT_LAYOUT" = closed ] || fail invented-tcp
uci set passwall.first.mode=0
uci set passwall.first.use_global_config=invalid
passwall_snapshot_capture && passwall_snapshot_pair "$PW_SNAPSHOT_DIR" acl first || fail mode-zero
[ "$PW_SNAPSHOT_LAYOUT:$PW_SNAPSHOT_INHERIT" = closed:0 ] || fail mode-zero-inherited
uci set passwall.settings.acl_enable=0
passwall_snapshot_capture && passwall_snapshot_pair "$PW_SNAPSHOT_DIR" acl first || fail acl-master
[ "$PW_SNAPSHOT_ENABLED:$PW_SNAPSHOT_ENABLED_RAW:$PW_SNAPSHOT_LAYOUT" = 0:1:closed ] || fail acl-master-active
uci set passwall.settings.node=hy
if passwall_snapshot_capture; then fail legacy-node-read-as-close; fi
[ -z "$PW_SNAPSHOT_DIR" ] && [ -f "$a/sealed" ] || fail legacy-rejection-cleanup
uci delete passwall.settings.node
uci set passwall.first.node=ss
if passwall_snapshot_capture; then fail legacy-acl-node-read-as-close; fi
[ -z "$PW_SNAPSHOT_DIR" ] || fail legacy-acl-publication
uci delete passwall.first.node
passwall_snapshot_capture || fail before-reorder
d=$PW_SNAPSHOT_DIR
passwall_snapshot_check "$d" || fail before-reorder-stale
uci reorder "passwall.$sid=0"
if passwall_snapshot_check "$d"; then fail acl-reorder-stale; fi
passwall_snapshot_capture || fail reordered-capture
new_sid=$(head -n 1 "$PW_SNAPSHOT_DIR/acls")
# Anonymous IDs are regenerated when the exported view is parsed. A reorder
# can therefore change the ID, but must preserve the section's fields/order.
[ "$(passwall_snapshot_uci "$PW_SNAPSHOT_DIR" get "$new_sid.udp_node")" = ss ] || fail acl-reorder-lost
[ "$(sed -n '2p' "$PW_SNAPSHOT_DIR/acls")" = first ] || fail acl-reorder-next
[ "$(sed -n '2p' "$d/acls")" = "$sid" ] || fail old-order-mutated
echo 'PASS real OpenWrt UCI/ash: snapshots, order, pending isolation, generations, five states, inheritance, stale/fault/retry and immutable reads'
