#!/bin/sh
# Real UCI; every config, delta and candidate stays inside the test directory.
set -eu
test_root=$(mktemp -d /tmp/passwall-split-test.XXXXXX)
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/source/config" "$test_root/source/state" "$test_root/output/config" "$test_root/output/state" "$test_root/shared-state"
view_config="$test_root/source/config"; view_state="$test_root/source/state"
candidate="$test_root/output/config/passwall"; fault=
uci() {
	local raw= conf="$view_config" state="$view_state" override= key
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-q) shift ;; -X|-N) raw="$raw $1"; shift ;;
			-c) conf="$2"; shift 2 ;; -C) override="$2"; shift 2 ;;
			-t) state="$2"; shift 2 ;; *) break ;;
		esac
	done
	key="$2"
	case "$key" in passwall_split_*) key="passwall${key#${key%%.*}}" ;; esac
	case "$fault:$1:$key" in
		udp:set:passwall.settings.udp_node=*|tcp:set:passwall.settings.tcp_node=*|delete:delete:passwall.settings.node|read:get:passwall.settings.node|tcp-read:get:passwall.settings.tcp_node|section:show:passwall.settings|package:show:passwall|late:delete:passwall.other.node) return 1 ;;
		source-export:export:passwall) [ "$conf" != "$view_config" ] || return 1 ;;
		final-export:export:passwall) [ "$conf" = "$view_config" ] || return 1 ;;
		partial-export:export:passwall)
			if [ "$conf" != "$view_config" ]; then printf '%s\n' 'package incomplete'; return 1; fi ;;
		partial:set:passwall.settings.tcp_node=*|partial-delete:delete:passwall.settings.node)
			command uci -q $raw -c "$conf" -C "${override:-$conf}" -t "$state" "$@"
			return 1 ;;
	esac
	# An extra real-UCI delta search path models the default delta path without
	# touching /tmp/.uci, so local runs are safe too.
	command uci -q $raw -c "$conf" -C "${override:-$conf}" -p "$test_root/shared-state" -t "$state" "$@" || return $?
	if [ "$fault:$1:$key:$conf" = "snapshot-delta:export:passwall:$view_config" ]; then
		command uci -q -c "$conf" -C "${override:-$conf}" -t "$test_root/shared-state" set passwall.settings.node=changed_after_snapshot
	fi
	return 0
}
mkdir() { [ "$fault" != mkdir ] || return 1; command mkdir "$@"; }
mktemp() { [ "$fault" != temp ] || return 1; command mktemp "$@"; }
mv() { [ "$fault" != publish ] || return 1; command mv "$@"; }
rm() {
	if [ "$fault" = cleanup ]; then
		case "${2-}" in "$candidate".??????*) return 1 ;; esac
	fi
	command rm "$@"
}
# MIGRATION_FUNCTION
reset_config() {
	fault=
	rm -f "$test_root/source/state/passwall" "$test_root/output/state/passwall" "$candidate"
	rm -f "$test_root/shared-state/passwall"
	rm -rf "$candidate".??????
	cat > "$test_root/source/config/passwall"
}
candidate_uci() { uci -c "$test_root/output/config" -t "$test_root/output/state" "$@"; }
remember_source() {
	uci -N export passwall > "$test_root/before.export"
	uci changes passwall > "$test_root/before.changes"
	cp "$test_root/source/config/passwall" "$test_root/before.file"
	if [ -f "$view_state/passwall" ]; then
		cp "$view_state/passwall" "$test_root/before.saved"; echo 1 > "$test_root/had.saved"
	else echo 0 > "$test_root/had.saved"; fi
}
assert_source() {
	uci -N export passwall > "$test_root/after.export"
	uci changes passwall > "$test_root/after.changes"
	cmp "$test_root/before.export" "$test_root/after.export"
	cmp "$test_root/before.changes" "$test_root/after.changes"
	cmp "$test_root/before.file" "$test_root/source/config/passwall"
	if [ "$(cat "$test_root/had.saved")" = 1 ]; then cmp "$test_root/before.saved" "$view_state/passwall"
	else [ ! -f "$view_state/passwall" ]; fi
}
prepare() {
	remember_source
	passwall_split_nodes_migrate "$candidate"
	assert_source
}
check_idempotent() (
	cp "$candidate" "$test_root/first.candidate"
	passwall_split_nodes_migrate "$candidate"
	cmp "$test_root/first.candidate" "$candidate"
	# Re-read the candidate itself as input: no re-migration or new defaults.
	view_config="$test_root/output/config"; view_state="$test_root/output/state"
	passwall_split_nodes_migrate "$test_root/again.candidate"
	cmp "$candidate" "$test_root/again.candidate"
)

reset_config <<'EOF'
# Preserve the source file byte-for-byte, including comments.
config global
 option node 'hy'
config acl_rule
 option node 'default'
 option use_global_config '1'
config acl_rule 'named'
 option node 'ss'
 option mode '0'
config socks 'keep'
 option node 'ss'
config nodes 'ss'
 option type 'SS'
EOF
prepare
[ "$(candidate_uci get 'passwall.@global[0].tcp_node')" = hy ]
[ "$(candidate_uci get 'passwall.@global[0].udp_node')" = tcp ]
[ "$(candidate_uci get 'passwall.@acl_rule[0].tcp_node')" = default ]
[ "$(candidate_uci get 'passwall.@acl_rule[0].udp_node')" = tcp ]
[ "$(candidate_uci get 'passwall.@acl_rule[0].use_global_config')" = 1 ]
[ "$(candidate_uci get passwall.named.mode)" = 0 ]
[ "$(candidate_uci get passwall.named.tcp_node)" = ss ]
[ "$(candidate_uci get passwall.keep.node)" = ss ]
! candidate_uci get 'passwall.@global[0].node'
! candidate_uci get passwall.named.node
check_idempotent
echo 'PASS real UCI: merged Lite, anonymous/named sections, ACL flags, unrelated SOCKS/nodes and idempotency'

for semantics in follow independent udp-close udp-only both-close; do
	reset_config <<'EOF'
config global 'settings'
config acl_rule
 option use_global_config '0'
 option mode '1'
EOF
	for sid in settings '@acl_rule[0]'; do
		case "$semantics" in
			follow|independent|udp-close) uci set "passwall.$sid.tcp_node=hy" ;;
		esac
		case "$semantics" in
			follow) uci set "passwall.$sid.udp_node=tcp" ;;
			independent|udp-only) uci set "passwall.$sid.udp_node=ss" ;;
			udp-close|both-close) uci set "passwall.$sid.udp_node=" ;;
		esac
	done
	prepare
	candidate_uci -N export passwall > "$test_root/canonical.export"
	cmp "$test_root/before.export" "$test_root/canonical.export"
	for sid in settings '@acl_rule[0]'; do
		case "$semantics" in
			follow|independent|udp-close) [ "$(candidate_uci get "passwall.$sid.tcp_node")" = hy ] ;;
			*) ! candidate_uci get "passwall.$sid.tcp_node" ;;
		esac
		case "$semantics" in
			follow) [ "$(candidate_uci get "passwall.$sid.udp_node")" = tcp ] ;;
			independent|udp-only) [ "$(candidate_uci get "passwall.$sid.udp_node")" = ss ] ;;
			*) ! candidate_uci get "passwall.$sid.udp_node" ;;
		esac
	done
	check_idempotent
	echo "PASS real UCI canonical semantics, global + independent ACL: $semantics"
done

reset_config <<'EOF'
config global 'settings'
 option node 'hy'
 option udp_node 'ss'
EOF
prepare
[ "$(candidate_uci get passwall.settings.tcp_node)" = hy ]
[ "$(candidate_uci get passwall.settings.udp_node)" = ss ]
check_idempotent
echo 'PASS real UCI: legacy alias plus explicit independent UDP preserved'

uci set passwall.settings.tcp_node=ss
uci set passwall.settings.udp_node=
prepare 2> "$test_root/warning"
[ "$(candidate_uci get passwall.settings.tcp_node)" = ss ]
! candidate_uci get passwall.settings.udp_node
grep -q 'keeping tcp_node' "$test_root/warning"
check_idempotent 2> "$test_root/warning"
echo 'PASS real UCI: canonical TCP wins with diagnostic, absent UDP stays Close'

# Success must not publish migration deltas either. A later unrelated commit
# may commit the caller's existing edits, but must not commit the migration.
reset_config <<'EOF'
config global 'settings'
 option node 'hy'
EOF
uci set passwall.settings.dns_mode=tcp
prepare
[ "$(candidate_uci get passwall.settings.dns_mode)" = tcp ]
uci set passwall.settings.enabled=0
uci commit passwall
[ "$(uci get passwall.settings.node)" = hy ]
[ "$(uci get passwall.settings.dns_mode)" = tcp ]
! uci get passwall.settings.tcp_node
! uci get passwall.settings.udp_node
echo 'PASS real UCI: successful preparation preserves caller pending edits; later unrelated commit cannot install migration'

reset_config <<'EOF'
config global 'settings'
 option node 'hy'
EOF
fault=snapshot-delta
passwall_split_nodes_migrate "$candidate"
fault=
[ "$(candidate_uci get passwall.settings.tcp_node)" = hy ]
[ "$(uci get passwall.settings.node)" = changed_after_snapshot ]
! uci get passwall.settings.tcp_node
! uci get passwall.settings.udp_node
echo 'PASS real UCI: shared delta added after source snapshot cannot override the private candidate or be overwritten by preparation'

for fault_case in source-export package section read tcp-read udp tcp delete partial partial-delete late final-export partial-export temp mkdir publish cleanup; do
	reset_config <<'EOF'
config global 'settings'
 option node 'hy'
config acl_rule 'other'
 option node 'ss'
config socks 'keep'
 option node 'ss'
EOF
	uci set passwall.settings.dns_mode=tcp
	[ "$fault_case" != tcp-read ] || uci set passwall.settings.tcp_node=ss
	remember_source
	printf '%s\n' 'previous candidate' > "$candidate"
	fault=$fault_case
	if passwall_split_nodes_migrate "$candidate"; then
		echo "FAIL: $fault_case reported success" >&2; exit 1
	fi
	fault=
	assert_source
	[ "$(cat "$candidate")" = 'previous candidate' ]
	# This reproduced the original defect: now a later commit cannot carry
	# any of the failed candidate's private deltas into the source package.
	uci set passwall.settings.enabled=0
	uci commit passwall
	[ "$(uci get passwall.settings.node)" = hy ]
	[ "$(uci get passwall.other.node)" = ss ]
	[ "$(uci get passwall.keep.node)" = ss ]
	! uci get passwall.settings.udp_node
	! uci get passwall.other.tcp_node
	! uci get passwall.other.udp_node
	if [ "$fault_case" = tcp-read ]; then [ "$(uci get passwall.settings.tcp_node)" = ss ]
	else ! uci get passwall.settings.tcp_node; fi
	prepare
	[ "$(candidate_uci get passwall.settings.tcp_node)" = "$(uci get passwall.settings.tcp_node || printf hy)" ]
	[ "$(candidate_uci get passwall.other.tcp_node)" = ss ]
	! candidate_uci get passwall.settings.node
	check_idempotent
	echo "PASS real UCI failure isolation + later commit + retry: $fault_case"
done
