#!/bin/sh
# Run with real OpenWrt uci. The driver inserts the production cleanup code.
set -eu
test_root=$(mktemp -d /tmp/passwall-uci-test.XXXXXX)
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/config" "$test_root/state"
uci() { command uci -c "$test_root/config" -t "$test_root/state" "$@"; }
cleanup() {
    :
# PRODUCTION_CLEANUP
}
check_clean() {
    cleanup
    ! uci -q show passwall | grep -q '=subscribe_list$'
    ! uci -q show passwall | grep -q '=global_subscribe$'
    [ "$(uci get passwall.keep.type)" = SS ]
    [ "$(uci get passwall.keep.password)" = unchanged ]
    [ "$(uci get 'passwall.@acl_rule[0].node')" = keep ]
    [ "$(uci get passwall.settings.enabled)" = 1 ]
    cleanup # Idempotent, including when no subscription sections remain.
    uci commit passwall
    ! uci show passwall | grep -q '=subscribe_list$'
}
for scenario in anonymous mixed; do
    cat > "$test_root/config/passwall" <<'EOF'
config global 'settings'
 option enabled '1'
config nodes 'keep'
 option type 'SS'
 option password 'unchanged'
config acl_rule
 option node 'keep'
config global_subscribe
config global_subscribe 'named_global'
config subscribe_list
 option remark 'anonymous-one'
config subscribe_list
 option remark 'anonymous-two'
config subscribe_list
 option remark 'anonymous-three'
EOF
    if [ "$scenario" = mixed ]; then
        uci set passwall.named_one=subscribe_list
        uci add passwall subscribe_list >/dev/null
        uci set passwall.named_two=subscribe_list
        uci add passwall subscribe_list >/dev/null
    fi
    check_clean
    echo "PASS real UCI cleanup: $scenario; unrelated sections unchanged"
done
