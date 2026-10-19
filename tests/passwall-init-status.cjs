// Source the real init scripts. Only OS commands and child applications are fixtures.
const cp = require('node:child_process');
const path = require('node:path');
const image = process.env.PASSWALL_INIT_DOCKER;
const root = path.resolve(__dirname, '..');
const script = String.raw`
set -e
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export IPKG_INSTROOT="$work" events="$work/events"
mkdir -p "$work/usr/share/passwall" "$work/app" "$work/locks"
cat > "$work/usr/share/passwall/utils.sh" <<'SH'
CONFIG=passwall
APP_PATH=$IPKG_INSTROOT/app
LOCK_PATH=$IPKG_INSTROOT/locks
echolog() { echo "log $*" >> "$events"; }
SH
cat > "$work/app/app.sh" <<'SH'
#!/bin/sh
echo "app $1:$2" >> "$events"
case "$1" in
start) exit "$START_STATUS";;
stop) exit "$STOP_STATUS";;
esac
SH
chmod +x "$work/app/app.sh"
export START_STATUS=0 STOP_STATUS=0
UPDATE_STATUS=0; LOCK_STATUS=0; UNLOCK_STATUS=0
flock() {
    echo "flock $*" >> "$events"
    case "$1" in -u) return "$UNLOCK_STATUS";; *) return "$LOCK_STATUS";; esac
}
lua() { return "$UPDATE_STATUS"; }
uci() { echo 0; }
sleep() { :; }
fail() { echo "FAIL: $*" >&2; cat "$events" >&2; exit 1; }
expect_status() {
    local expected="$1" actual=0
    shift
    "$@" || actual=$?
    [ "$actual" = "$expected" ] || fail "expected $expected, received $actual: $*"
}
assert_unlocked() {
    grep -q '^flock -u 9$' "$events" || fail 'lock not released'
    if ( : >&9 ) 2>/dev/null; then fail 'lock descriptor still open'; fi
}
no_start() { ! grep -q '^app start:' "$events" || fail 'started after failed stop'; }
reset_events() { : > "$events"; }
. "$SOURCE/luci-app-passwall/root/etc/init.d/passwall"

for status in 0 7; do
    START_STATUS=$status; reset_events
    expect_status "$status" start start token
    grep -q '^app start:token$' "$events" || fail 'start argument lost'
    assert_unlocked
done
START_STATUS=0
for status in 0 9; do
    STOP_STATUS=$status; reset_events
    expect_status "$status" stop stop token
    grep -q '^app stop:token$' "$events" || fail 'stop argument lost'
    assert_unlocked
done
for command in restart reload; do
    STOP_STATUS=9; START_STATUS=0; reset_events
    expect_status 9 "$command" restart
    no_start; assert_unlocked
    STOP_STATUS=0; START_STATUS=7; reset_events
    expect_status 7 "$command" restart
    grep -q '^app start:' "$events" || fail 'start not attempted'
    assert_unlocked
    START_STATUS=0; reset_events
    expect_status 0 "$command" restart
    [ "$(grep '^app ' "$events" | tr '\n' '|')" = 'app stop:|app start:|' ] || fail 'wrong restart sequence'
    assert_unlocked
done
# Cleanup must never replace the original application result, even if unlock fails.
START_STATUS=7; UNLOCK_STATUS=3; reset_events
expect_status 7 start start token
assert_unlocked
UNLOCK_STATUS=0; START_STATUS=0
# A rule-update failure still releases the service lock and starts nothing.
UPDATE_STATUS=2; reset_events
expect_status 1 restart restart
! grep -q '^app ' "$events" || fail 'update failure launched application'
assert_unlocked
UPDATE_STATUS=0
# Boot readiness is published only after a successful stop/start pair.
STOP_STATUS=9; reset_events
expect_status 1 boot_func
[ ! -e "$LOCK_PATH/passwall_ready.lock" ] || fail 'false boot readiness'
STOP_STATUS=0; START_STATUS=7; reset_events
expect_status 1 boot_func
[ ! -e "$LOCK_PATH/passwall_ready.lock" ] || fail 'false boot readiness'
START_STATUS=0; reset_events
expect_status 0 boot_func
[ -e "$LOCK_PATH/passwall_ready.lock" ] || fail 'successful boot not marked ready'
# Preserve the existing client lock-contention behavior; do not release another lock.
LOCK_STATUS=1; reset_events
expect_status 1 stop stop token
! grep -q '^app ' "$events" || fail 'stop ran without lock'
! grep -q '^flock -u' "$events" || fail 'released a lock without acquiring it'
exec 9>&-
LOCK_STATUS=0
echo 'PASS real client init: start/stop/restart/reload status, arguments, unlock, update failure and boot readiness'

. "$SOURCE/luci-app-passwall/root/etc/init.d/passwall_server"
lua() {
    echo "server $2" >> "$events"
    case "$2" in start) return "$START_STATUS";; stop) return "$STOP_STATUS";; esac
}
config_load() { :; }
config_get() { start_delay=0; }
for command in start stop; do
    START_STATUS=7; STOP_STATUS=9; reset_events
    if [ "$command" = start ]; then expected=7; else expected=9; fi
    expect_status "$expected" "$command"
done
for command in restart reload boot_func; do
    START_STATUS=0; STOP_STATUS=9; reset_events
    expect_status 9 "$command"
    ! grep -q '^server start$' "$events" || fail 'server started after failed stop'
    START_STATUS=7; STOP_STATUS=0; reset_events
    expect_status 7 "$command"
    grep -q '^server start$' "$events" || fail 'server start not attempted'
    START_STATUS=0; reset_events
    expect_status 0 "$command"
    [ "$(grep '^server ' "$events" | tr '\n' '|')" = 'server stop|server start|' ] || fail 'wrong server restart sequence'
done
echo 'PASS real server init: start/stop/restart/reload/boot status and failed-stop isolation'
`;
if (image) {
  cp.execFileSync('docker', ['run', '--rm', '-i', '--network', 'none',
    '--mount', `type=bind,source=${root},target=/source,readonly`,
    '--env', 'SOURCE=/source', '--entrypoint', '/bin/ash', image, '-s'],
  { input: script, stdio: ['pipe', 'inherit', 'inherit'] });
} else {
  const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
  cp.execFileSync(bash, ['-s'], {
    input: script, env: { ...process.env, SOURCE: root.replaceAll('\\', '/') },
    stdio: ['pipe', 'inherit', 'inherit']
  });
}
