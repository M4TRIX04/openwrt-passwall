// Uses the real production cleanup and SS shell startup branches.
// Optional real UCI: PASSWALL_UCI_DOCKER=openwrt/rootfs:x86-64 node tests/passwall-blockers.cjs
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8').replace(/\r\n/g, '\n');
const defaults = read('luci-app-passwall/root/etc/uci-defaults/luci-app-passwall');
const cleanup = defaults.match(/^while uci -q delete "passwall\.@subscribe_list\[0\]"; do :; done\nwhile uci -q delete "passwall\.@global_subscribe\[0\]"; do :; done/m);
if (!cleanup) throw Error('Production cleanup not found');
const fixture = read('tests/uci-subscription-cleanup.sh').replace('# PRODUCTION_CLEANUP', cleanup[0]);
if (process.env.PASSWALL_UCI_DOCKER) {
  cp.execFileSync('docker', ['run', '--rm', '--network', 'none', '-i', process.env.PASSWALL_UCI_DOCKER, '/bin/sh'], {input: fixture, stdio: ['pipe','inherit','inherit']});
} else if (process.env.PASSWALL_UCI_LOCAL) {
  cp.execFileSync('/bin/sh', ['-s'], {input: fixture, stdio: ['pipe','inherit','inherit']});
} else {
  console.log('SKIP real UCI (set PASSWALL_UCI_DOCKER or PASSWALL_UCI_LOCAL)');
}
const app = read('luci-app-passwall/root/usr/share/passwall/app.sh');
const helper = app.slice(app.indexOf('gen_ss_config() {'), app.indexOf('run_socks() {'));
const branches = [...app.matchAll(/\n\tss\)\n([\s\S]*?)\n\t;;/g)];
if (branches.length !== 2) throw Error('Expected ss-local and ss-redir branches');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
for (const branch of branches) {
  cp.execFileSync(bash, ['-s'], {input: `
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
UTIL_SS=real-util
${helper}
echolog() { printf '%s' "$*" > "$work/error"; }
lua() { if [ "$fail" = 1 ]; then echo 'Shadowsocks-libev: unsupported or missing method: none' >&2; return 1; fi; printf '%s\\n' "$3"; }
json_dump() { printf '{"mode":"%s"}' "$ss_mode"; }
json_add_string() { [ "$1" != mode ] || ss_mode=$2; return 0; }
first_type() { echo "$1"; }
ln_run() { echo started >> "$work/started"; printf '%s\\n' "$@" > "$work/argv"; }
start_node() {
  ${branch[1]}
}
config_file="$work/config.json"
bind=127.0.0.1; socks_port=1080; REDIR_PORT=1041; TCP_PROXY_WAY=tproxy; log_file=/dev/null; no_run=
fail=1
if start_node; then echo 'ERROR: invalid SS config was accepted'; exit 1; fi
[ ! -e "$work/started" ] && [ ! -e "$config_file" ]
grep -q 'unsupported or missing method' "$work/error"
fail=0
start_node
[ -s "$work/started" ] && [ -s "$config_file" ]
grep -q '"mode":"tcp_and_udp"' "$config_file"
grep -qx -- '-c' "$work/argv"
! grep -Eq -- '^-(u|U)$' "$work/argv"
echo 'PASS real SS startup branch: generation failure returns nonzero and prevents launch; valid config launches'
`, stdio: ['pipe','inherit','inherit']});
}
