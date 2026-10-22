// B3.3-3B native tests. Only a disposable private container is mutated.
// Set PASSWALL_DEP_DOCKER to an existing Alpine image for a complete run.
// PASSWALL_DEP_CONTAINER may name a task-owned prepared isolated lab; caller
// owns its cleanup. Never point this at a router/production container.
const fs = require('node:fs'), path = require('node:path');
const cp = require('node:child_process'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8').replace(/\r\n/g, '\n');
function func(s, n) {
  const start = s.indexOf('\n' + n + '() {') + 1;
  assert(start > 0, n);
  const tail = s.slice(start), end = tail.search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);
  return end < 0 ? tail : tail.slice(0, end);
}
const utils = read('luci-app-passwall/root/usr/share/passwall/utils.sh');
const app = read('luci-app-passwall/root/usr/share/passwall/app.sh');
const contract = read('docs/passwall-b3.3-3-dependency-contract.md');
for (const p of ['luci-app-passwall/root/usr/share/passwall/dns_dependency.sh',
  'luci-app-passwall/luasrc/passwall/dependency_probe.lua']) {
  const source = read(p);
  assert(!/\bdns_dep_(ok|not_required|config_invalid)\b/.test(source), '3B must not export success/error aliases or the 3C config gate: ' + p);
  for (const [reason] of source.matchAll(/\bdns_dep_[a-z]+(?:_[a-z]+)*\b/g)) {
    assert(contract.includes('`' + reason + '`'), 'undocumented dependency reason: ' + reason);
  }
}
const helpers = ['shell_quote', 'del_cache_var', 'set_cache_var', 'set_cache_vars', 'get_cache_var',
  'get_new_port', 'check_port_exists', 'get_process_start_time'].map(n => func(utils, n)).join('\n') + '\n' +
  ['check_node_supported', 'gen_ss_config', 'gen_hysteria_config', 'start_hysteria'].map(n => func(app, n)).join('\n');
for (const p of ['app.sh', 'nftables.sh', 'iptables.sh', 'split_firewall.sh']) {
  assert(!/dns_dependency|dependency_probe|passwall_validate_dns_dependency/.test(read('luci-app-passwall/root/usr/share/passwall/' + p)), p);
}
const fixture = read('tests/shell-bound-nodes.sh').split('# Real servers;')[0]
  .replace('# PRODUCTION_HELPERS', () => helpers)
  .replace('config_n_get() {', 'config_n_get() {\n [ "${PW_DEP_TEST_ACTIVE:-0}" != 1 ] || { echo live-read >> "$work/live-read"; return 1; }');
const test = fixture + '\n' + read('tests/shell-dns-dependency.sh');
let container = process.env.PASSWALL_DEP_CONTAINER, own = false;
const docker = (args, options = {}) => cp.execFileSync('docker', args, {encoding: 'utf8', ...options});
try {
  if (!container) {
    const image = process.env.PASSWALL_DEP_DOCKER;
    if (!image) {
      console.log('SKIP native DNS dependency: set PASSWALL_DEP_DOCKER or task-owned PASSWALL_DEP_CONTAINER');
      process.exitCode = 0;
    } else {
      container = docker(['run', '-d', '--rm', '--init', '--pull=never', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
        '--cap-add', 'SYS_PTRACE', '--mount', `type=bind,source=${root},target=/workspace,readonly`,
        '--entrypoint', '/bin/ash', image, '-c', 'sleep 3600']).trim();
      own = true;
    }
  }
  if (container) {
    assert(/^[a-f0-9]{64}$/.test(container), 'full task-owned container ID required');
    const info = JSON.parse(docker(['inspect', container]))[0];
    assert(!['host', 'container'].some(x => info.HostConfig.NetworkMode.startsWith(x)));
    assert(!info.HostConfig.PidMode && !info.HostConfig.Privileged);
    assert(info.Mounts.length === 1 && info.Mounts[0].Destination === '/workspace' && !info.Mounts[0].RW);
    if (own) docker(['exec', '-i', container, '/bin/ash'], {input: read('tests/prepare-bound-native.sh') + '\n', stdio: ['pipe', 'inherit', 'inherit']});
    docker(['exec', '-i', container, '/bin/ash'], {input: test, stdio: ['pipe', 'inherit', 'inherit']});
    console.log('PASS B3.3-3B native candidates; outer/DNS/helper/production integration NOT tested');
  }
} finally {
  if (own && container) docker(['rm', '-f', container], {stdio: 'ignore'});
}
