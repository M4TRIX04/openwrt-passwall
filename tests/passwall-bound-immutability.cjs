// Native, inactive B3.3-3C-1A regression. Reuse the existing bound fixture.
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
for (const p of ['app.sh', 'nftables.sh', 'iptables.sh']) {
  assert(!/bound_nodes|runtime_binding|passwall_start_bound|_pw_bound_reference/.test(read('luci-app-passwall/root/usr/share/passwall/' + p)), p);
}
assert(!/bound_nodes|runtime_binding|passwall_start_bound|_pw_bound_reference/.test(read('luci-app-passwall/root/etc/init.d/passwall')));
console.log('PASS static: no production bound/reference entry');
const helpers = ['shell_quote', 'del_cache_var', 'set_cache_var', 'set_cache_vars', 'get_cache_var',
  'get_new_port', 'check_port_exists', 'get_process_start_time'].map(n => func(utils, n)).join('\n') + '\n' +
  ['check_node_supported', 'gen_ss_config', 'gen_hysteria_config', 'start_hysteria'].map(n => func(app, n)).join('\n');
const script = read('tests/shell-bound-nodes.sh').split('# Real servers;')[0]
  .replace('# PRODUCTION_HELPERS', () => helpers) + '\n' + read('tests/shell-bound-immutability.sh');
const docker = (args, opts = {}) => cp.execFileSync('docker', args, {encoding: 'utf8', ...opts});
let container = process.env.PASSWALL_BOUND_CONTAINER, own = false;
try {
  if (!container && process.env.PASSWALL_BOUND_DOCKER) {
    container = docker(['run', '-d', '--rm', '--init', '--pull=never', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
      '--cap-add', 'SYS_PTRACE', '--mount', `type=bind,source=${root},target=/workspace,readonly`,
      '--entrypoint', '/bin/ash', process.env.PASSWALL_BOUND_DOCKER, '-c', 'sleep 3600']).trim();
    own = true;
  }
  if (!container) {
    console.log('SKIP native immutability: set PASSWALL_BOUND_DOCKER or task-owned PASSWALL_BOUND_CONTAINER');
  } else {
    assert(/^[a-f0-9]{64}$/.test(container), 'full task-owned container ID required');
    const info = JSON.parse(docker(['inspect', container]))[0];
    assert(!['host', 'container'].some(x => info.HostConfig.NetworkMode.startsWith(x)));
    assert(!info.HostConfig.PidMode && !info.HostConfig.Privileged);
    assert(info.Mounts.length === 1 && info.Mounts[0].Destination === '/workspace' && !info.Mounts[0].RW);
    if (own) docker(['exec', '-i', container, '/bin/ash'], {input: read('tests/prepare-bound-native.sh'), stdio: ['pipe', 'inherit', 'inherit']});
    docker(['exec', '-i', container, '/bin/ash'], {input: script, stdio: ['pipe', 'inherit', 'inherit']});
    console.log('PASS native immutable publication; data forwarding/DNS/production integration NOT tested');
  }
} finally {
  if (own && container) docker(['rm', '-f', container], {stdio: 'ignore'});
}
