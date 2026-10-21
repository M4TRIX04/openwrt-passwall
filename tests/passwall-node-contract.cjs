// B1: real, inactive resolver + existing production cache/port functions.
// Cache bindings below are contract fixtures, NOT an implemented B2 launcher.
// PASSWALL_CONTRACT_DOCKER=openwrt/rootfs:x86-64 node tests/passwall-node-contract.cjs
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8').replace(/\r\n/g, '\n');
const helperPath = 'luci-app-passwall/root/usr/share/passwall/node_config.sh';
const helper = read(helperPath);
const utils = read('luci-app-passwall/root/usr/share/passwall/utils.sh');
function func(name) {
  const start = utils.indexOf('\n' + name + '() {') + 1;
  assert(start > 0, name);
  const rest = utils.slice(start);
  const end = rest.search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);
  return end < 0 ? rest : rest.slice(0, end);
}
// The only packaged reference is the definition file itself. No activation.
function checkUnused(dir) {
  for (const entry of fs.readdirSync(path.join(root, dir), {withFileTypes: true})) {
    const p = dir + '/' + entry.name;
    if (entry.isDirectory()) checkUnused(p);
    else if (p !== helperPath && !['global_nodes.sh', 'acl_nodes.sh'].some(n => p === 'luci-app-passwall/root/usr/share/passwall/' + n)) {
      const text = read(p);
      assert(!/passwall_resolve_(?:acl_)?node_pair|node_config\.sh/.test(text), p);
    }
  }
}
checkUnused('luci-app-passwall/root');
checkUnused('luci-app-passwall/luasrc');
assert(!/\b(?:uci|set_cache_vars|get_cache_var|ln_run)\s/.test(helper), 'resolver must stay pure');
const cache = ['shell_quote', 'del_cache_var', 'set_cache_var', 'set_cache_vars',
  'get_cache_var', 'get_new_port', 'check_port_exists'].map(func).join('\n');
const fixture = read('tests/shell-node-contract.sh')
  .replace('# PRODUCTION_RESOLVER', helper).replace('# PRODUCTION_CACHE', cache);
const image = process.env.PASSWALL_CONTRACT_DOCKER;
if (image) {
  cp.execFileSync('docker', ['run', '--rm', '--pull=never', '--network', 'none', '-i',
    '--entrypoint', '/bin/ash', image], {input: fixture, stdio: ['pipe', 'inherit', 'inherit']});
} else {
  const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
  cp.execFileSync(bash, ['-s'], {input: fixture, stdio: ['pipe', 'inherit', 'inherit']});
}
console.log('PASS B1 resolver not connected to runtime; ' + (image ? 'OpenWrt BusyBox ash' : 'bash (not BusyBox)'));
