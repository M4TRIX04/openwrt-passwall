// Real UCI and production preparation function, in private temporary directories.
// PASSWALL_UCI_DOCKER=openwrt/rootfs:x86-64 node tests/passwall-split-node-migration.cjs
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8').replace(/\r\n/g, '\n');
const helper = read('tools/migrations/passwall-split-nodes.sh');
const fixture = read('tests/uci-split-nodes.sh').replace('# MIGRATION_FUNCTION', helper);
// Preparation must remain outside the package, without an installation/runtime call.
function checkUnused(dir) {
  for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
    const name = path.join(dir, entry.name);
    if (entry.isDirectory()) checkUnused(name);
    else assert(!fs.readFileSync(name, 'utf8').includes('passwall_split_nodes_migrate'), name);
  }
}
checkUnused(path.join(root, 'luci-app-passwall/root'));
checkUnused(path.join(root, 'luci-app-passwall/luasrc'));
console.log('PASS split-node migration is not connected to installation or runtime');
if (process.env.PASSWALL_UCI_DOCKER) {
  cp.execFileSync('docker', ['run', '--rm', '--pull=never', '--network', 'none', '-i',
    '--entrypoint', '/bin/ash', process.env.PASSWALL_UCI_DOCKER],
  {input: fixture, stdio: ['pipe', 'inherit', 'inherit']});
} else if (process.env.PASSWALL_UCI_LOCAL) {
  cp.execFileSync('/bin/sh', ['-s'], {input: fixture, stdio: ['pipe', 'inherit', 'inherit']});
} else {
  console.log('SKIP real UCI migration tests (set PASSWALL_UCI_DOCKER or PASSWALL_UCI_LOCAL)');
}
