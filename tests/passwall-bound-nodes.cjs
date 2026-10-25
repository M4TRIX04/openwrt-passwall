// Native UCI/nixio, actual Hysteria v1.3.5/SS-libev/ipt2socks in a private PID/net namespace.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
function func(s,n){const start=s.indexOf('\n'+n+'() {')+1;assert(start>0,n);const rest=s.slice(start),end=rest.search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) \{/);return end<0?rest:rest.slice(0,end);}
const utils=read('luci-app-passwall/root/usr/share/passwall/utils.sh'),app=read('luci-app-passwall/root/usr/share/passwall/app.sh');
const helpers=['shell_quote','del_cache_var','set_cache_var','set_cache_vars','get_cache_var','get_new_port','check_port_exists','get_process_start_time'].map(n=>func(utils,n)).join('\n')+'\n'+['check_node_supported','gen_ss_config','gen_hysteria_config','start_hysteria'].map(n=>func(app,n)).join('\n');
for(const p of ['app.sh','nftables.sh','iptables.sh'])assert(!/bound_nodes|runtime_binding|passwall_start_bound/.test(read('luci-app-passwall/root/usr/share/passwall/'+p)),p);
let script=read('tests/shell-bound-nodes.sh').replace('# PRODUCTION_HELPERS',()=>helpers);
const b1=process.env.PASSWALL_BOUND_B1;
if(b1){
 assert(['empty_birth','stop_owner'].includes(b1),'unknown B1 group');
 let argument='';
 if(b1==='empty_birth'){
  const scenario=process.env.PASSWALL_BOUND_B1_CASE;
  assert(['global-live','global-exited','global-stat-eacces','global-truncated','global-illegal-pid','global-invalid-birth','global-mismatch','global-idempotent','global-unsealed-eacces','global-unsealed-eio','rollback-unsealed-exited','rollback-sealed-exited','acl-main-live','acl-main-exited','acl-relay-live','acl-relay-eacces','acl-relay-eio','acl-main-mismatch','acl-relay-mismatch','acl-idempotent'].includes(scenario),'unknown D1-A scenario');
  assert(process.env.PASSWALL_BOUND_CONTAINER,'D1-A requires a prepared isolated container');
  argument=' '+scenario; // Literal whitelist only; passed explicitly into ash input.
 }
 if(b1==='stop_owner'){
  const scenario=process.env.PASSWALL_BOUND_B1_CASE;
  assert(['global-sealed-eio','global-sealed-stat-damaged','acl-main-sealed-eacces','acl-main-sealed-eio','acl-main-sealed-stat-damaged','identity-missing-live','identity-missing-exited','acl-identity-missing-exited','identity-corrupt','seal-pid','seal-node','binding-gid','binding-config-md5','seal-config-md5','endpoint-port','command-invalid','command-incomplete','directory-invalid','cross-root','noncanonical','symlink','snapshot-invalid','metadata-node','seal-generation','birth-number','birth-invalid','birth-changed-empty','birth-changed-normal'].includes(scenario),'unknown D1-C scenario');
  assert(process.env.PASSWALL_BOUND_CONTAINER,'D1-C requires a prepared isolated container');
  argument=' '+scenario;
 }
 script=script.split('# Real servers;')[0]+'\n'+read('tests/shell-bound-b1.sh')+'\nb1_'+b1+argument+'\n';
}
const container=process.env.PASSWALL_BOUND_CONTAINER;
if(container){
 assert(/^[a-f0-9]{64}$/.test(container));
 try {cp.execFileSync('docker',['exec','-i',container,'/bin/ash'],{input:script,stdio:['pipe','inherit','inherit']});}
 catch(error){if(!['empty_birth','stop_owner'].includes(b1)||error.status!==10)throw error;process.exitCode=10;}
}
else {
 const image=process.env.PASSWALL_BOUND_DOCKER;assert(image,'Set PASSWALL_BOUND_DOCKER (Alpine image) or PASSWALL_BOUND_CONTAINER (prepared isolated lab)');
 const setup=read('tests/prepare-bound-native.sh');
 cp.execFileSync('docker',['run','--rm','--init','--pull=never','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','SYS_PTRACE','--mount',`type=bind,source=${root},target=/workspace,readonly`,'-i','--entrypoint','/bin/ash',image],{input:setup+'\n'+script,stdio:['pipe','inherit','inherit']});
}
if(b1==='stop_owner')console.log('D1-C driver completed; see D1C_RESULT (exit 10 means behavior FAIL).');
else if(b1==='empty_birth')console.log('D1-A driver completed; production verdict is in D1A_RESULT (exit 10 means behavior FAIL).');
else console.log('PASS inactive bound runtime: actual binaries and live kernel evidence; no production startup/hook/migration');
