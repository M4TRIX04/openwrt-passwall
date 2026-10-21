// Real B1/B2/B3.1 startup/cache/listener checks + B3.2 rendering/lifecycle.
// nft/xtables commands are a file-backed fixture; no kernel firewall is changed.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict'),Module=require('node:module');
const root=path.resolve(__dirname,'..'),read=p=>fs.readFileSync(path.join(root,p),'utf8').replace(/\r\n/g,'\n');
const image=process.env.PASSWALL_FW_DOCKER;
assert(image,'Set PASSWALL_FW_DOCKER to an existing Alpine image for native Lua/ash tests');
for(const p of ['app.sh','nftables.sh','iptables.sh'])assert(!/split_firewall\.sh|passwall_fw_/.test(read('luci-app-passwall/root/usr/share/passwall/'+p)),p);
process.env.PASSWALL_B3_DOCKER=image;
const file=path.join(__dirname,'passwall-acl-nodes.cjs'),m=new Module(file,module);m.filename=file;m.paths=module.paths;
m._compile(fs.readFileSync(file,'utf8').split('script+=setup.replace')[0]+'\nmodule.exports={script,setup,helpers,func,utils};',file);
let {script,setup,helpers}=m.exports;
// Preserve production's 100ms nanosleep in this larger native lifecycle matrix;
// B2's 10ms acceleration is not the production stop timeout.
script=script.replace("nanosleep=function() call('sleep 0.01') end","nanosleep=function() call('sleep 0.1') end");
script+="cat > /tmp/fw-cache-get.sh <<'__FW_GET__'\n"+m.exports.func(m.exports.utils,'get_cache_var')+'\n__FW_GET__\n';
let idx=100;
for(const [dest,src] of Object.entries({'/tmp/split_firewall.sh':'luci-app-passwall/root/usr/share/passwall/split_firewall.sh','/tmp/firewall_endpoint.lua':'luci-app-passwall/luasrc/passwall/firewall_endpoint.lua','/tmp/firewall-fixture.lua':'tests/firewall-fixture.lua'})){
 const end='__FW_FILE_'+idx+++'__';script+="cat > "+dest+" <<'"+end+"'\n"+read(src)+'\n'+end+'\n';
}
script+=setup.replace('# PRODUCTION_HELPERS',()=>helpers)+read('tests/shell-acl-nodes.sh').split('[ -z "${PW_B3_TRACE:-}" ] || set -x')[0]+
 m.exports.func(m.exports.utils,'get_new_port').replace('get_new_port()','fixture_get_new_port()')+'\n'+read('tests/shell-split-firewall.sh');
// An init reaper supplies the PID1 role for native test children, instead of
// relying on ash's incidental orphan-reaping behavior.
const result=cp.spawnSync('docker',['run','--rm','--init','--pull=never','--cap-add','SYS_PTRACE','-i','--entrypoint','/bin/ash',image],{input:script,encoding:'utf8',maxBuffer:24*1024*1024});
process.stderr.write(result.stderr||'');
if(result.status!==0){process.stdout.write((result.stdout||'').split('\n').filter(s=>!s.startsWith('FW_CASE ')).join('\n'));assert.equal(result.status,0,'native firewall test failed');}
const cases=result.stdout.split('\n').filter(s=>s.startsWith('FW_CASE ')).map(s=>JSON.parse(s.slice(8)));
// Interpret actual backend rules, independently of production rendering. Packets
// traverse mangle, then IPv4 nat; RETURN pops the virtual call stack.
// This models new-flow rule evaluation, not existing conntrack NAT mappings.
function evaluate(c,input,output=false,link="dispatcher",traces=[]){
 const p={...input};
 const f=p.family||4,base=f+'/';let marked=false;
 function inSet(set,dir){return (p[dir+'Sets']||[]).includes(set);}
 function address(s){if(s.includes(':')){const a=s.split('::'),l=a[0]?a[0].split(':'):[],r=a[1]?a[1].split(':'):[];return [...l,...Array(8-l.length-r.length).fill('0'),...r].reduce((v,n)=>(v<<16n)+BigInt('0x'+n),0n);}return s.split('.').reduce((v,n)=>(v<<8n)+BigInt(n),0n);}
 function inAddress(value,s){if(s.includes('-')){const [a,b]=s.split('-');return address(value)>=address(a)&&address(value)<=address(b);}const [a,bits]=s.split('/');if(bits===undefined)return a===value;const shift=BigInt((value.includes(':')?128:32)-Number(bits));return address(value)>>shift===address(a)>>shift;}
 function interval(value,s){const [a,b=a]=s.split(/[:-]/).map(Number);return value>=a&&value<=b;}
 function run(table,chain,depth=0){
  assert(depth<16,'recursive test chain');traces.push('enter '+table+'/'+chain);
  for(const r of c.chains[base+table+'/'+chain]||[]){
   let x;
   if((x=r.match(/(?:meta l4proto |^-p )(tcp|udp)/))&&x[1]!==p.proto)continue;
   if((x=r.match(/meta nfproto ipv([46])/))&&+x[1]!==f)continue;
   if((x=r.match(/(?:ip6? saddr | -s )([\da-fA-F:.]+(?:\/\d+|-[\da-fA-F:.]+)?)(?= |$)/))&&!inAddress(p.source,x[1]))continue;
   if((x=r.match(/--src-range ([\d.-]+)/))&&!inAddress(p.source,x[1]))continue;
   if((x=r.match(/(?:daddr | -d )([\da-fA-F:.]+)(?= |$)/))&&x[1]!==p.dest)continue;
   if((x=r.match(/(?:ether saddr |--mac-source )([\da-fA-F:]+)/))&&x[1]!==p.mac)continue;
   if((x=r.match(/(?:iifname "| -i )([\w.-]+)/))&&x[1]!==p.iif)continue;
   if((r.includes('oifname "lo"')||r.includes('-o lo'))&&p.oif!=='lo')continue;
   if((x=r.match(/(?:ip6? saddr @)(\w+)/))&&!inSet(x[1],'source'))continue;
   if((x=r.match(/(?:ip6? daddr @)(\w+)/))&&!inSet(x[1],'dest'))continue;
   if((x=r.match(/--match-set (\w+) (src|dst)/))&&!inSet(x[1],x[2]==='src'?'source':'dest'))continue;
   if((x=r.match(/(?:dport |--dport )([\d:-]+)/))&&!interval(p.port,x[1]))continue;
   if((r.includes('ct direction reply')||r.includes('--ctdir REPLY'))&&!p.reply)continue;
   if((r.includes('meta mark & 0xff')||r.includes('--mark 0xff/0xff'))&&p.mark!==255)continue;
   if((r.includes('meta mark 0x50535731')||r.includes('--mark 0x50535731'))&&p.mark!==0x50535731)continue;
   traces.push('hit '+table+'/'+chain+' '+r);
   const branch=r.match(/(?:\b(jump|goto) |-(j|g) )([A-Za-z0-9_]+)/);
   if(branch&&c.chains[base+table+'/'+branch[3]]){
    const verdict=run(table,branch[3],depth+1);
    if(verdict.action!=='return')return verdict;
    if(branch[1]==='goto'||branch[2]==='g')return verdict;
    continue;
   }
   if(r.includes('set-xmark')||r.includes('meta mark set')){marked=true;p.mark=0x50535731;}
   if(/(?:tproxy ip6? to :|--on-port )/.test(r)){
    if(p.noSocket){if(c.backend==='nft'){traces.push('NFT_BREAK: no transparent socket');continue;}return {action:'drop'};}
    return {action:'proxy',port:+r.match(/(?:to :|--on-port )(\d+)/)[1]};
   }
   if(/(?:redirect to :|--to-ports )/.test(r))return {action:'proxy',port:+r.match(/(?:to :|--to-ports )(\d+)/)[1]};
   if(/(?:counter drop|-j DROP)/.test(r))return {action:'drop'};
   if(/(?:counter return|-j RETURN)/.test(r))return {action:'return'};
   if(/(?: accept$|-j ACCEPT)/.test(r))return marked?{action:'mark'}:{action:'accept'};
  }
  return {action:'return'};
 }
 const entry=(table,letter)=>{
  const own=c.token+letter+f;
  if(link==='dispatcher')return own;
  const mode=typeof link==='object'?link[table]:link;
  const parent='PARENT_'+table;
  const nft=c.backend==='nft';
  const wrapper='WRAPPER_'+table;
  if(mode==='nested-goto')c.chains[base+table+'/'+wrapper]=[nft?'goto '+own:'-g '+own];
  const target=mode==='nested-goto'?wrapper:own,branch=mode==='nested-goto'?'jump':mode;
  const nf=f===4?'ip':'ip6';
  const tail=table==='nat'?(nft?'meta l4proto tcp counter redirect to :19999':'-p tcp -j REDIRECT --to-ports 19999'):
   output?(nft?'counter meta mark set 0x50535731 accept':'-j MARK --set-xmark 0x50535731/0xffffffff'):
   nft?'counter meta mark set 0x50535731 tproxy '+nf+' to :19999 accept':'-j TPROXY --on-port 19999 --tproxy-mark 0x50535731/0xffffffff';
  c.chains[base+table+'/'+parent]=nft?[branch+' '+target,tail]:['-'+(branch==='goto'?'g':'j')+' '+target,tail];
  return parent;
 };
 const a=run('mangle',entry('mangle',output?'O':'P'));
 if(a.action==='drop')return a;
 // ACCEPT in mangle does not skip subsequent nat/other base chains.
 const b=f===4?run('nat',entry('nat',output?'R':'N')):{action:'return'};
 if(b.action==='drop'||b.action==='proxy')return b;
 if(typeof link==='object'&&link.laterChain){const later=run('filter',link.laterChain);if(later.action==='drop')return later;}
 return a.action==='return'||a.action==='accept'?{action:'direct'}:a;
}
function packet(proto,source='10.1.0.2',family=4){return {proto,source,family,dest:family===4?'203.0.113.9':'2001:db8::9',port:8080};}
function check(c,p,expected,output=false){assert.deepEqual(evaluate(c,p,output),expected,c.name+' '+JSON.stringify(p));}
assert(cases.length>20,'missing native matrix');
for(const c of cases){
 assert.deepEqual(c.chains['4/mangle/PSW_DNS'],['KEEP DNS SRV KMS']);
 assert.deepEqual(c.chains['4/nat/PSW'],['KEEP LEGACY']);
 if(c.name==='mixed'){
  check(c,packet('tcp'),{action:'proxy',port:12001});check(c,packet('udp'),{action:'direct'});
  check(c,packet('tcp','10.1.0.3'),{action:'drop'});check(c,packet('udp','10.1.0.3'),{action:'proxy',port:12002});
  check(c,packet('tcp','10.1.0.4'),{action:'proxy',port:12003});check(c,packet('udp','10.1.0.4'),{action:'proxy',port:12003});
  check(c,packet('tcp','10.1.0.5'),{action:'direct'});check(c,packet('udp','10.1.0.5'),{action:'direct'});
  check(c,packet('tcp','10.1.0.6'),{action:'proxy',port:1041});
  check(c,packet('udp','10.1.0.6'),{action:'proxy',port:1051});
  check(c,{...packet('tcp'),dest:'192.168.1.1',destSets:['psw_local','psw_lan'],port:53},{action:'direct'});
  check(c,{...packet('tcp','10.1.0.8'),dest:'192.0.2.3',port:443},{action:'direct'},true);
  check(c,packet('udp','10.1.0.8'),{action:'mark'},true);
  check(c,{...packet('udp'),iif:'lo',mark:0x50535731},{action:'proxy',port:1051});
  if(c.ipv6==='1')check(c,packet('tcp','2001:db8:1::1',6),{action:'proxy',port:1041});
 } else if(/^state-/.test(c.name)){
  const [,tcp,udp]=c.name.split('-');
  for(const [p,s,port] of [['tcp',tcp,1041],['udp',udp,1051]])check(c,packet(p),s==='ready'?{action:'proxy',port}:s==='failed'?{action:'drop'}:{action:'direct'});
 } else if(c.name.startsWith('combo-')){
  const [,tcp,udp]=c.name.split('-');check(c,packet('tcp'),{action:'proxy',port:1041});check(c,packet('udp'),{action:'proxy',port:udp==='tcp'||udp===tcp?1041:1051});
 } else if(c.name==='inherit'){
  check(c,packet('tcp'),{action:'proxy',port:1041});check(c,packet('udp'),{action:'drop'});check(c,packet('udp','10.1.0.8'),{action:'direct'});
 } else if(c.name==='families'){
  for(const p of ['tcp','udp']){
   check(c,packet(p),{action:'proxy',port:12001});check(c,packet(p,'2001:db8:1::2',6),{action:'proxy',port:12001});
   check(c,packet(p,'10.1.0.3'),{action:'drop'});check(c,packet(p,'2001:db8:1::3',6),{action:'proxy',port:12002});
  }
  check(c,packet('tcp','10.1.0.8'),{action:'proxy',port:1041});check(c,packet('udp','10.1.0.8'),{action:'drop'});
  check(c,packet('tcp','2001:db8::8',6),{action:'drop'});check(c,packet('udp','2001:db8::8',6),{action:'proxy',port:1051});
 } else if(c.name==='policy'){
  for(const proto of ['tcp','udp']){
   const base=packet(proto),port=proto==='tcp'?1041:1051;
   check(c,{...base,port:22,destSets:['psw_block']},{action:'direct'});
   check(c,{...base,port:80,destSets:['psw_block']},{action:'drop'});
   check(c,{...base,port:80,destSets:['psw_white','psw_black']},{action:'direct'});
   check(c,{...base,port:80,destSets:['psw_black']},{action:'proxy',port});
   check(c,{...base,port:443,destSets:['psw_black']},{action:'drop'});
   check(c,{...base,port:80,destSets:['psw_gfw']},{action:'proxy',port});
   check(c,{...base,port:80,destSets:['psw_chn']},{action:'direct'});
   check(c,{...base,port:80},{action:'direct'});
  }
 } else if(c.name==='sources'){
  check(c,{...packet('tcp'),mac:'00:11:22:33:44:55',iif:'br-lan'},{action:'direct'});
  check(c,{...packet('tcp'),mac:'00:11:22:33:44:55',iif:'other'},{action:'proxy',port:1041});
  check(c,{...packet('tcp'),sourceSets:['devices']},{action:'direct'});
  check(c,packet('tcp','10.2.0.5'),{action:'direct'});check(c,packet('tcp','10.2.0.10'),{action:'proxy',port:1041});
  check(c,packet('udp','2001:db8:1::2',6),{action:'direct'});check(c,packet('udp','2001:db8:1::9',6),{action:'proxy',port:1051});
 } else if(c.name.startsWith('remote-')){
  const node=c.name.slice(7),dest=node==='ss6'?'2001:db8::123':node==='ssdns'?'2001:db8::10':'192.0.2.3';
  const family=node==='hyvideo'?4:6,proto=node==='hyvideo'?'udp':'tcp',port=node==='hyvideo'?443:8388;
  check(c,{...packet(proto,'10.1.0.8',family),dest,port},{action:'direct'},true);
  check(c,{...packet(proto,'10.1.0.8',family),dest,port},family===6||node==='hyvideo'?{action:'direct'}:{action:'proxy',port:1041});
  if(node==='hyvideo')check(c,{...packet('tcp'),dest,port},{action:'proxy',port:1041},false);
 } else if(c.name.startsWith('outer-conflict-')){
  const tcp=c.name.includes('ssbad-hyfake')?'failed':'ready';
  check(c,packet('tcp'),tcp==='ready'?{action:'proxy',port:1041}:{action:'drop'});
  check(c,packet('udp'),tcp==='ready'?{action:'drop'}:{action:'proxy',port:1051});
 } else if(c.name==='router-only'){
  for(const proto of ['tcp','udp']){
   check(c,packet(proto),{action:'direct'});
   check(c,packet(proto),{action:'mark'},true);
   check(c,{...packet(proto),iif:'lo',mark:0x50535731},{action:'proxy',port:proto==='tcp'?1041:1051});
  }
 } else if(c.name==='retry'||c.name==='other'){
  check(c,packet('tcp'),{action:'proxy',port:1041});check(c,packet('udp'),{action:'proxy',port:1051});
 } else assert.fail('unvalidated snapshot '+c.name);
}
// Parent tail is deliberately hostile: closed must escape it through goto;
// jump demonstrably resumes the old global rule. No production hook is added.
for(const c of cases.filter(c=>c.name==='mixed')){
 for(const p of [packet('udp'),packet('tcp','10.1.0.5'),packet('udp','10.1.0.5')]){
  const trace=[];assert.deepEqual(evaluate(c,p,false,'goto',trace),{action:'direct'});
  assert(!trace.some(x=>x.includes('19999')),'closed reached parent tail');
  assert.deepEqual(evaluate(c,p,false,'jump'),{action:'proxy',port:19999});
  assert.deepEqual(evaluate(c,p,false,'nested-goto'),{action:'proxy',port:19999});
 }
 // Failure isolation must also hold for the other ready node's remote tuple.
 assert.deepEqual(evaluate(c,{...packet('tcp','10.1.0.3'),dest:'192.0.2.3',port:443},false,'goto'),{action:'drop'});
 for(const proto of ['tcp','udp']){
  const p=packet(proto,'10.1.0.3');
  for(const [port,sets] of [[53,['psw_local']],[1688,['psw_lan']],[22,['psw_local']],[445,['psw_lan']]]){
   for(const output of [false,true]){
    const trace=[];assert.deepEqual(evaluate(c,{...p,port,destSets:sets},output,'goto',trace),{action:'direct'});
    assert(!trace.some(x=>/counter drop|-j DROP|19999/.test(x)));
   }
  }
  assert.deepEqual(evaluate(c,{...p,port:53,dest:'8.8.8.8'},false,'goto'),proto==='tcp'?{action:'drop'}:{action:'proxy',port:12002});
  assert.deepEqual(evaluate(c,packet(proto,'10.1.0.6'),false,'goto'),{action:'proxy',port:proto==='tcp'?1041:1051});
 }
 const trace=[];
 assert.deepEqual(evaluate(c,{...packet('udp','10.1.0.3'),noSocket:true},false,'goto',trace),{action:'drop'});
 if(c.backend==='nft')assert(trace.some(x=>x.includes('NFT_BREAK')));
 assert.deepEqual(evaluate(c,packet('udp'),true,'goto'),{action:'mark'});
 assert.deepEqual(evaluate(c,{...packet('udp'),iif:'lo',mark:0x50535731},false,'goto'),{action:'proxy',port:1051});
 assert.deepEqual(evaluate(c,{...packet('udp'),iif:'lo',mark:0x50535731,noSocket:true},false,'goto'),{action:'drop'});
 // mangle acceptance alone cannot protect against a stale nat parent rule.
 if(c.way==='tproxy')assert.deepEqual(evaluate(c,packet('tcp','10.1.0.4'),false,{mangle:'goto',nat:'jump'}),{action:'proxy',port:19999});
 c.chains['4/filter/LATER']=[c.backend==='nft'?'counter drop':'-j DROP'];
 assert.deepEqual(evaluate(c,packet('udp'),false,{mangle:'goto',nat:'goto',laterChain:'LATER'}),{action:'drop'});
}
for(const c of cases.filter(c=>c.name==='families')){
 for(const proto of ['tcp','udp']){
  assert.deepEqual(evaluate(c,packet(proto,'2001:db8:1::2',6),false,'goto'),{action:'proxy',port:12001});
  assert.deepEqual(evaluate(c,{...packet(proto,'2001:db8:1::2',6),noSocket:true},false,'goto'),{action:'drop'});
  const trace=[];assert.deepEqual(evaluate(c,packet('tcp','2001:db8:1::3',6),false,'goto',trace),{action:'proxy',port:12002});
  assert(!trace.some(x=>x.includes('19999')));
 }
}
console.log('PASS full parent/goto/jump and subsequent nat packet paths');
console.log('PASS native B3.2 production functions: '+cases.length+' installed snapshots; nft/iptables semantic matrix, owned cleanup and legacy DNS preservation');
