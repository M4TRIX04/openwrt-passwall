// Execute both production probe functions and their shared cleanup helper.
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const dir=path.resolve(__dirname,'../luci-app-passwall/root/usr/share/passwall');
const read=n=>fs.readFileSync(path.join(dir,n),'utf8').replace(/\r\n/g,'\n');
function func(s,n){const a=s.indexOf('\n'+n+'() ')+1;if(!a)throw Error(n);const b=s.slice(a).search(/\n[A-Za-z_][A-Za-z_0-9]*\(\) /);return b<0?s.slice(a):s.slice(a,a+b)}
const helper=func(read('utils.sh'),'cleanup_hysteria_probe');
const auto=func(read('socks_auto_switch.sh'),'test_node');
const test=read('test.sh');const url=test.slice(test.indexOf('url_test_node() ('),test.indexOf('\narg1='));
const image=process.env.PASSWALL_PROBE_DOCKER;
const bash=image?'docker':(process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/bin/bash');
const args=image?['run','--rm','-i','--network','none','--entrypoint','/bin/ash',image,'-s']:['-s'];
for(const [name,body,invoke] of [['auto',auto,'test_node n'],['url',url.replace(/\/usr\/share\/\$\{CONFIG\}\/app.sh/g,'"$APP_FILE"'),'url_test_node n']]){
 cp.execFileSync(bash,args,{stdio:['pipe','inherit','inherit'],input:`
work=$(mktemp -d);trap 'rm -rf "$work"' EXIT
TMP_PATH="$work";LOCK_PATH="$work";CONFIG=passwall;APP_FILE="$work/app.sh";id=one
export TMP_PATH
cat > "$APP_FILE" <<'SH'
#!/bin/sh
for x in "$@";do case "$x" in config_file=*) echo alive > "$TMP_PATH/\u0024{x#*=}";;esac;done
exit "\u0024{launch_error:-0}"
SH
chmod +x "$APP_FILE"
config_n_get() { [ "$2" != type ] || echo Hysteria; }
get_new_port() { echo 48900; };check_process() { :; };flock() { :; };sleep() { :; }
test_url() { echo 200; };curl() { echo 200; }
busybox() { echo 'ERROR generic Hysteria kill' >&2;exit 99; }
lua() { [ "$2:$3" = stop:client ] || exit 98;echo "$4" >> "$TMP_PATH/cleaned";[ "\u0024{cleanup_error:-0}" = 0 ] || return 1;rm -f "$4"; }
${helper}
${body}
${invoke} >/dev/null || exit 1
[ "$(wc -l < "$work/cleaned")" = 1 ] || exit 1
! ls "$work"/*.json >/dev/null 2>&1 || exit 1
# Failure to launch still takes the production EXIT cleanup path.
launch_error=1;export launch_error
if ${invoke} >/dev/null;then exit 1;fi
! ls "$work"/*.json >/dev/null 2>&1 || exit 1
launch_error=0;cleanup_error=1;export launch_error cleanup_error
if ${invoke} >/dev/null;then exit 1;fi
ls "$work"/*.json >/dev/null 2>&1 || exit 1
cleanup_error=0
cleanup_hysteria_probe "$(basename "$(ls "$work"/*.json)" .json)" || exit 1
`});console.log('PASS '+name+' real probe: success, launch failure, cleanup failure, retained state and retry');
}
