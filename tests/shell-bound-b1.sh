#!/bin/sh
# D1-A: one explicitly selected scenario per fresh, offline native container.
# 0=driver complete/behavior PASS, 10=driver complete/behavior FAIL; other exits
# are infrastructure/precondition failures, never proof of a production defect.
b1_empty_birth() {
	d1a_case=$1
	case "$d1a_case" in
		global-live|global-exited|global-stat-eacces|global-truncated|global-illegal-pid|global-invalid-birth|global-mismatch|global-idempotent|global-unsealed-eacces|global-unsealed-eio|rollback-unsealed-exited|rollback-sealed-exited|acl-main-live|acl-main-exited|acl-relay-live|acl-relay-eacces|acl-relay-eio|acl-main-mismatch|acl-relay-mismatch|acl-idempotent) ;;
		*) echo 'D1A infrastructure: invalid scenario' >&2; return 2 ;;
	esac
	b1_identity_fixture
	uci set passwall.settings.tcp_node=ss; uci set passwall.settings.udp_node=tcp
	uci set passwall.a.tcp_node=ss; uci set passwall.a.udp_node=tcp
	capture
	d1a_role=main; d1a_scope=global; d1a_expected=1; d1a_io_fault=
	case "$d1a_case" in acl-*) d1a_scope=acl ;; esac
	case "$d1a_case" in acl-relay-*|acl-idempotent) d1a_role=relay ;; esac
	case "$d1a_case" in
		rollback-*|global-unsealed-*|global-idempotent)
			[ "$d1a_case" = rollback-sealed-exited ] || d1a_birth_fault=1
			d1a_start_rc=0
			case "$d1a_case" in rollback-*) export D1A_PHASE=operation ;; esac
			passwall_start_bound_global_nodes "$snapshot" ipv4 4 || d1a_start_rc=$?
			d1a_birth_fault=
			d1a_instance=$(cat "$D1A_ROOT/instance")
			case "$d1a_case" in
				rollback-*) d1a_rc=$d1a_start_rc; d1a_expected=2 ;;
				*) [ "$d1a_start_rc" = 1 ] || fail d1a-unsealed-precondition ;;
			esac
			;;
		*)
			if [ "$d1a_scope" = global ]; then
				status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
				d1a_config=$(global_config TCP)
			else
				status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
				d1a_config=$(acl_config a tcp)
			fi
			d1a_instance=${d1a_config%/*}
			d1a_evidence register main "$(head -n 1 "$d1a_instance/process")"
			[ "$d1a_scope" != acl ] || d1a_evidence register relay "$(head -n 1 "$d1a_instance/relay/process")"
			d1a_evidence snapshot sealed "$d1a_instance"
			d1a_record="$d1a_instance/process"; [ "$d1a_role" != relay ] || d1a_record="$d1a_instance/relay/process"
			d1a_mutation=empty
			case "$d1a_case" in *-truncated) d1a_mutation=truncated ;; *-illegal-pid) d1a_mutation=illegal-pid ;; *-invalid-birth) d1a_mutation=invalid-birth ;; *-mismatch) d1a_mutation=mismatch ;; esac
			d1a_evidence mutate "$d1a_record" "$d1a_mutation"
			;;
	esac
	d1a_target=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["pid"])' "$D1A_ROOT/identities.json" "$d1a_role")
	case "$d1a_case" in
		global-exited|acl-main-exited|acl-idempotent|global-idempotent)
			d1a_evidence terminate "$d1a_role"; d1a_expected=0 ;;
		acl-relay-mismatch) d1a_expected=0 ;;
	esac
	case "$d1a_case" in *eacces) d1a_io_fault=eacces ;; *eio) d1a_io_fault=eio ;; esac
	export D1A_PHASE=probe
	_pw_global_ss_state "$d1a_target" '' > "$D1A_ROOT/direct"
	if [ -n "$d1a_io_fault" ]; then
		[ "$(cat "$D1A_ROOT/direct")" = unknown ] || fail d1a-probe-fault
	fi
	case "$d1a_case" in
		rollback-*) ;; # The wrapper captured before while the directory existed.
		*)
			d1a_evidence snapshot before "$d1a_instance"
			export D1A_PHASE=operation; d1a_rc=0
			if [ "$d1a_scope" = global ]; then passwall_stop_global_nodes || d1a_rc=$?
			else passwall_stop_acl_nodes a || d1a_rc=$?; fi
			;;
	esac
	d1a_evidence snapshot after "$d1a_instance"
	case "$d1a_case" in
		global-idempotent|acl-idempotent)
			export D1A_PHASE=repeat; d1a_repeat=0
			if [ "$d1a_scope" = global ]; then passwall_stop_global_nodes || d1a_repeat=$?
			else passwall_stop_acl_nodes a || d1a_repeat=$?; fi
			printf '%s\n' "$d1a_repeat" > "$D1A_ROOT/repeat-rc"
			d1a_evidence snapshot repeat "$d1a_instance"
			;;
	esac
	d1a_evidence verdict "$d1a_case" "$d1a_rc" "$d1a_expected" "$d1a_instance" "$d1a_role"
}

# Shared setup; the original D1-A assertions remain in their own verdict.
b1_stop_owner() {
	d1a_case=$1; d1c_active=1
	case "$d1a_case" in
		global-sealed-eio|global-sealed-stat-damaged|acl-main-sealed-eacces|acl-main-sealed-eio|acl-main-sealed-stat-damaged|identity-missing-live|identity-missing-exited|acl-identity-missing-exited|identity-corrupt|seal-pid|seal-node|binding-gid|binding-config-md5|seal-config-md5|endpoint-port|command-invalid|command-incomplete|directory-invalid|cross-root|noncanonical|symlink|snapshot-invalid|metadata-node|seal-generation|birth-number|birth-invalid|birth-changed-empty|birth-changed-normal) ;;
		*) echo 'D1C infrastructure: invalid scenario' >&2; return 2 ;;
	esac
	b1_identity_fixture
	uci set passwall.settings.tcp_node=ss; uci set passwall.settings.udp_node=tcp
	uci set passwall.a.tcp_node=ss; uci set passwall.a.udp_node=tcp
	capture
	d1a_scope=global; d1a_io_fault=
	case "$d1a_case" in acl-*) d1a_scope=acl ;; esac
	if [ "$d1a_scope" = global ]; then
		status_is 0 passwall_start_bound_global_nodes "$snapshot" ipv4 4
		d1a_config=$(global_config TCP)
	else
		status_is 0 passwall_start_bound_acl_nodes "$snapshot" a ipv4 4 0 warn
		d1a_config=$(acl_config a tcp)
	fi
	d1a_instance=${d1a_config%/*}
	d1a_evidence register main "$(head -n 1 "$d1a_instance/process")"
	[ "$d1a_scope" != acl ] || d1a_evidence register relay "$(head -n 1 "$d1a_instance/relay/process")"
	d1a_evidence snapshot sealed "$d1a_instance"
	[ "$d1a_case" = birth-changed-normal ] || d1a_evidence mutate "$d1a_instance/process" empty
	export D1A_PHASE=baseline
	d1c_rc=0; _pw_bound_helper owner "$d1a_instance" stop "$TMP_PATH" || d1c_rc=$?
	printf '%s\n' "$d1c_rc" > "$D1A_ROOT/baseline-rc"
	[ "$d1c_rc" = 0 ] || fail d1c-invalid-baseline
	d1a_evidence d1c-mutate "$d1a_case" "$d1a_instance"
	d1a_instance=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["actual"])' "$D1A_ROOT/location.json")
	d1c_call=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["call"])' "$D1A_ROOT/location.json")
	d1c_internal=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["internal"]))' "$D1A_ROOT/location.json")
	d1a_target=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["main"]["pid"])' "$D1A_ROOT/identities.json")
	case "$d1a_case" in *-exited) d1a_evidence terminate main ;; esac
	case "$d1a_case" in *-eacces) d1a_io_fault=eacces ;; *-eio) d1a_io_fault=eio ;; *-stat-damaged) d1a_io_fault=stat-damaged ;; esac
	export D1A_PHASE=normal_probe
	d1c_rc=0; _pw_bound_helper owner "$d1c_call" || d1c_rc=$?
	printf '%s\n' "$d1c_rc" > "$D1A_ROOT/normal_probe-rc"
	export D1A_PHASE=stop_probe
	d1c_rc=0; _pw_bound_helper owner "$d1c_call" stop "$TMP_PATH" || d1c_rc=$?
	printf '%s\n' "$d1c_rc" > "$D1A_ROOT/stop_probe-rc"
	d1a_evidence snapshot before "$d1a_instance"
	export D1A_PHASE=operation; d1c_rc=0
	if [ "$d1c_internal" = 1 ]; then _pw_global_instance_stop "$d1c_call" || d1c_rc=$?
	elif [ "$d1a_scope" = global ]; then passwall_stop_global_nodes || d1c_rc=$?
	else passwall_stop_acl_nodes a || d1c_rc=$?; fi
	d1a_evidence snapshot after "$d1a_instance"
	d1a_evidence d1c-verdict "$d1a_case" "$d1c_rc" "$d1a_instance"
}

b1_identity_fixture() {
	# Do not let the old fixture EXIT cleanup obscure the captured outcome.
	# The host collects evidence then destroys this task-owned container.
	trap - EXIT
	export D1A_ROOT="$work/d1a" D1A_PHASE=prepare
	mkdir "$D1A_ROOT"
	: > "$D1A_ROOT/events"
	cat > "$D1A_ROOT/evidence.py" <<'PY'
import errno, hashlib, json, os, pathlib, signal, sys, time
root = pathlib.Path(os.environ['D1A_ROOT'])
def load(name, default):
    p = root / name
    return json.loads(p.read_text()) if p.exists() else default
def save(name, value): (root / name).write_text(json.dumps(value, sort_keys=True))
def proc(pid):
    try:
        raw = pathlib.Path('/proc/' + str(pid) + '/stat').read_text()
        actual, rest = raw.split(' ', 1); fields = rest.rsplit(') ', 1)[1].split()
        assert actual == str(pid) and len(fields) >= 20 and fields[19].isdigit(), raw
        return dict(pid=str(pid), birth=fields[19], state=fields[0], stat=raw)
    except OSError as e: return dict(pid=str(pid), errno=e.errno)
def sockets(pid):
    owned = set()
    try:
        for p in pathlib.Path('/proc/' + str(pid) + '/fd').iterdir():
            try:
                link = os.readlink(p)
                if link.startswith('socket:['): owned.add(link[8:-1])
            except OSError: pass
    except OSError: pass
    rows = []
    for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
        for row in pathlib.Path('/proc/net/' + proto).read_text().splitlines()[1:]:
            f = row.split()
            if len(f) > 9 and f[9] in owned: rows.append(dict(proto=proto, inode=f[9], local=f[1], state=f[3]))
    return rows
def snapshot(instance):
    directory = pathlib.Path(instance)
    files = {}
    for name in ['process','relay/process','binding.json','bound.identity','bound.capabilities','meta','config.json']:
        p = directory / name
        if p.is_file():
            data = p.read_bytes()
            files[name] = dict(hex=data.hex(), sha256=hashlib.sha256(data).hexdigest())
    runtime = pathlib.Path(os.environ['D1A_RUNTIME'])
    cache = runtime / 'var'; release = runtime / 'acl/split-acl/release.a'
    return dict(instance=instance, exists=directory.is_dir(), files=files,
        processes={k:dict(proc(v['pid']), sockets=sockets(v['pid'])) for k,v in load('identities.json',{}).items()},
        cache=cache.read_text() if cache.is_file() else '', release=release.read_text() if release.is_file() else None)
action = sys.argv[1]
if action == 'register':
    role, pid = sys.argv[2:]; p = proc(pid)
    assert 'errno' not in p and p['state'] != 'Z', p
    identities = load('identities.json', {}); identities[role] = p; save('identities.json', identities)
elif action == 'snapshot':
    phase, instance = sys.argv[2:]; data = load('snapshots.json', {}); data[phase] = snapshot(instance); save('snapshots.json', data)
elif action == 'mutate':
    path, mode = sys.argv[2:]; p = pathlib.Path(path); raw = p.read_bytes(); lines = raw.split(b'\n')
    assert len(lines) >= 4 and lines[0].isdigit() and lines[1].isdigit(), raw
    if mode == 'truncated': data = lines[0] + b'\n'
    else:
        if mode == 'illegal-pid': lines[0], lines[1] = b'invalid', b''
        elif mode == 'invalid-birth': lines[1] = b'invalid'
        elif mode == 'mismatch': lines[1] = str(int(lines[1])+1).encode()
        else:
            assert mode == 'empty'; lines[1] = b''
        data = b'\n'.join(lines)
    p.write_bytes(data)
    if mode == 'empty': assert data.split(b'\n')[1] == b'' and len(data.split(b'\n')) >= 4
    changes = load('mutations.json', []); changes.append(dict(path=path, mode=mode, before=raw.hex(), after=data.hex())); save('mutations.json', changes)
elif action == 'terminate':
    role = sys.argv[2]; original = load('identities.json', {})[role]; now = proc(original['pid'])
    assert now.get('birth') == original['birth'] and now.get('state') != 'Z', (original,now)
    with (root/'events').open('a') as f: f.write('setup-signal\t'+os.environ['D1A_PHASE']+'\t-TERM\t'+original['pid']+'\n')
    os.kill(int(original['pid']), signal.SIGTERM)
    for _ in range(500):
        now = proc(original['pid'])
        if now.get('errno') == errno.ENOENT: break
        assert 'errno' not in now and now['birth'] == original['birth'], now
        time.sleep(.01)
    assert now.get('errno') == errno.ENOENT, now
    save('enoent-'+role+'.json', now)
elif action == 'd1c-mutate':
    case, instance = sys.argv[2:]; directory = pathlib.Path(instance)
    location = dict(actual=instance, call=instance, internal=False)
    change = None
    if case in ['directory-invalid','cross-root']:
        runtime = pathlib.Path(os.environ['D1A_RUNTIME']); work = runtime.parent
        parent = work / ('invalid' if case=='directory-invalid' else 'other-runtime/acl/default/split')
        parent.mkdir(parents=True); destination = parent / directory.name
        directory.rename(destination)
        change = dict(field='instance_location',before=instance,after=str(destination))
        location = dict(actual=str(destination),call=str(destination),internal=True)
    elif case in ['noncanonical','symlink']:
        argument = instance + '/.'
        if case=='symlink':
            argument = str(directory.parent/'instance.alias'); os.symlink(instance,argument)
        change = dict(field='stop_argument',before=instance,after=argument)
        location = dict(actual=instance,call=argument,internal=True)
    elif case.startswith('identity-missing') or case=='acl-identity-missing-exited':
        p=directory/'bound.identity'; raw=p.read_bytes(); p.unlink()
        change=dict(field='bound.identity',before=raw.hex(),after=None)
    elif case=='identity-corrupt':
        p=directory/'bound.identity'; raw=p.read_bytes(); data=b'{invalid JSON\n'; p.write_bytes(data)
        change=dict(field='bound.identity',before=raw.hex(),after=data.hex())
    elif case.startswith('command-'):
        p=directory/'process'; raw=p.read_bytes(); lines=raw.split(b'\n')
        assert lines[1]==b'' and len(lines)==4,raw
        data=lines[0]+b'\n\n'+(b'invalid-command\n' if case=='command-invalid' else b'')
        p.write_bytes(data); change=dict(field='process.command',before=raw.hex(),after=data.hex())
    elif case=='metadata-node':
        p=directory/'meta'; raw=p.read_bytes(); lines=raw.split(b'\n'); before=lines[1].decode(); lines[1]=b'other'
        assert before!='other'; data=b'\n'.join(lines); p.write_bytes(data)
        change=dict(field='meta.node',before=before,after='other',before_hex=raw.hex(),after_hex=data.hex())
    elif case not in ['global-sealed-eio','global-sealed-stat-damaged','acl-main-sealed-eacces','acl-main-sealed-eio','acl-main-sealed-stat-damaged']:
        seal_cases=['seal-pid','seal-node','seal-config-md5','seal-generation','birth-number','birth-invalid','birth-changed-empty','birth-changed-normal']
        name='bound.identity' if case in seal_cases else 'binding.json'
        p=directory/name; raw=p.read_bytes(); data=json.loads(raw); old=json.loads(raw)
        key={'seal-pid':'pid','seal-node':'node_id','binding-gid':'gid','binding-config-md5':'config_md5','seal-config-md5':'config_md5','endpoint-port':'endpoint.port','snapshot-invalid':'snapshot','seal-generation':'generation','birth-number':'birth','birth-invalid':'birth','birth-changed-empty':'birth','birth-changed-normal':'birth'}[case]
        target=data['endpoint'] if key=='endpoint.port' else data; leaf=key.split('.')[-1]; before=target[leaf]
        if case=='seal-pid' or case.startswith('birth-changed'): after=str(int(before)+1)
        elif case=='birth-number': after=int(before)
        elif case=='birth-invalid': after='invalid'
        elif case=='binding-gid': after=0
        elif 'config-md5' in case: after='0'*32
        elif case=='endpoint-port': after=int(before)+1
        elif case=='snapshot-invalid': after=str(pathlib.Path(before).parent/'not-generation')
        else: after='other'
        assert type(before)!=type(after) or before!=after
        target[leaf]=after
        # Prove only the named logical field differs (JSON whitespace is immaterial).
        restored=json.loads(json.dumps(data)); (restored['endpoint'] if key=='endpoint.port' else restored)[leaf]=before
        assert restored==old
        new=json.dumps(data,sort_keys=True).encode(); p.write_bytes(new)
        change=dict(field=name+'.'+key,before=before,after=after,before_hex=raw.hex(),after_hex=new.hex())
    save('boundary.json',[] if change is None else [change]); save('location.json',location)
elif action == 'd1c-verdict':
    case, rc, instance = sys.argv[2:]; rc=int(rc)
    snaps=load('snapshots.json',{}); before,after=snaps['before'],snaps['after']; ids=load('identities.json',{})
    events=[line.split('\t') for line in (root/'events').read_text().splitlines()]
    op=[e for e in events if e[1]=='operation']; owners=[e for e in op if e[0]=='owner']; states=[e for e in op if e[0]=='state']; signals=[e for e in op if e[0]=='signal']; faults=[e for e in op if e[0]=='fault']
    probes={phase:int((root/(phase+'-rc')).read_text()) for phase in ['baseline','normal_probe','stop_probe']}
    stderr={phase:(root/('owner-'+phase+'.stderr')).read_text() for phase in ['baseline','normal_probe','stop_probe','operation'] if (root/('owner-'+phase+'.stderr')).exists()}
    boundary=load('boundary.json',[]); location=load('location.json',{}); io_case='sealed-' in case
    assert probes['baseline']==0, 'fixture invalid before boundary injection'
    seal=json.loads(bytes.fromhex(snaps['sealed']['files']['bound.identity']['hex']))
    assert seal['pid']==ids['main']['pid'] and seal['birth']==ids['main']['birth']
    assert before['exists'] and before['files']['binding.json']
    changes=load('mutations.json',[])
    if case!='birth-changed-normal':
        assert len(changes)==1 and changes[0]['mode']=='empty'
        lines=bytes.fromhex(changes[0]['after']).split(b'\n'); assert len(lines)==4 and lines[1]==b'' and lines[2]
    else: assert not changes
    assert len(boundary)==(0 if io_case else 1), boundary
    dead=load('enoent-main.json',None)
    if case.endswith('-exited'):
        assert dead and dead['errno']==errno.ENOENT and before['processes']['main'].get('errno')==errno.ENOENT
    else: assert before['processes']['main'].get('birth')==ids['main']['birth']
    errors=[]
    def check(ok,message):
        if not ok: errors.append(message)
    if io_case:
        assert probes['stop_probe']==0 and owners and all(e[3]=='0' for e in owners), 'owner did not admit the valid empty-birth fixture'
        assert faults and any(e[2]==ids['main']['pid'] and e[4]=='unknown' for e in states), 'fault missed lifecycle observer'
        check(not any(e[3]==ids['main']['pid'] for e in signals),'identity-unknown main received signal')
        check(after['processes']['main'].get('birth')==ids['main']['birth'],'protected main disappeared')
        if case.startswith('acl-'):
            check(after['processes']['relay'].get('errno')==errno.ENOENT and not after['processes']['relay']['sockets'],'valid relay not independently stopped')
    elif case=='birth-changed-empty':
        check(probes['stop_probe']==0 and owners and all(e[3]=='0' for e in owners),'owner did not admit the empty-birth fixture')
        check(states and all(e[2]==ids['main']['pid'] and e[3]=='' and e[4]=='unknown' for e in states),'live empty-birth instance did not remain unknown')
        check(not signals,'empty-birth instance received a production signal')
        check(after['processes']['main'].get('birth')==ids['main']['birth'],'protected main disappeared')
    else:
        check(probes['stop_probe']==1,'stop_owner admitted a missing/tampered identity or invalid responsibility path')
        check(owners and all(e[3]=='1' for e in owners),'lifecycle owner did not reject')
        check(not states,'lifecycle observer reached after boundary violation')
        check(not signals,'production signal sent after boundary violation')
        for role,p in before['processes'].items():
            if p.get('errno')==errno.ENOENT: check(after['processes'][role].get('errno')==errno.ENOENT,role+' PID unexpectedly reappeared')
            else: check(after['processes'][role].get('birth')==p['birth'],role+' disappeared despite owner violation')
    check(rc==1,'production rc: expected 1 got '+str(rc))
    check(after['exists'],'responsibility directory lost')
    if after['exists']:
        check(after['files']==before['files'],'responsibility records/config changed')
    if case.startswith('acl-'): check(after['release'] is not None,'ACL release responsibility lost')
    if location['internal']: check(after['cache']==before['cache'],'internal rejection changed public cache')
    else: check(not any(line.split('=',1)[0].endswith('_instance') for line in after['cache'].splitlines()),'public instance cache remains')
    target_signals=[e for e in signals if e[3]==ids['main']['pid']]
    safety=not target_signals and (after['processes']['main'].get('errno')==errno.ENOENT if dead else after['processes']['main'].get('birth')==ids['main']['birth'])
    result=dict(case=case,driver='PASS',behavior='FAIL' if errors else 'PASS',production_rc=rc,errors=errors,probes=probes,owner_stderr=stderr,identities=ids,mutations=changes,boundary=boundary,location=location,snapshots=snaps,events=events,main_signal_protection='PASS' if safety else 'FAIL',lifecycle=dict(owner_rc=[int(e[3]) for e in owners],observer_calls=len(states),fault_hits=len(faults),signals=signals),rejection_layer='observer' if io_case or case=='birth-changed-empty' else ('owner' if probes['stop_probe']==1 else 'NOT REJECTED'))
    save('result.json',result)
    print('D1C_RESULT '+json.dumps({k:v for k,v in result.items() if k not in ['identities','snapshots','events','mutations','boundary','owner_stderr']}))
    sys.exit(10 if errors else 0)
elif action == 'verdict':
    case, actual, expected, instance, role = sys.argv[2:]; actual, expected = int(actual), int(expected)
    snaps=load('snapshots.json',{}); before, after=snaps['before'],snaps['after']
    events=[line.split('\t') for line in (root/'events').read_text().splitlines()]
    operational=[e for e in events if e[1]=='operation']; target=load('identities.json',{})[role]
    owners=[e for e in operational if e[0]=='owner']; states=[e for e in operational if e[0]=='state']; signals=[e for e in operational if e[0]=='signal']; faults=[e for e in operational if e[0]=='fault']
    mutations=load('mutations.json',[]); direct=(root/'direct').read_text().strip()
    dead=load('enoent-'+role+'.json',None)
    is_rollback=case.startswith('rollback-'); unsealed=case.startswith('global-unsealed-') or case=='global-idempotent' or case=='rollback-unsealed-exited'
    # A missing prerequisite must not become a production FAIL.
    assert target['birth'].isdigit() and before['exists'] and 'binding.json' in before['files']
    assert unsealed or 'bound.identity' in before['files']
    if unsealed:
        receipt=bytes.fromhex(before['files']['process']['hex']).split(b'\n')
        assert len(receipt)>=4 and receipt[0].decode()==target['pid'] and receipt[1]==b'', receipt
    if not unsealed:
        seal=json.loads(bytes.fromhex(before['files']['bound.identity']['hex']))
        main=load('identities.json',{})['main']; assert str(seal['pid'])==main['pid'] and str(seal['birth'])==main['birth']
    if dead: assert dead['errno']==errno.ENOENT and before['processes'][role].get('errno')==errno.ENOENT and direct=='exited'
    else: assert before['processes'][role].get('birth')==target['birth'] and before['processes'][role].get('state')!='Z'
    if not unsealed: assert len(mutations)==1
    if 'eacces' in case or 'eio' in case:
        probe=[e for e in events if e[0]=='fault' and e[1]=='probe']; assert probe, 'I/O injection never hit the real observer'
        if unsealed or case.startswith('acl-relay-'): assert faults, 'lifecycle I/O injection not hit'
    if is_rollback:
        assert any(e[0]=='injection' and e[2]==('birth' if unsealed else 'seal') for e in events)
        if not unsealed:
            memory=(root/'memory').read_text().splitlines(); assert memory==[target['pid'],target['birth']], memory
    errors=[]
    def check(ok, message):
        if not ok: errors.append(message)
    check(actual==expected, 'production rc: expected %d got %d'%(expected,actual))
    check(not any(e[3]==target['pid'] for e in signals), 'uncertain/exited target received a production signal')
    if expected in [0,2]:
        check(not after['exists'], 'responsibility directory not reclaimed')
        for k,p in after['processes'].items():
            if case=='acl-relay-mismatch' and k==role: check(p.get('birth')==target['birth'], 'mismatched relay was killed')
            else: check(p.get('errno')==errno.ENOENT and not p['sockets'], k+' process/socket remains')
    else:
        check(after['exists'], 'responsibility directory lost')
        if not dead: check(after['processes'][role].get('birth')==target['birth'], 'protected target disappeared')
    if case.startswith('acl-relay-'):
        check(after['processes']['main'].get('errno')==errno.ENOENT and not after['processes']['main']['sockets'], 'valid ACL main process not stopped')
    if after['exists']:
        for name in ['process','relay/process','binding.json','bound.identity','bound.capabilities']:
            if name in before['files']: check(after['files'].get(name)==before['files'][name], name+' changed')
    check(not any(line.split('=',1)[0].endswith('_instance') for line in after['cache'].splitlines()), 'public instance cache remains')
    if case.startswith('acl-'): check((after['release'] is not None)==after['exists'], 'ACL release responsibility mismatch')
    if 'repeat' in snaps:
        check((root/'repeat-rc').read_text().strip()=='0' and not snaps['repeat']['exists'] and snaps['repeat']['release'] is None, 'repeat stop failed')
    reproduced=bool(dead and direct=='exited' and actual==1 and after['exists'] and owners and all(e[3]=='1' for e in owners) and not states and mutations and mutations[0]['mode']=='empty')
    result=dict(case=case,driver='PASS',behavior='FAIL' if errors else 'PASS',expected_rc=expected,production_rc=actual,owner_block_reproduced=reproduced,errors=errors,identities=load('identities.json',{}),mutations=mutations,snapshots=snaps,events=events,direct=direct,lifecycle=dict(owner_rc=[int(e[3]) for e in owners],observer_calls=len(states),fault_hits=len(faults),signals=signals),io_lifecycle=('PASS' if faults else 'NOT RUN: owner gate') if ('eacces' in case or 'eio' in case) else 'NOT APPLICABLE',empty_birth_repeat='PASS' if 'repeat' in snaps and not errors else 'NOT RUN')
    save('result.json',result)
    print('D1A_RESULT '+json.dumps({k:v for k,v in result.items() if k not in ['snapshots','identities','events','mutations']}))
    sys.exit(10 if errors else 0)
else: raise AssertionError(action)
PY
	export D1A_RUNTIME="$TMP_PATH"
	d1a_evidence() { python3 "$D1A_ROOT/evidence.py" "$@"; }
	# Preserve exact production implementations, then delegate and log only.
	eval "$(sed -n '/^_pw_global_ss_state() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/global_nodes.sh" | sed '1s/_pw_global_ss_state/d1a_real_state/')"
	eval "$(sed -n '/^_pw_bound_helper() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/bound_nodes.sh" | sed '1s/_pw_bound_helper/d1a_real_helper/')"
	eval "$(sed -n '/^_pw_bound_seal() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/bound_nodes.sh" | sed '1s/_pw_bound_seal/d1a_real_seal/')"
	eval "$(sed -n '/^get_process_start_time() {/,/^}/p' "$PW_BOUND_REPO/luci-app-passwall/root/usr/share/passwall/utils.sh" | sed '1s/get_process_start_time/d1a_real_birth/')"
	_pw_global_ss_state() {
		local value rc=0
		value=$(d1a_real_state "$@") || rc=$?
		printf 'state\t%s\t%s\t%s\t%s\t%s\n' "$D1A_PHASE" "$1" "$2" "$value" "$rc" >> "$D1A_ROOT/events"
		printf '%s\n' "$value"; return "$rc"
	}
	_pw_bound_helper() {
		local rc=0
		if [ "$d1a_case:$1" = rollback-unsealed-exited:owner ]; then d1a_evidence snapshot before "$2"; fi
		if [ "${d1c_active:-}:$1" = 1:owner ]; then
			d1a_real_helper "$@" 2> "$D1A_ROOT/owner-$D1A_PHASE.stderr" || rc=$?
			cat "$D1A_ROOT/owner-$D1A_PHASE.stderr" >&2
		else d1a_real_helper "$@" || rc=$?; fi
		[ "$1" != owner ] || printf 'owner\t%s\t%s\t%s\t%s\n' "$D1A_PHASE" "$2" "$rc" "${3:-normal}" >> "$D1A_ROOT/events"
		return "$rc"
	}
	kill() { printf 'signal\t%s\t%s\t%s\n' "$D1A_PHASE" "$1" "${2:-}" >> "$D1A_ROOT/events"; command kill "$@"; }
	get_process_start_time() {
		if [ "${d1a_birth_fault:-}" = 1 ] && [ ! -e "$D1A_ROOT/birth-hit" ]; then
			touch "$D1A_ROOT/birth-hit"
			d1a_evidence register main "$1"
			printf '%s\n' "$PW_GLOBAL_NEW_INSTANCE" > "$D1A_ROOT/instance"
			printf 'injection\t%s\tbirth\t%s\n' "$D1A_PHASE" "$1" >> "$D1A_ROOT/events"
			[ "$d1a_case" != rollback-unsealed-exited ] || d1a_evidence terminate main
			return 0
		fi
		d1a_real_birth "$@"
	}
	_pw_bound_seal() {
		d1a_real_seal "$@" || return
		if [ "$d1a_case" = rollback-sealed-exited ]; then
			printf '%s\n' "$1" > "$D1A_ROOT/instance"
			d1a_evidence register main "$(head -n 1 "$1/process")"
			printf '%s\n' "$PW_GLOBAL_NEW_PID" "$PW_GLOBAL_NEW_BIRTH" > "$D1A_ROOT/memory"
			d1a_evidence snapshot sealed "$1"
			d1a_evidence mutate "$1/process" empty
			d1a_evidence terminate main
			d1a_evidence snapshot before "$1"
			printf 'injection\t%s\tseal\t%s\n' "$D1A_PHASE" "$1" >> "$D1A_ROOT/events"
			return 1
		fi
	}
	lua() {
		if [ "$1" != - ]; then command lua5.1 "$PW_BOUND_REPO/tests/bound-api.lua" "$@"; return; fi
		if [ -z "${d1a_io_fault:-}" ]; then command lua5.1 "$@"; return; fi
		{
			cat <<'LUA'
local open=io.open; local target=os.getenv('D1A_TARGET'); local fault=os.getenv('D1A_IO_FAULT')
io.open=function(path,...)
 if path=='/proc/'..target..'/stat' then
  local log=assert(open(os.getenv('D1A_ROOT')..'/events','a'))
  log:write('fault\t'..os.getenv('D1A_PHASE')..'\t'..fault..'\t'..target..'\n'); log:close()
  if fault=='stat-damaged' then return {read=function() return target..' (broken) R 0' end,close=function() return true end} end
  return nil,'injected '..fault,fault=='eio' and 5 or 13
 end
 return open(path,...)
end
LUA
			cat
		} | D1A_TARGET="$d1a_target" D1A_IO_FAULT="$d1a_io_fault" command lua5.1 "$@"
	}
}
