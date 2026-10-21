"""Disposable-container socket experiment, NOT an SS/Hysteria substitute.
The launcher calls the real api.exec_call_as_gid with native nixio.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading


def command(argv, data=None):
    try:
        return subprocess.check_output(argv, input=data, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        print(error.output, file=sys.stderr)
        raise


def child():
    mode, family, kind, target = sys.argv[2:]
    family, target = int(family), int(target)
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    addr = '127.0.0.1' if family == 4 else '::1'
    if mode == 'fork':
        pid = os.fork()
        if pid:
            os.waitpid(pid, 0)
            return
    sock = socket.socket(af, socket.SOCK_RAW if kind == 'raw' else
                         socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM,
                         socket.IPPROTO_TCP if kind == 'raw' else 0)
    sock.settimeout(.35)
    created_gid = os.fstat(sock.fileno()).st_gid
    if mode == 'early':
        os.setgid(9911)
    elif mode == 'late':
        os.setgid(0)
    elif mode == 'ttl':
        sock.setsockopt(socket.IPPROTO_IP if family == 4 else socket.IPPROTO_IPV6,
                        socket.IP_TTL if family == 4 else socket.IPV6_UNICAST_HOPS, 1)
    if kind == 'raw':
        # Same IP raw-socket class used by H1 FakeTCP, NOT its wire protocol.
        segment = struct.pack('!HHIIBBHHH', 40321, target, 12345, 0, 5 << 4, 2, 2048, 0, 0)
        address = socket.inet_pton(af, addr)
        pseudo = address * 2 + (struct.pack('!BBH', 0, 6, len(segment)) if family == 4 else
                                struct.pack('!I3xB', len(segment), 6))
        payload = pseudo + segment
        total = sum(struct.unpack('!' + 'H' * (len(payload) // 2), payload))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        checksum = (~total) & 65535
        segment = segment[:16] + struct.pack('!H', checksum) + segment[18:]
        # A local netfilter DROP can return EPERM to a raw sender. Still require
        # the expected kernel counter below; an unrelated permission failure
        # must not be accepted as evidence of matching.
        try:
            sock.sendto(segment, (addr, 0))
        except PermissionError:
            pass
        received = None  # Only kernel rule counters prove raw OUTPUT matching.
    else:
        try:
            sock.connect((addr, target))
            sock.send(b'x')
            received = sock.recv(2) == b'ok'
        except (TimeoutError, OSError):
            received = False
    print(json.dumps(dict(mode=mode, family=family, kind=kind, gid=os.getgid(),
                          created_gid=created_gid, received=received)), flush=True)
    sock.close()


def server(sock, kind):
    while True:
        if kind == 'tcp':
            conn, _ = sock.accept()
            with conn:
                conn.recv(1)
                conn.sendall(b'ok')
        else:
            _, address = sock.recvfrom(100)
            sock.sendto(b'ok', address)


def driver():
    print('TEST kernel:', os.uname().release, 'machine:', os.uname().machine)
    listeners, ports, families = [], {}, []
    for family in (4, 6):
        af = socket.AF_INET if family == 4 else socket.AF_INET6
        try:
            for kind in ('tcp', 'udp'):
                s = socket.socket(af, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM)
                if family == 6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind(('127.0.0.1' if family == 4 else '::1', 0))
                if kind == 'tcp':
                    s.listen()
                ports[family, kind] = s.getsockname()[1]
                listeners.append(s)
                threading.Thread(target=server, args=(s, kind), daemon=True).start()
            ports[family, 'raw'] = 33334
            families.append(family)
        except OSError as error:
            if family == 4:
                raise
            print('SKIP IPv6 socket environment:', error)

    def launch(gid, mode, family, kind):
        value = json.loads(command(['lua5.1', '/tmp/gid-launch.lua', str(gid), mode,
                                    str(family), kind, str(ports[family, kind])]))
        assert value['created_gid'] == gid, value
        return value

    # These facts hold even when the container kernel lacks netfilter modules.
    for family in families:
        for kind in ('tcp', 'udp'):
            for gid, mode in ((0, 'early'), (9911, 'normal'), (9911, 'fork'), (9911, 'late')):
                value = launch(gid, mode, family, kind)
                assert value['received'], value
                assert value['gid'] == (0 if mode == 'late' else 9911), value
    print('PASS native api.exec_call_as_gid/nixio: families', families, 'TCP/UDP socket creation, fork/exec inheritance and pre-created descriptor counterexample')

    for backend in ('nft', 'iptables'):
        bins = {4: shutil.which('iptables-legacy') or 'iptables',
                6: shutil.which('ip6tables-legacy') or 'ip6tables'}
        for binary in (['nft'] if backend == 'nft' else list(bins.values())):
            version = command([binary, '--version']).strip()
            print('TEST backend:', version)
            if '(nf_tables)' in version:
                print('BOUNDARY: iptables-nft frontend; legacy xt_owner kernel path is not covered by this run')
        try:
            if backend == 'nft':
                command(['nft', 'add', 'table', 'inet', 'pwc_identity'])
            else:
                for family in families:
                    command([bins[family], '-t', 'filter', '-N', 'PWC_IDENTITY'])
        except subprocess.CalledProcessError as error:
            print('SKIP real', backend, 'kernel unavailable:', error.output.strip())
            continue
        if backend == 'nft':
            lines = ['add chain inet pwc_identity out { type filter hook output priority -200; policy accept; }']
            for family in families:
                for kind in ('tcp', 'udp', 'raw'):
                    proto = 'udp' if kind == 'udp' else 'tcp'
                    match = f'meta nfproto ipv{family} {proto} dport {ports[family, kind]}'
                    tag = f'{family}-{kind}'
                    lines += [f'add rule inet pwc_identity out {match} meta skgid 9911 counter accept comment "{tag}-allow"',
                              f'add rule inet pwc_identity out {match} counter drop comment "{tag}-drop"']
            command(['nft', '-f', '-'], '\n'.join(lines) + '\n')
        else:
            for family in families:
                b = bins[family]
                command([b, '-A', 'PWC_IDENTITY', '-m', 'owner', '--gid-owner', '9911', '-j', 'RETURN'])
                command([b, '-A', 'PWC_IDENTITY', '-j', 'DROP'])
                for kind in ('tcp', 'udp', 'raw'):
                    command([b, '-I', 'OUTPUT', '-p', 'udp' if kind == 'udp' else 'tcp',
                             '--dport', str(ports[family, kind]), '-j', 'PWC_IDENTITY'])

        def counters(family, kind):
            if backend == 'nft':
                rules = json.loads(command(['nft', '-j', 'list', 'table', 'inet', 'pwc_identity']))['nftables']
                result = {}
                for item in rules:
                    r = item.get('rule', {})
                    if r.get('comment', '').startswith(f'{family}-{kind}-'):
                        result[r['comment'].rsplit('-', 1)[1]] = next(e['counter']['packets'] for e in r['expr'] if 'counter' in e)
                return result
            rows = command([bins[family], '-nvxL', 'PWC_IDENTITY']).splitlines()[2:]
            return dict(zip(('allow', 'drop'), (int(row.split()[0]) for row in rows)))

        for family in families:
            for kind in ('tcp', 'udp', 'raw'):
                for gid, mode, allowed in ((9911, 'normal', True), (0, 'normal', False),
                                            (0, 'early', False), (9911, 'fork', True), (9911, 'late', True)):
                    before = counters(family, kind)
                    value = launch(gid, mode, family, kind)
                    after = counters(family, kind)
                    hit = 'allow' if allowed else 'drop'
                    assert after[hit] > before[hit], (backend, value, before, after)
                    if kind != 'raw':
                        assert value['received'] == allowed, (backend, value)
        print('PASS real', backend, 'OUTPUT counters: TCP/UDP/IP-raw families', families, '; same endpoint ordinary traffic blocked; creation fsgid, not current process GID')
        if backend == 'nft':
            command(['nft', 'delete', 'table', 'inet', 'pwc_identity'])
        else:
            for family in families:
                for kind in ('tcp', 'udp', 'raw'):
                    command([bins[family], '-D', 'OUTPUT', '-p', 'udp' if kind == 'udp' else 'tcp',
                             '--dport', str(ports[family, kind]), '-j', 'PWC_IDENTITY'])
                command([bins[family], '-F', 'PWC_IDENTITY'])
                command([bins[family], '-X', 'PWC_IDENTITY'])

        # Route selection exemption must not bypass a later filter TTL/HL DROP.
        # This models the placement contract, NOT a FakeTCP binary handshake.
        if backend == 'nft':
            lines = ['add table inet pwc_guard',
                     'add chain inet pwc_guard route { type route hook output priority -150; policy accept; }',
                     'add chain inet pwc_guard filter { type filter hook output priority 0; policy accept; }']
            for family in families:
                match = f'meta nfproto ipv{family} tcp dport {ports[family, "tcp"]}'
                ttl = 'ip ttl 1' if family == 4 else 'ip6 hoplimit 1'
                lines += [f'add rule inet pwc_guard route {match} meta skgid 9911 counter return comment "{family}-exempt"',
                          f'add rule inet pwc_guard filter {match} {ttl} counter drop comment "{family}-guard"']
            command(['nft', '-f', '-'], '\n'.join(lines) + '\n')
        else:
            for family in families:
                b = bins[family]
                command([b, '-t', 'mangle', '-N', 'PWC_ROUTE'])
                command([b, '-t', 'mangle', '-A', 'PWC_ROUTE', '-m', 'owner', '--gid-owner', '9911', '-j', 'RETURN'])
                command([b, '-t', 'mangle', '-I', 'OUTPUT', '-p', 'tcp', '--dport', str(ports[family, 'tcp']), '-j', 'PWC_ROUTE'])
                command([b, '-N', 'PWC_GUARD'])
                command([b, '-A', 'PWC_GUARD', '-j', 'DROP'])
                command([b, '-I', 'OUTPUT', '-p', 'tcp', '--dport', str(ports[family, 'tcp']),
                         '-m', 'ttl' if family == 4 else 'hl', '--ttl-eq' if family == 4 else '--hl-eq', '1', '-j', 'PWC_GUARD'])
        for family in families:
            value = launch(9911, 'ttl', family, 'tcp')
            assert not value['received'], (backend, value)
            if backend == 'nft':
                rules = json.loads(command(['nft', '-j', 'list', 'table', 'inet', 'pwc_guard']))['nftables']
                hits = {item['rule']['comment']: next(e['counter']['packets'] for e in item['rule']['expr'] if 'counter' in e)
                        for item in rules if 'rule' in item}
                assert hits[f'{family}-exempt'] > 0 and hits[f'{family}-guard'] > 0, hits
            else:
                b = bins[family]
                for table, chain in (('mangle', 'PWC_ROUTE'), ('filter', 'PWC_GUARD')):
                    rows = command([b, '-t', table, '-nvxL', chain]).splitlines()[2:]
                    assert int(rows[0].split()[0]) > 0, (table, chain, rows)
        print('PASS real', backend, 'IPv4 TTL/IPv6 HL filter DROP survives earlier GID route exemption; families', families)
        if backend == 'nft':
            command(['nft', 'delete', 'table', 'inet', 'pwc_guard'])
        else:
            for family in families:
                b = bins[family]
                command([b, '-t', 'mangle', '-D', 'OUTPUT', '-p', 'tcp', '--dport', str(ports[family, 'tcp']), '-j', 'PWC_ROUTE'])
                command([b, '-t', 'mangle', '-F', 'PWC_ROUTE'])
                command([b, '-t', 'mangle', '-X', 'PWC_ROUTE'])
                command([b, '-D', 'OUTPUT', '-p', 'tcp', '--dport', str(ports[family, 'tcp']),
                         '-m', 'ttl' if family == 4 else 'hl', '--ttl-eq' if family == 4 else '--hl-eq', '1', '-j', 'PWC_GUARD'])
                command([b, '-F', 'PWC_GUARD'])
                command([b, '-X', 'PWC_GUARD'])
    print('BOUNDARY: no real SS-libev or Hysteria binary/handshake was executed; IP-raw is a socket-class experiment, not FakeTCP validation')


if __name__ == '__main__':
    child() if len(sys.argv) > 1 and sys.argv[1] == 'child' else driver()
