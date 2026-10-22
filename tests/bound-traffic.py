"""Actual proxy traffic / private netfilter counters, never a proxy-core fixture."""
import http.server
import ipaddress
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

MARKER = b'bound-real-core-ok'
PORTS = [('tcp', 38388), ('udp', 38388), ('udp', 34443), ('udp', 34445), ('tcp', 34444)]


def command(args, data=None):
    return subprocess.check_output(args, input=data, text=True, stderr=subprocess.STDOUT)


def identity(backend, add):
    if backend == 'nft':
        if not add:
            command(['nft', 'delete', 'table', 'inet', 'pbidentity'])
            return
        lines = ['add table inet pbidentity', 'add chain inet pbidentity out { type route hook output priority -150; policy accept; }']
        for family, address in ((4, '127.0.0.1'), (6, '::1')):
            for proto, port in PORTS:
                match = f'{"ip" if family == 4 else "ip6"} daddr {address} {proto} dport {port}'
                lines += [f'add rule inet pbidentity out {match} meta skgid 9911 counter return comment "{family}-{proto}-{port}-allow"',
                          f'add rule inet pbidentity out {match} counter drop comment "{family}-{proto}-{port}-drop"']
        command(['nft', '-f', '-'], '\n'.join(lines) + '\n')
    else:
        for family, address in ((4, '127.0.0.1'), (6, '::1')):
            binary = 'iptables' if family == 4 else 'ip6tables'
            if add:
                command([binary, '-t', 'mangle', '-N', 'PBIDENTITY'])
                command([binary, '-t', 'mangle', '-A', 'PBIDENTITY', '-m', 'owner', '--gid-owner', '9911', '-j', 'RETURN'])
                command([binary, '-t', 'mangle', '-A', 'PBIDENTITY', '-j', 'DROP'])
            for proto, port in PORTS:
                command([binary, '-t', 'mangle', '-I' if add else '-D', 'OUTPUT', '-d', address, '-p', proto,
                         '--dport', str(port), '-j', 'PBIDENTITY'])
            if not add:
                command([binary, '-t', 'mangle', '-F', 'PBIDENTITY'])
                command([binary, '-t', 'mangle', '-X', 'PBIDENTITY'])


def counters(backend, family, proto, port):
    if backend == 'nft':
        data = json.loads(command(['nft', '-j', 'list', 'table', 'inet', 'pbidentity']))['nftables']
        result = {}
        for item in data:
            r = item.get('rule', {})
            if r.get('comment', '').startswith(f'{family}-{proto}-{port}-'):
                result[r['comment'].rsplit('-', 1)[1]] = next(e['counter']['packets'] for e in r['expr'] if 'counter' in e)
        return result
    rows = command(['iptables' if family == 4 else 'ip6tables', '-t', 'mangle', '-nvxL', 'PBIDENTITY']).splitlines()[2:]
    return dict(zip(('allow', 'drop'), (int(row.split()[0]) for row in rows)))


def receive(sock, length):
    data = b''
    while len(data) < length:
        piece = sock.recv(length - len(data))
        assert piece, 'early SOCKS EOF'
        data += piece
    return data


def socks(port, udp, family):
    control = socket.create_connection(('127.0.0.1', port), 4)
    control.settimeout(4)
    with control:
        control.sendall(b'\x05\x01\x00')
        assert receive(control, 2) == b'\x05\x00'
        target = ipaddress.ip_address('127.0.0.1' if family == 4 else '::1')
        endpoint = bytes([1 if family == 4 else 4]) + target.packed + struct.pack('!H', 18083 if udp else 18080)
        control.sendall(b'\x05' + bytes([3 if udp else 1]) + b'\x00' + (b'\x01\0\0\0\0\0\0' if udp else endpoint))
        head = receive(control, 4)
        assert head[:2] == b'\x05\x00', head
        address = receive(control, 4 if head[3] == 1 else 16)
        relay_port = struct.unpack('!H', receive(control, 2))[0]
        if udp:
            with socket.socket(socket.AF_INET if head[3] == 1 else socket.AF_INET6, socket.SOCK_DGRAM) as data:
                data.settimeout(4)
                relay = str(ipaddress.ip_address(address))
                if ipaddress.ip_address(relay).is_unspecified:
                    relay = '127.0.0.1' if head[3] == 1 else '::1'
                data.sendto(b'\0\0\0' + endpoint + MARKER, (relay, relay_port))
                assert data.recv(4096).endswith(MARKER)
        else:
            control.sendall(b'GET / HTTP/1.0\r\nHost: local\r\n\r\n')
            data = b''
            while True:
                piece = control.recv(4096)
                if not piece:
                    break
                data += piece
            assert MARKER in data, data


def traffic(backend, kind, listen, family, proto, remote_port):
    before = counters(backend, family, proto, remote_port)
    if kind == 'redir':
        command(['nft', '-f', '-'], 'add table ip pbredir\nadd chain ip pbredir out { type nat hook output priority -100; policy accept; }\n'
                f'add rule ip pbredir out ip daddr 198.18.0.10 tcp dport 18080 meta skgid != 9911 meta skgid != 9922 redirect to :{listen}\n')
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            assert MARKER in opener.open('http://198.18.0.10:18080', timeout=5).read()
        finally:
            command(['nft', 'delete', 'table', 'ip', 'pbredir'])
    else:
        socks(listen, kind == 'socks-udp', family)
    after = counters(backend, family, proto, remote_port)
    assert after['allow'] > before['allow'], (backend, kind, family, proto, before, after)
    # Same destination, ordinary GID: must hit DROP, not a public endpoint exemption.
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    with socket.socket(af, socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM) as normal:
        normal.settimeout(.15)
        address = '127.0.0.1' if family == 4 else '::1'
        try:
            if proto == 'tcp':
                normal.connect((address, remote_port))
                raise AssertionError('ordinary OUTPUT reached a core-only endpoint')
            normal.sendto(b'ordinary-output', (address, remote_port))
        except (TimeoutError, PermissionError):
            pass
    blocked = counters(backend, family, proto, remote_port)
    assert blocked['drop'] > after['drop'], (backend, before, after, blocked)
    print(f'PASS ACTUAL_CORE {backend} {kind} IPv{family} outer={proto}/{remote_port} core-allow + ordinary-drop')


def serve():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(MARKER)

        def log_message(self, *args):
            pass

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    server = Server(('::', 18080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as echo:
        echo.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        echo.bind(('::', 18083))
        while True:
            packet, address = echo.recvfrom(4096)
            echo.sendto(packet, address)


def ttl(family):
    binary = 'iptables' if family == 4 else 'ip6tables'
    command([binary, '-t', 'filter', '-C', 'OUTPUT', '-m', 'ttl' if family == 4 else 'hl',
             '--ttl-eq' if family == 4 else '--hl-eq', '1', '-p', 'tcp',
             '-d', '127.0.0.1' if family == 4 else '::1', '--dport', '34444', '-j', 'DROP'])
    rows = command([binary, '-t', 'filter', '-nvxL', 'OUTPUT']).splitlines()[2:]
    matches = [r for r in rows if 'dpt:34444' in r and ('ttl' if family == 4 else 'hl') in r.lower()]
    assert any(r.split()[2] == 'DROP' and int(r.split()[0]) > 0 for r in matches), rows
    print(f'PASS actual FakeTCP IPv{family} TTL/HL filter DROP counter despite GID route exemption')


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve()
    elif sys.argv[1] in ('identity-add', 'identity-remove'):
        identity(sys.argv[2], sys.argv[1] == 'identity-add')
    elif sys.argv[1] == 'ttl':
        ttl(int(sys.argv[2]))
    else:
        traffic(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], int(sys.argv[6]))
