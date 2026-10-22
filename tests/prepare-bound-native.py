"""Test-only official binary packages, extracted into /tmp; never run maintainer scripts."""
import gzip
import hashlib
import io
import json
import os
import tarfile
import urllib.request

root = '/tmp/native'
os.makedirs(root, exist_ok=True)
indexes = {}
records = []


def download(url, expected=None):
    data = urllib.request.urlopen(url, timeout=90).read()
    checksum = hashlib.sha256(data).hexdigest()
    if expected:
        assert checksum == expected, (url, checksum)
    return data, checksum


for release in ('23.05.5', '24.10.0'):
    packages = {}
    for feed in ('base', 'packages'):
        url = f'https://downloads.openwrt.org/releases/{release}/packages/x86_64/{feed}/'
        raw, _ = download(url + 'Packages.gz')
        for part in gzip.decompress(raw).decode().split('\n\n'):
            fields = dict(line.split(': ', 1) for line in part.splitlines()
                          if ': ' in line and not line.startswith(' '))
            if 'Package' in fields:
                fields['url'] = url
                packages[fields['Package']] = fields
    indexes[release] = packages

seen = set()


def extract(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        member = next(x for x in archive.getmembers() if x.name.endswith('data.tar.gz'))
        with tarfile.open(fileobj=archive.extractfile(member), mode='r:gz') as payload:
            # These are manifest-hashed official packages, inside a disposable container.
            payload.extractall(root, filter='fully_trusted')


def install(name, release):
    if name in ('libc', 'libpthread', 'librt', 'libgcc', 'liblua5.1.5', 'shadowsocks-libev-config'):
        return
    if (name, release) in seen:
        return
    seen.add((name, release))
    package = indexes[release][name]
    for dependency in package.get('Depends', '').split(', '):
        if dependency:
            install(dependency.split(' ')[0], release)
    data, _ = download(package['url'] + package['Filename'], package['SHA256sum'])
    extract(data)
    records.append({key: package[key] for key in ('Package', 'Version', 'SHA256sum')})


for package in ('shadowsocks-libev-ss-redir', 'shadowsocks-libev-ss-local', 'shadowsocks-libev-ss-server'):
    assert indexes['23.05.5'][package]['Version'] == '3.3.5-11'
    install(package, '23.05.5')
for package in ('uci', 'libuci-lua'):
    install(package, '24.10.0')
url = 'https://downloads.immortalwrt.org/releases/24.10.0/packages/x86_64/packages/ipt2socks_1.1.4-r2_x86_64.ipk'
data, checksum = download(url, 'a0a5ba66e14f8d41e5fc7e9d51ad2862876b0527fed2b9f00ad6a0b6db3deee6')
extract(data)
records.append(dict(Package='ipt2socks', Version='1.1.4-r2', SHA256sum=checksum))
url = 'https://github.com/HyNetworks/hysteria/releases/download/v1.3.5/hysteria-linux-amd64'
data, checksum = download(url, '41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d')
with open('/tmp/hysteria', 'wb') as output:
    output.write(data)
os.chmod('/tmp/hysteria', 0o755)
records.append(dict(Package='hysteria', Version='1.3.5', SHA256sum=checksum))
with open('/tmp/native-packages.json', 'w') as output:
    json.dump(records, output, indent=2)
print(json.dumps(records, indent=2))
