#!/usr/bin/env python3
"""Add SmartDNS to an existing REALITY + AdGuard stack; keep their listeners."""
import argparse
import base64
import copy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.request

CONFIG_DIR = Path('/etc/smartdns-existing')
STATE_DIR = Path('/var/lib/smartdns-existing')
RUNTIME_DIR = Path('/run/smartdns-existing')
SERVICE = 'smartdns-existing.service'
DAEMON_PATH = Path('/usr/local/libexec/smartdns-existing.py')
XRAY_DROPIN = Path('/etc/systemd/system/xray.service.d/smartdns-existing.conf')
BEGIN = '! BEGIN smartdns-existing managed rules'
END = '! END smartdns-existing managed rules'
DEFAULT_DOMAINS_URL = 'https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts'
MSG_RU = {
    'Run integration as root': 'Запустите интеграцию от root',
    'Run rollback as root': 'Запустите откат от root',
    'Invalid PROVIDER_HOSTNAME': 'Недопустимое значение PROVIDER_HOSTNAME',
    'Target domain list is empty': 'Список целевых доменов пуст',
    'Existing AdGuard TLS must already use PROVIDER_HOSTNAME': 'Существующий TLS AdGuard должен использовать PROVIDER_HOSTNAME',
    'Existing Xray and AdGuardHome services must be active': 'Существующие службы Xray и AdGuardHome должны быть активны',
    'Expected exactly one existing REALITY listener on port 443': 'Ожидался один существующий обработчик REALITY на порту 443',
    'This integration requires an existing UNIX-socket fallback with xver=1': 'Для интеграции нужен существующий fallback через UNIX-сокет с xver=1',
    'Existing REALITY serverNames must include PROVIDER_HOSTNAME': 'Список serverNames REALITY должен содержать PROVIDER_HOSTNAME',
    'Cannot uniquely identify the existing hostname TLS server in Nginx; set NGINX_SITE': 'Не удалось однозначно найти TLS-сервер имени хоста в Nginx; задайте NGINX_SITE',
    'Existing DoH endpoint did not return a DNS response': 'Существующий DoH не вернул ответ DNS',
    'Existing DoT endpoint did not return a DNS response': 'Существующий DoT не вернул ответ DNS',
    'Existing fallback path is not a UNIX socket': 'Существующий путь fallback не является UNIX-сокетом',
    'Another process already owns the Nginx fallback socket': 'Сокет fallback Nginx уже принадлежит работающему процессу',
    'Fallback service did not start': 'Служба fallback не запустилась',
    'Existing DoH endpoint failed after integration': 'Существующий DoH не работает после интеграции',
    'Target domain did not rewrite to the VPS': 'Целевой домен не перенаправлен на VPS',
    'Existing DoT endpoint did not apply the target rewrite': 'Существующий DoT не применил перенаправление целевого домена',
    'AAAA/HTTPS response suppression failed': 'Не удалось подавить ответы AAAA/HTTPS',
    'Unauthenticated target SNI was accepted': 'Целевой SNI был принят без авторизации',
    'Integration service is not active: ': 'Служба интеграции не активна: ',
    'Integration already exists. Use --info or --rollback; do not run the fresh installer.': 'Интеграция уже выполнена. Используйте --info или --rollback; не запускайте новую установку.',
    'SmartDNS integrated with the existing REALITY and AdGuard listeners.': 'SmartDNS интегрирован с существующими обработчиками REALITY и AdGuard.',
    'Existing Xray clients, routing, AdGuard TLS ports and settings are preserved.': 'Клиенты и маршрутизация Xray, порты TLS и настройки AdGuard сохранены.',
    'Read the private authorization URL in': 'Секретная ссылка авторизации находится в',
    'Backups:': 'Резервные копии:',
    'Previous Xray/AdGuard/Nginx configurations restored.': 'Предыдущие конфигурации Xray/AdGuard/Nginx восстановлены.',
    'SmartDNS integration stopped:': 'Интеграция SmartDNS остановлена:',
}
MSG_EN = {key: key for key in MSG_RU}
MSG_RU.update({
    'Authorization enabled (24-hour secret link).': 'Авторизация включена (секретная ссылка на 24 часа).',
    'Authorization disabled; all client IPs can proxy the managed target domains.': 'Авторизация отключена; все клиентские IP могут проксировать управляемые целевые домены.',
    'Existing integration hostname/IP do not match the supplied inputs.': 'Имя хоста/IP существующей интеграции не совпадают с переданными значениями.',
})
MSG_EN.update({key: key for key in MSG_RU})


def tr(text):
    table = MSG_RU if os.environ.get('SCRIPT_LANG', 'en') == 'ru' else MSG_EN
    for key, value in table.items():
        if text.startswith(key):
            return value + text[len(key):]
    return text


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode:
        detail = result.stderr.decode(errors='replace') if isinstance(result.stderr, bytes) else (result.stderr or '')
        detail = re.sub(r'/auth/[A-Za-z0-9_-]+', '/auth/[redacted]', detail)
        raise RuntimeError(f'{Path(args[0]).name} check failed: {detail[-1500:]}')
    return result


def clear_stale_unix_socket(path):
    path = Path(path)
    if not path.exists():
        return
    if not stat.S_ISSOCK(path.lstat().st_mode):
        raise ValueError('Existing fallback path is not a UNIX socket')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            path.unlink()
            return
    raise ValueError('Another process already owns the Nginx fallback socket')


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise EOFError('Connection closed')
        result.extend(data)
    return bytes(result)


def client_hello(sock):
    """Return original TLS records plus SNI; support fragmented ClientHello."""
    wire = bytearray()
    handshake = bytearray()
    while len(wire) < 131072:
        header = exact(sock, 5)
        if header[0] != 22 or header[1] != 3:
            raise ValueError('Not a TLS handshake')
        length = int.from_bytes(header[3:5], 'big')
        if not 0 < length <= 18432:
            raise ValueError('Invalid TLS record length')
        body = exact(sock, length)
        wire.extend(header + body)
        handshake.extend(body)
        if len(handshake) < 4:
            continue
        total = 4 + int.from_bytes(handshake[1:4], 'big')
        if handshake[0] != 1 or total > 65539:
            raise ValueError('Invalid ClientHello')
        if len(handshake) < total:
            continue
        data = bytes(handshake[4:total])
        cursor = 34
        cursor += 1 + data[cursor]
        cursor += 2 + int.from_bytes(data[cursor:cursor + 2], 'big')
        cursor += 1 + data[cursor]
        if cursor == len(data):
            return bytes(wire), ''
        end = cursor + 2 + int.from_bytes(data[cursor:cursor + 2], 'big')
        cursor += 2
        if end != len(data):
            raise ValueError('Invalid extensions length')
        while cursor + 4 <= end:
            kind, length = struct.unpack('!HH', data[cursor:cursor + 4])
            extension = data[cursor + 4:cursor + 4 + length]
            if len(extension) != length:
                raise ValueError('Truncated TLS extension')
            if kind == 0:
                if len(extension) < 5 or int.from_bytes(extension[:2], 'big') != len(extension) - 2:
                    raise ValueError('Invalid SNI extension')
                position = 2
                while position + 3 <= len(extension):
                    name_type = extension[position]
                    name_size = int.from_bytes(extension[position + 1:position + 3], 'big')
                    name = extension[position + 3:position + 3 + name_size]
                    if len(name) != name_size:
                        raise ValueError('Truncated SNI')
                    if name_type == 0:
                        hostname = name.decode('ascii').lower().rstrip('.')
                        if not valid_domain(hostname):
                            raise ValueError('Invalid SNI hostname')
                        return bytes(wire), hostname
                    position += 3 + name_size
            cursor += 4 + length
        return bytes(wire), ''
    raise ValueError('ClientHello too large')


def valid_domain(domain):
    return len(domain) <= 253 and bool(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', domain))


def domain_matches(hostname, domains):
    return any(hostname == domain or hostname.endswith('.' + domain) for domain in domains)


def parse_domains(text, hostname):
    domains = set()
    for line in text.splitlines():
        fields = line.split('#', 1)[0].strip().split()
        if not fields:
            continue
        try:
            ipaddress.ip_address(fields[0])
            fields = fields[1:]
        except ValueError:
            pass
        for field in fields:
            domain = field.lower().rstrip('.')
            if valid_domain(domain) and domain != hostname and not hostname.endswith('.' + domain):
                domains.add(domain)
    # Domain rewrite rules include descendants, so retain only the parent rule.
    result = []
    for domain in sorted(domains, key=lambda item: (item.count('.'), item)):
        if not domain_matches(domain, result):
            result.append(domain)
    if not result:
        raise ValueError('Target domain list is empty')
    return result


def dns_name_end(packet, offset):
    for _ in range(128):
        length = packet[offset]
        offset += 1
        if length & 0xC0 == 0xC0:
            return offset + 1
        if length == 0:
            return offset
        if length > 63:
            raise ValueError('Invalid DNS name')
        offset += length
    raise ValueError('Invalid DNS name length')


def resolve_public_ipv4(hostname, resolvers=('1.1.1.1', '8.8.8.8')):
    transaction = secrets.randbelow(65536)
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in hostname.split('.')) + b'\0\0\1\0\1'
    request = struct.pack('!HHHHHH', transaction, 0x0100, 1, 0, 0, 0) + question
    for resolver in resolvers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(4)
                client.connect((resolver, 53))
                client.send(request)
                packet = client.recv(65535)
            ident, flags, queries, answers, _, _ = struct.unpack('!HHHHHH', packet[:12])
            if ident != transaction or flags & 0x820F != 0x8000 or queries != 1:
                continue
            cursor = dns_name_end(packet, 12) + 4
            addresses = []
            for _ in range(answers):
                cursor = dns_name_end(packet, cursor)
                kind, dns_class, _, size = struct.unpack('!HHIH', packet[cursor:cursor + 10])
                cursor += 10
                if kind == 1 and dns_class == 1 and size == 4:
                    address = ipaddress.IPv4Address(packet[cursor:cursor + size])
                    if address.is_global:
                        addresses.append(str(address))
                cursor += size
            if addresses:
                return list(dict.fromkeys(addresses))
        except (OSError, ValueError, IndexError, struct.error):
            continue
    raise OSError('No public IPv4 address from independent DNS resolvers')


class Runtime:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.clients_file = Path(config['clients_file'])
        self.clients = (json.loads(self.clients_file.read_text())
                        if config.get('authorization_required', True) and self.clients_file.exists() else {})
        self.domains = set(config['domains'])
        self.limit = threading.BoundedSemaphore(128)

    def authorized(self, address):
        if not self.config.get('authorization_required', True):
            return True
        with self.lock:
            return self.clients.get(address, 0) > time.time()

    def authorize(self, address):
        address = str(ipaddress.ip_address(address))
        if not ipaddress.ip_address(address).is_global:
            raise ValueError('A public client address is required')
        with self.lock:
            now = time.time()
            self.clients = {key: value for key, value in self.clients.items() if value > now}
            if len(self.clients) >= 2048 and address not in self.clients:
                raise ValueError('Client authorization limit reached')
            expires = int(now + 86400)
            self.clients[address] = expires
            staged = self.clients_file.with_suffix('.new')
            staged.write_text(json.dumps(self.clients))
            staged.chmod(0o600)
            staged.replace(self.clients_file)
        return expires


class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        runtime = self.server.runtime
        if not runtime.config.get('authorization_required', True) or not hmac.compare_digest(self.path, '/auth/' + runtime.config['token']):
            self.send_error(404)
            return
        try:
            address = self.headers.get('X-SmartDNS-Client', '')
            expires = runtime.authorize(address)
        except ValueError:
            self.send_error(400)
            return
        body = f'SmartDNS authorized for {address} until {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires))}.\n'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        # Never log the secret authorization URL.
        pass


class FallbackHandler(socketserver.BaseRequestHandler):
    def handle(self):
        runtime = self.server.runtime
        if not runtime.limit.acquire(blocking=False):
            return
        try:
            self.request.settimeout(10)
            header = bytearray()
            while not header.endswith(b'\r\n') and len(header) < 108:
                header.extend(exact(self.request, 1))
            fields = header.decode('ascii').split()
            if len(fields) != 6 or fields[:2] not in [['PROXY', 'TCP4'], ['PROXY', 'TCP6']]:
                raise ValueError('Trusted PROXY v1 header required')
            address = str(ipaddress.ip_address(fields[2]))
            initial, hostname = client_hello(self.request)
            if domain_matches(hostname, runtime.domains):
                if not runtime.authorized(address):
                    return
                destination = None
                for target_ip in resolve_public_ipv4(hostname):
                    if target_ip == runtime.config['public_ipv4']:
                        continue
                    try:
                        destination = socket.create_connection((target_ip, 443), timeout=6)
                        break
                    except OSError:
                        continue
                if destination is None:
                    return
            else:
                destination = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                destination.settimeout(6)
                destination.connect(runtime.config['original_fallback'])
                destination.sendall(header)
            with destination:
                destination.sendall(initial)
                self.request.settimeout(30)
                destination.settimeout(30)
                while True:
                    readable, _, _ = select.select([self.request, destination], [], [], 120)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        (destination if source is self.request else self.request).sendall(data)
        except (OSError, EOFError, ValueError, IndexError, UnicodeError, struct.error):
            return
        finally:
            runtime.limit.release()


def serve(config_file):
    class FallbackServer(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
    runtime = Runtime(json.loads(Path(config_file).read_text()))
    socket_path = Path(runtime.config['socket'])
    if socket_path.exists():
        socket_path.unlink()
    relay = FallbackServer(str(socket_path), FallbackHandler)
    socket_path.chmod(0o660)
    relay.runtime = runtime
    http = ThreadingHTTPServer(('127.0.0.1', runtime.config['auth_port']), AuthHandler)
    http.runtime = runtime
    threading.Thread(target=http.serve_forever, daemon=True).start()
    relay.serve_forever()


def service_state(service):
    return subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True).stdout.strip()


def server_blocks(text):
    """Locate complete server blocks without counting braces in strings/comments."""
    for match in re.finditer(r'\bserver\s*\{', text):
        position = match.end()
        depth, quote, comment, escape = 1, None, False, False
        while position < len(text):
            char = text[position]
            if comment:
                comment = char != '\n'
            elif escape:
                escape = False
            elif char == '\\':
                escape = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ['"', "'"]:
                quote = char
            elif char == '#':
                comment = True
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    yield match.start(), position + 1
                    break
            position += 1


def managed_rules(existing, domains, address):
    result, inside = [], False
    for rule in existing:
        if rule == BEGIN:
            inside = True
        elif rule == END:
            inside = False
        elif not inside:
            result.append(rule)
    result.append(BEGIN)
    for domain in domains:
        result += [f'||{domain}^$dnstype=A,dnsrewrite=NOERROR;A;{address}',
                   f'||{domain}^$dnstype=AAAA,dnsrewrite=NOERROR',
                   f'||{domain}^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR']
    result.append(END)
    return result


def restore(config):
    run('systemctl', 'stop', SERVICE)
    run('systemctl', 'stop', 'AdGuardHome')
    XRAY_DROPIN.unlink(missing_ok=True)
    for item in config['backups']:
        shutil.copy2(item['backup'], item['path'])
    run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', 'AdGuardHome', 'xray')
    if config['nginx_was_active']:
        run('systemctl', 'restart', 'nginx')
    else:
        subprocess.run(['systemctl', 'stop', 'nginx'], capture_output=True)
    subprocess.run(['systemctl', 'disable', SERVICE], capture_output=True)


def https_request(hostname, port, path, body=None):
    import http.client
    connection = http.client.HTTPSConnection(hostname, port, timeout=12)
    try:
        headers = {'Content-Type': 'application/dns-message'} if body else {}
        connection.request('POST' if body else 'GET', path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        if response.status != 200:
            raise RuntimeError(f'HTTPS verification failed: status {response.status}')
        return data
    finally:
        connection.close()


def dns_question(domain, record_type=1):
    name = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\0'
    return struct.pack('!HHHHHH', 0x1742, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', record_type, 1)


def dot_request(hostname, port, question):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=12) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as encrypted:
            encrypted.sendall(struct.pack('!H', len(question)) + question)
            size = struct.unpack('!H', exact(encrypted, 2))[0]
            return exact(encrypted, size)


def connection_info(config):
    host = config['hostname']
    lines = [f"Existing DoH: https://{host}:{config['doh_port']}/dns-query",
             f"Existing DoT: {host}:{config.get('dot_port', 853)}"]
    if config.get('authorization_required', True):
        lines += [f"Authorize this client IP for 24 hours: https://{host}/auth/{config['token']}",
                  'Open the authorization URL from the same network that uses AdGuard DNS.']
    else:
        lines += ['Authorization disabled; all client IPs can proxy the managed target domains.']
    lines += [f"Managed domain rules: {len(config['domains'])}",
              f"Backup: {Path(config['backups'][0]['backup']).parent}",
              'Rollback: python3 /usr/local/libexec/smartdns-existing.py --rollback']
    return '\n'.join(lines) + '\n'


def update_existing_mode(config_file, config, authorization_required):
    daemon = DAEMON_PATH
    info = STATE_DIR / 'connection-info.txt'
    old_config, old_code = config_file.read_bytes(), daemon.read_bytes()
    old_info = info.read_bytes() if info.exists() else None
    if 'dot_port' not in config and old_info:
        port = re.search(rb'^Existing DoT: .+:(\d+)$', old_info, re.MULTILINE)
        if port:
            config['dot_port'] = int(port.group(1))
    metadata = config_file.stat()

    def write_config(data):
        staged = config_file.with_suffix('.new')
        staged.write_bytes(data)
        staged.chmod(metadata.st_mode & 0o777)
        os.chown(staged, metadata.st_uid, metadata.st_gid)
        staged.replace(config_file)

    config['authorization_required'] = authorization_required
    try:
        if Path(__file__).resolve() != daemon.resolve():
            shutil.copyfile(Path(__file__).resolve(), daemon)
        write_config(json.dumps(config, indent=2).encode())
        run('systemctl', 'restart', SERVICE)
        if service_state(SERVICE) != 'active':
            raise RuntimeError('Integration service is not active: ' + SERVICE)
        info.write_text(connection_info(config))
        info.chmod(0o600)
    except Exception:
        write_config(old_config)
        daemon.write_bytes(old_code)
        if old_info is not None:
            info.write_bytes(old_info)
        else:
            info.unlink(missing_ok=True)
        run('systemctl', 'restart', SERVICE)
        raise
    print(tr('Authorization enabled (24-hour secret link).' if authorization_required else
             'Authorization disabled; all client IPs can proxy the managed target domains.'))


def install(hostname, public_ipv4, authorization_required=True):
    import pwd
    import yaml
    if os.geteuid() != 0:
        raise ValueError('Run integration as root')
    if not valid_domain(hostname):
        raise ValueError('Invalid PROVIDER_HOSTNAME')
    public_ipv4 = str(ipaddress.IPv4Address(public_ipv4))
    config_file = CONFIG_DIR / 'config.json'
    if config_file.exists():
        config = json.loads(config_file.read_text())
        if config['hostname'] != hostname or config['public_ipv4'] != public_ipv4:
            raise ValueError('Existing integration hostname/IP do not match the supplied inputs.')
        update_existing_mode(config_file, config, authorization_required)
        return
    if XRAY_DROPIN.exists():
        raise ValueError('A pre-existing SmartDNS Xray drop-in requires inspection before installation')
    xray_path = Path(os.environ.get('XRAY_CONFIG', '/etc/xray/config.json')).resolve()
    adguard_path = Path(os.environ.get('ADGUARD_CONFIG', '/opt/AdGuardHome/AdGuardHome.yaml')).resolve()
    xray = json.loads(xray_path.read_text())
    adguard = yaml.safe_load(adguard_path.read_text())
    tls = adguard.get('tls', {})
    if not tls.get('enabled') or tls.get('server_name') != hostname:
        raise ValueError('Existing AdGuard TLS must already use PROVIDER_HOSTNAME')
    if service_state('xray') != 'active' or service_state('AdGuardHome') != 'active':
        raise ValueError('Existing Xray and AdGuardHome services must be active')
    inbounds = [item for item in xray.get('inbounds', []) if item.get('port') == 443 and item.get('streamSettings', {}).get('security') == 'reality']
    if len(inbounds) != 1:
        raise ValueError('Expected exactly one existing REALITY listener on port 443')
    reality = inbounds[0]['streamSettings']['realitySettings']
    original_fallback = reality.get('target', reality.get('dest'))
    if not isinstance(original_fallback, str) or not original_fallback.startswith('/') or reality.get('xver') != 1:
        raise ValueError('This integration requires an existing UNIX-socket fallback with xver=1')
    if hostname not in reality.get('serverNames', []):
        raise ValueError('Existing REALITY serverNames must include PROVIDER_HOSTNAME')
    candidates = [Path(os.environ['NGINX_SITE'])] if os.environ.get('NGINX_SITE') else list(Path('/etc/nginx/sites-enabled').glob('*'))
    sites = []
    for path in candidates:
        if path.is_file():
            text = path.read_text()
            blocks = [(a, b) for a, b in server_blocks(text) if re.search(r'\bserver_name\s+' + re.escape(hostname) + r'\s*;', text[a:b]) and 'unix:' + original_fallback in text[a:b]]
            if blocks:
                sites.append((path.resolve(), text, blocks))
    if len(sites) != 1 or len(sites[0][2]) != 1:
        raise ValueError('Cannot uniquely identify the existing hostname TLS server in Nginx; set NGINX_SITE')
    site_path, site_text, blocks = sites[0]
    if os.environ.get('SMARTDNS_DOMAINS_FILE'):
        source = Path(os.environ['SMARTDNS_DOMAINS_FILE']).read_text()
    else:
        with urllib.request.urlopen(DEFAULT_DOMAINS_URL, timeout=30) as response:
            source = response.read(8 * 1024 * 1024).decode()
    domains = parse_domains(source, hostname)
    # Confirm AdGuard's existing endpoint is working before making changes.
    doh_port = int(tls['port_https'])
    if len(https_request(hostname, doh_port, '/dns-query', dns_question('example.com'))) < 12:
        raise ValueError('Existing DoH endpoint did not return a DNS response')
    dot_port = int(tls['port_dns_over_tls'])
    if len(dot_request(hostname, dot_port, dns_question('example.com'))) < 12:
        raise ValueError('Existing DoT endpoint did not return a DNS response')
    account = pwd.getpwnam('xray')
    CONFIG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(CONFIG_DIR, 0, account.pw_gid)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE_DIR, account.pw_uid, account.pw_gid)
    backup_dir = Path('/var/backups/smartdns-existing') / (time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
    backup_dir.mkdir(mode=0o700, parents=True)
    backup_dir.parent.chmod(0o700)
    backups = []
    for name, path in [('xray.json', xray_path), ('AdGuardHome.yaml', adguard_path), ('nginx-site.conf', site_path)]:
        backup = backup_dir / name
        shutil.copy2(path, backup)
        backups.append({'path': str(path), 'backup': str(backup)})
    config = {'hostname': hostname, 'public_ipv4': public_ipv4, 'original_fallback': original_fallback,
              'socket': str(RUNTIME_DIR / 'fallback.sock'), 'clients_file': str(STATE_DIR / 'clients.json'),
              'domains': domains, 'token': secrets.token_urlsafe(40), 'auth_port': 18081,
              'backups': backups, 'nginx_was_active': service_state('nginx') == 'active', 'doh_port': doh_port,
              'dot_port': dot_port, 'authorization_required': authorization_required}
    daemon = Path('/usr/local/libexec/smartdns-existing.py')
    daemon.parent.mkdir(exist_ok=True, parents=True)
    shutil.copyfile(Path(__file__).resolve(), daemon)
    daemon.chmod(0o755)
    unit = Path('/etc/systemd/system') / SERVICE
    unit.write_text(f'''[Unit]
Description=SmartDNS fallback relay and 24-hour IP authorization
After=network-online.target nginx.service
Wants=network-online.target nginx.service

[Service]
User=xray
Group=xray
ExecStart=/usr/bin/python3 {daemon} --serve --config {config_file}
Restart=on-failure
RestartSec=2
RuntimeDirectory=smartdns-existing
RuntimeDirectoryMode=0750
StateDirectory=smartdns-existing
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={STATE_DIR} {RUNTIME_DIR}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
''')
    location = CONFIG_DIR / 'auth-location.conf'
    location.write_text(f'''location = /auth/{config['token']} {{
    access_log off;
    error_log /dev/null;
    proxy_set_header X-SmartDNS-Client $proxy_protocol_addr;
    proxy_pass http://127.0.0.1:{config['auth_port']};
}}
''')
    location.chmod(0o600)
    start, end = blocks[0]
    modified_site = site_text[:end - 1] + '\n    include ' + str(location) + ';\n' + site_text[end - 1:]
    changed_xray = copy.deepcopy(xray)
    target = next(item for item in changed_xray['inbounds'] if item.get('port') == 443)['streamSettings']['realitySettings']
    target.pop('target', None)
    target['dest'] = config['socket']
    changed_adguard = copy.deepcopy(adguard)
    changed_adguard['user_rules'] = managed_rules(adguard.get('user_rules', []), domains, public_ipv4)
    # Only the fallback destination and managed DNS rules may change.
    compare = copy.deepcopy(changed_xray)
    same = next(item for item in compare['inbounds'] if item.get('port') == 443)['streamSettings']['realitySettings']
    same.clear()
    same.update(reality)
    assert compare == xray
    compare = copy.deepcopy(changed_adguard)
    compare['user_rules'] = adguard.get('user_rules', [])
    assert compare == adguard
    staged_xray = backup_dir / 'xray-proposed.json'
    staged_xray.write_text(json.dumps(changed_xray, indent=2))
    staged_xray.chmod(0o600)
    run('/usr/local/bin/xray', 'run', '-test', '-config', str(staged_xray), env=dict(os.environ, XRAY_LOCATION_ASSET='/etc/xray'))
    staged_adguard = backup_dir / 'AdGuardHome-proposed.yaml'
    staged_adguard.write_text(yaml.safe_dump(changed_adguard, sort_keys=False, allow_unicode=True))
    staged_adguard.chmod(0o600)
    run('/usr/local/bin/AdGuardHome', '--check-config', '--config', str(staged_adguard), '--work-dir', str(adguard_path.parent))
    config_file.write_text(json.dumps(config, indent=2))
    config_file.chmod(0o640)
    os.chown(config_file, 0, account.pw_gid)
    activated = False
    try:
        site_path.write_text(modified_site)
        run('/usr/local/bin/nginx', '-t')
        if not config['nginx_was_active']:
            clear_stale_unix_socket(original_fallback)
        XRAY_DROPIN.parent.mkdir(exist_ok=True)
        XRAY_DROPIN.write_text('[Unit]\nWants=smartdns-existing.service\nAfter=smartdns-existing.service\n')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', SERVICE)
        for _ in range(30):
            if Path(config['socket']).exists():
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Fallback service did not start')
        if config['nginx_was_active']:
            run('systemctl', 'reload', 'nginx')
        else:
            run('systemctl', 'reset-failed', 'nginx')
            run('systemctl', 'start', 'nginx')
        activated = True
        xray_path.write_text(json.dumps(changed_xray, indent=2))
        run('systemctl', 'restart', 'xray')
        # Stop AdGuard before updating its file, so shutdown cannot overwrite it.
        run('systemctl', 'stop', 'AdGuardHome')
        adguard_path.write_text(yaml.safe_dump(changed_adguard, sort_keys=False, allow_unicode=True))
        run('systemctl', 'start', 'AdGuardHome')
        for _ in range(30):
            try:
                if len(https_request(hostname, doh_port, '/dns-query', dns_question('example.com'))) >= 12:
                    break
            except (OSError, RuntimeError):
                time.sleep(0.3)
        else:
            raise RuntimeError('Existing DoH endpoint failed after integration')
        if authorization_required:
            https_request(hostname, 443, '/auth/' + config['token'])
        probe_domain = next((item for item in ['chatgpt.com', 'api.openai.com', 'openai.com'] if domain_matches(item, domains)), domains[0])
        answer = https_request(hostname, doh_port, '/dns-query', dns_question(probe_domain))
        if ipaddress.IPv4Address(public_ipv4).packed not in answer:
            raise RuntimeError('Target domain did not rewrite to the VPS')
        answer = dot_request(hostname, dot_port, dns_question(probe_domain))
        if ipaddress.IPv4Address(public_ipv4).packed not in answer:
            raise RuntimeError('Existing DoT endpoint did not apply the target rewrite')
        for kind in [28, 65]:
            for answer in [https_request(hostname, doh_port, '/dns-query', dns_question(probe_domain, kind)),
                           dot_request(hostname, dot_port, dns_question(probe_domain, kind))]:
                if len(answer) < 12 or answer[3] & 15 or answer[6:8] != b'\0\0':
                    raise RuntimeError('AAAA/HTTPS response suppression failed')
        # A loopback client has not authorized; its target TLS connection must fail.
        if authorization_required:
            try:
                with socket.create_connection(('127.0.0.1', 443), timeout=5) as raw:
                    with ssl.create_default_context().wrap_socket(raw, server_hostname=probe_domain):
                        raise RuntimeError('Unauthenticated target SNI was accepted')
            except (ssl.SSLError, ConnectionError, TimeoutError):
                pass
        else:
            with socket.create_connection(('127.0.0.1', 443), timeout=12) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=probe_domain):
                    pass
        context = ssl.create_default_context()
        with socket.create_connection((public_ipv4, 443), timeout=12) as raw:
            with context.wrap_socket(raw, server_hostname=probe_domain):
                pass
        for service in ['xray', 'AdGuardHome', 'nginx', SERVICE]:
            if service_state(service) != 'active':
                raise RuntimeError('Integration service is not active: ' + service)
    except Exception:
        # Restore file content before restarting its owning services.
        if activated or site_path.read_text() != site_text:
            restore(config)
        config_file.unlink(missing_ok=True)
        raise
    info = STATE_DIR / 'connection-info.txt'
    info.write_text(connection_info(config))
    info.chmod(0o600)
    print('PASS: existing DoH/DoT TLS, target rewrites, AAAA/HTTPS suppression and selected authorization policy')
    print(tr('SmartDNS integrated with the existing REALITY and AdGuard listeners.'))
    print(tr('Existing Xray clients, routing, AdGuard TLS ports and settings are preserved.'))
    print(tr('Read the private authorization URL in'), info)
    print(tr('Backups:'), backup_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--info', action='store_true')
    parser.add_argument('--config', default=str(CONFIG_DIR / 'config.json'))
    parser.add_argument('--no-authorization', action='store_true', help='Allow all client IPs to proxy managed target domains; use with --install')
    args = parser.parse_args()
    if args.no_authorization and not args.install:
        parser.error('--no-authorization requires --install')
    if args.serve:
        serve(args.config)
    elif args.install:
        install(os.environ['PROVIDER_HOSTNAME'], os.environ['PUBLIC_IPV4'], not args.no_authorization)
    elif args.rollback:
        if os.geteuid() != 0:
            raise ValueError('Run rollback as root')
        restore(json.loads(Path(args.config).read_text()))
        Path(args.config).unlink()
        print(tr('Previous Xray/AdGuard/Nginx configurations restored.'))
    elif args.info:
        print((STATE_DIR / 'connection-info.txt').read_text())
    else:
        parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        # Do not print subprocess command arguments, config files or secret URLs.
        print(tr('SmartDNS integration stopped:'), tr(str(error)) if not isinstance(error, subprocess.CalledProcessError) else 'A configuration check or service operation failed; original configurations were restored when activation had begun.', file=sys.stderr)
        sys.exit(1)
