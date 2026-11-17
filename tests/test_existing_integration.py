import importlib.util
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import unittest
import threading
import urllib.error
import urllib.request
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('existing', os.environ.get('SMARTDNS_INTEGRATION_HELPER', str(Path(__file__).resolve().parents[1] / 'smartdns-existing.py')))
existing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(existing)


class Reader:
    def __init__(self, data):
        self.data = data

    def recv(self, size):
        result, self.data = self.data[:size], self.data[size:]
        return result


def hello(hostname):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ssl.create_default_context().wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class ExistingIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'UNIX socket lifecycle requires Linux')
    def test_only_a_refused_unix_socket_is_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fallback.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            with self.assertRaises(ValueError):
                existing.clear_stale_unix_socket(path)
            self.assertTrue(path.exists())
            server.close()
            existing.clear_stale_unix_socket(path)
            self.assertFalse(path.exists())
            path.write_text('not a socket')
            with self.assertRaises(ValueError):
                existing.clear_stale_unix_socket(path)
            self.assertEqual(path.read_text(), 'not a socket')

    def test_secret_authorization_endpoint(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('SMARTDNS_TEST_TMPDIR')) as folder:
            runtime = existing.Runtime({'clients_file': str(Path(folder) / 'clients.json'), 'domains': [], 'token': 'test-secret'})
            server = existing.ThreadingHTTPServer(('127.0.0.1', 0), existing.AuthHandler)
            server.runtime = runtime
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = 'http://127.0.0.1:' + str(server.server_port)
                for path, address, status in [('/auth/wrong', '8.8.4.4', 404), ('/auth/test-secret', '127.0.0.1', 400)]:
                    request = urllib.request.Request(base + path, headers={'X-SmartDNS-Client': address})
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request)
                    self.assertEqual(error.exception.code, status)
                self.assertFalse(runtime.authorized('8.8.4.4'))
                request = urllib.request.Request(base + '/auth/test-secret', headers={'X-SmartDNS-Client': '8.8.4.4'})
                with urllib.request.urlopen(request) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                self.assertTrue(runtime.authorized('8.8.4.4'))
            finally:
                server.shutdown()
                server.server_close()
    def test_real_clienthello_and_fragmentation(self):
        wire = hello('api.example.com')
        self.assertEqual(existing.client_hello(Reader(wire)), (wire, 'api.example.com'))
        body = wire[5:]
        fragmented = wire[:3] + struct.pack('!H', 7) + body[:7] + wire[:3] + struct.pack('!H', len(body) - 7) + body[7:]
        self.assertEqual(existing.client_hello(Reader(fragmented)), (fragmented, 'api.example.com'))

    def test_malformed_and_truncated_clienthello(self):
        for data in [b'GET / HTTP/1.0\r\n', b'\x16\x03\x01\xff\xff', hello('example.com')[:10]]:
            with self.assertRaises((ValueError, EOFError)):
                existing.client_hello(Reader(data))

    def test_domain_boundaries_and_provider_exclusion(self):
        domains = existing.parse_domains('0.0.0.0 example.com api.example.com\n127.0.0.1 cdn.test.net\n!bad\n', 'dns.cdn.test.net')
        self.assertEqual(domains, ['example.com'])
        self.assertTrue(existing.domain_matches('api.example.com', domains))
        self.assertFalse(existing.domain_matches('notexample.com', domains))
        self.assertFalse(existing.domain_matches('example.com.evil.net', domains))

    def test_managed_rules_preserve_existing_rules_and_are_idempotent(self):
        original = ['||ads.example^', '@@||safe.example^']
        generated = existing.managed_rules(original, ['example.com'], '192.0.2.25')
        self.assertEqual(generated[:2], original)
        self.assertEqual(existing.managed_rules(generated, ['example.com'], '192.0.2.25'), generated)
        self.assertIn('||example.com^$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.25', generated)
        self.assertIn('||example.com^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR', generated)

    def test_authorization_expiry_and_restart_persistence(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('SMARTDNS_TEST_TMPDIR')) as folder:
            config = {'clients_file': str(Path(folder) / 'clients.json'), 'domains': ['example.com']}
            runtime = existing.Runtime(config)
            with patch.object(existing.time, 'time', return_value=1000):
                self.assertEqual(runtime.authorize('8.8.4.4'), 87400)
                self.assertTrue(runtime.authorized('8.8.4.4'))
                self.assertTrue(existing.Runtime(config).authorized('8.8.4.4'))
            with patch.object(existing.time, 'time', return_value=87400):
                self.assertFalse(runtime.authorized('8.8.4.4'))
            for address in ['127.0.0.1', '10.0.0.1', '::1', 'not-an-ip']:
                with self.assertRaises(ValueError):
                    runtime.authorize(address)

    def test_nginx_server_blocks_ignore_quoted_braces(self):
        text = 'server { listen 80; location ~ "a{1}" { return 404; } }\nserver { listen unix:/tmp/site ssl; }'
        blocks = list(existing.server_blocks(text))
        self.assertEqual(len(blocks), 2)
        self.assertIn('listen 80', text[slice(*blocks[0])])
        self.assertIn('listen unix:', text[slice(*blocks[1])])

    def test_independent_dns_rejects_private_addresses(self):
        class DNS:
            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def settimeout(self, timeout):
                pass

            def connect(self, address):
                pass

            def send(self, packet):
                self.query = packet

            def recv(self, size):
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + ipaddress.IPv4Address('10.0.0.1').packed
                return self.query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + self.query[12:] + answer
        with patch.object(existing.socket, 'socket', DNS):
            with self.assertRaises(OSError):
                existing.resolve_public_ipv4('example.com')


if __name__ == '__main__':
    unittest.main()
