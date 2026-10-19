"""Loopback startup must not depend on external reverse DNS."""
import http.server
import http.client
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.local_stand.tls import TLSHTTPServer, server_context
from tools.local_stand.pki import create


class TLSStartup(unittest.TestCase):
    def test_bind_uses_numeric_address_without_reverse_dns(self):
        with mock.patch.object(socket, 'getfqdn', side_effect=AssertionError('DNS is unavailable')):
            server = TLSHTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler,
                                   ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        try:
            self.assertEqual(server.server_name, '127.0.0.1')
            self.assertEqual(server.server_port, server.server_address[1])
            self.assertGreater(server.server_port, 0)
        finally:
            server.server_close()


class TLSDeadlines(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.pki = create(Path(cls.temp.name)/'pki')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.end_headers()
        self.server = TLSHTTPServer(('127.0.0.1', 0), Handler,
                                    server_context(str(self.pki/'server.pem'), str(self.pki/'server.key')),
                                    workers=1, request_timeout=0.4)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.context = ssl.create_default_context(cafile=str(self.pki/'ca.pem'))
        self.context.verify_flags |= ssl.VERIFY_X509_STRICT

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def connect(self):
        raw = socket.create_connection(self.server.server_address, timeout=2)
        try:
            return self.context.wrap_socket(raw, server_hostname='localhost')
        except Exception:
            raw.close()
            raise

    def assert_recovered(self):
        deadline = time.monotonic()+2
        while time.monotonic() < deadline:
            conn = http.client.HTTPSConnection(*self.server.server_address, context=self.context, timeout=1)
            try:
                conn.request('GET', '/')
                self.assertEqual(conn.getresponse().status, 204)
                return
            except (OSError, http.client.HTTPException):
                time.sleep(0.02)
            finally:
                conn.close()
        self.fail('server did not release its worker after the request deadline')

    def test_incomplete_handshake_expires_and_worker_recovers(self):
        start = time.monotonic()
        with socket.create_connection(self.server.server_address, timeout=2) as conn:
            conn.sendall(b'\x16')
            self.assertEqual(conn.recv(256), b'')
        self.assertLess(time.monotonic()-start, 1.5)
        self.assert_recovered()

    def test_slow_headers_cannot_extend_deadline_or_exhaust_workers(self):
        with self.connect() as conn:
            start = time.monotonic()
            conn.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ')
            # A fully occupied server must reject excess connections promptly.
            with self.assertRaises((OSError, ssl.SSLError)):
                with self.connect():
                    self.fail('excess connection was admitted')
            try:
                for _ in range(15):
                    conn.sendall(b'x')
                    time.sleep(0.05)
                conn.sendall(b'\r\n\r\n')
                response = conn.recv(256)
            except OSError:
                response = b''
            self.assertEqual(response, b'')
            self.assertLess(time.monotonic()-start, 1.5)
        self.assert_recovered()


if __name__ == '__main__':
    unittest.main()
