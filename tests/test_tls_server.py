"""Loopback startup must not depend on external reverse DNS."""
import http.server
from pathlib import Path
import socket
import ssl
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.local_stand.tls import TLSHTTPServer


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


if __name__ == '__main__':
    unittest.main()
