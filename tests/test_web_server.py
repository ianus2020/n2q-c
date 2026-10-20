"""The loopback browser-test host starts and serves headers without reverse DNS."""
from functools import partial
import http.client
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('test_web_host',ROOT/'scripts/serve-web.py')
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class WebHost(unittest.TestCase):
    def test_startup_and_headers_without_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'index.html').write_text('public browser fixture')
            with mock.patch.object(socket,'getfqdn',side_effect=AssertionError('reverse DNS unavailable')):
                server=host.LocalHTTPServer(('127.0.0.1',0),partial(host.Handler,directory=directory))
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            try:
                self.assertEqual(server.server_name,'127.0.0.1')
                self.assertGreater(server.server_port,0)
                thread.start()
                for method in ('GET','HEAD'):
                    connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                    try:
                        connection.request(method,'/')
                        response=connection.getresponse()
                        self.assertEqual(response.status,200)
                        self.assertEqual(response.getheader('Content-Security-Policy'),host.CSP)
                        self.assertEqual(response.getheader('X-Content-Type-Options'),'nosniff')
                        self.assertEqual(response.getheader('Cache-Control'),'no-store')
                        self.assertEqual(response.read(),b'' if method=='HEAD' else b'public browser fixture')
                    finally:connection.close()
            finally:
                if thread.is_alive():server.shutdown()
                server.server_close()
                if thread.ident is not None:thread.join(timeout=3)


if __name__=='__main__':unittest.main()
