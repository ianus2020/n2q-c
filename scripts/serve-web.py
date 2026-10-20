#!/usr/bin/env python3
"""Loopback-only browser test host with the deployment's intended headers."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer

CSP="default-src 'none'; script-src 'self' blob: 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
class LocalHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # The loopback test host needs no DNS name. HTTPServer's default bind
        # calls getfqdn(), which can stall before the socket starts listening.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        for name,value in {
            "Content-Security-Policy":CSP,
            "X-Content-Type-Options":"nosniff",
            "X-Frame-Options":"DENY",
            "Referrer-Policy":"no-referrer",
            "Cross-Origin-Opener-Policy":"same-origin",
            "Cross-Origin-Embedder-Policy":"require-corp",
            "Cross-Origin-Resource-Policy":"same-origin",
            "Permissions-Policy":"camera=(), microphone=(), geolocation=()",
            "Cache-Control":"no-store",
        }.items():self.send_header(name,value)
        super().end_headers()
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--port",type=int,default=8765)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]/"impl/n2q-c-wasm/web"
    LocalHTTPServer(("127.0.0.1",args.port),partial(Handler,directory=str(root))).serve_forever()
