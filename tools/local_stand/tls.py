"""Bounded TLS request workers for the local integration stand."""
import http.server
import socket
import socketserver
import ssl
import threading


class TLSHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, handler, context, workers=16):
        self.context = context
        self.slots = threading.BoundedSemaphore(workers)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        wrapped = None
        try:
            request.settimeout(3)
            wrapped = self.context.wrap_socket(request, server_side=True)
            self.finish_request(wrapped, address)
        except (ssl.SSLError, OSError, ValueError):
            pass
        finally:
            self.shutdown_request(wrapped if wrapped is not None else request)
            self.slots.release()


def server_context(cert, key, client_ca=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256')
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(cert, key)
    if client_ca is not None:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=client_ca)
    return context
