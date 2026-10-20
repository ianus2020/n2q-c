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

    def __init__(self, address, handler, context, workers=16, request_timeout=3):
        self.context = context
        self.slots = threading.BoundedSemaphore(workers)
        self.request_timeout = request_timeout
        super().__init__(address, handler)

    def server_bind(self):
        # HTTPServer normally performs an unbounded reverse DNS lookup here.
        # This loopback service has no use for a DNS-derived server name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

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
        deadline_socket = None
        timer = None
        timer_started = False
        try:
            request.settimeout(self.request_timeout)
            # A socket timeout alone restarts on each successful read. A peer
            # can otherwise keep a worker forever by slowly dripping headers.
            # The duplicate keeps access to the TCP connection after wrap_socket
            # transfers ownership of the original descriptor to SSLSocket.
            deadline_socket = request.dup()
            def expire():
                try:
                    deadline_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(self.request_timeout, expire)
            timer.daemon = True
            timer.start()
            timer_started = True
            wrapped = self.context.wrap_socket(request, server_side=True)
            self.finish_request(wrapped, address)
        except (ssl.SSLError, OSError, ValueError):
            pass
        finally:
            if timer is not None:
                timer.cancel()
                if timer_started:
                    timer.join()
            self.shutdown_request(wrapped if wrapped is not None else request)
            if deadline_socket is not None:
                deadline_socket.close()
            self.slots.release()


def server_context(cert, key, client_ca=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256')
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(cert, key)
    if client_ca is not None:
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        context.load_verify_locations(cafile=client_ca)
    return context
