import socket
import threading
import ssl
import os
from http.server import BaseHTTPRequestHandler
from evillimiter.console import shell
from socketserver import TCPServer
from urllib.parse import urlparse
import struct
import tempfile
import subprocess
from evillimiter.common.globals import BIN_PFCTL


class TransparentProxy:
    """Handles HTTP(S) traffic redirection using PF"""

    def __init__(self, interface='0.0.0.0', port=8080):
        # Store network interface name for pfctl rules
        self.interface = interface
        # Use 0.0.0.0 for binding to accept connections on all interfaces
        self.bind_address = '0.0.0.0'
        self.port = port
        self.running = False
        self.thread = None
        self.redirect_rules = {}  # {host_ip: redirect_target or None for built-in page}
        self.portal_html = (
            "<!doctype html><html><head>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>Network Access</title></head>"
            "<body style='font-family:sans-serif;text-align:center;padding:3em'>"
            "<h1>Network Access Portal</h1>"
            "<p>This device is managed. Please contact the network administrator.</p>"
            "</body></html>"
        )

    def start(self):
        """Start the transparent proxy server"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        print(f"DEBUG: Transparent proxy started on {self.interface}:{self.port}")

    def stop(self):
        """Stop the proxy server"""
        self.running = False

    def add_redirect(self, host_ip, target_url):
        """Add redirection rule for a host"""
        self.redirect_rules[host_ip] = target_url
        print(f"DEBUG: Added redirect rule: {host_ip} -> {target_url}")

    def install_enforcement(self, host_ip, block_ipv6=None, harden=False, lockdown=False, doh_ips=None, allow_ips=None):
        """
        Install the pf rules that make DNS injection stick. Redirection itself is
        done by injecting forged DNS answers (see DNSInjector); these rules only
        *block* the target's escape routes. No rdr, no proxy.

          force-IPv4 : block the host's routable IPv6 so it can't resolve/connect over v6
          --harden   : block DoT (853) and known DoH resolver IPs -> fall back to plain DNS
          --lockdown : allow only DNS, DHCP and the redirect target(s); block everything else
        """
        rules = []

        for addr in (block_ipv6 or []):
            rules.append(f"block return out quick on {self.interface} inet6 from {addr}")
            rules.append(f"block return in quick on {self.interface} inet6 to {addr}")

        if lockdown:
            for aip in (allow_ips or []):
                rules.append(f"pass out quick on {self.interface} inet from {host_ip} to {aip}")
            rules.append(f"pass out quick on {self.interface} inet proto udp from {host_ip} to any port 53")
            rules.append(f"pass out quick on {self.interface} inet proto udp from {host_ip} to any port 67")
            rules.append(f"pass out quick on {self.interface} inet proto udp from {host_ip} to any port 68")
            rules.append(f"block return out quick on {self.interface} inet from {host_ip}")
        elif harden:
            rules.append(f"block return out quick on {self.interface} inet proto tcp from {host_ip} to any port 853")
            rules.append(f"block return out quick on {self.interface} inet proto udp from {host_ip} to any port 853")
            for ip in (doh_ips or []):
                rules.append(f"block return out quick on {self.interface} inet proto tcp from {host_ip} to {ip} port 443")
                rules.append(f"block return out quick on {self.interface} inet proto tcp from {host_ip} to {ip} port 853")

        if not rules:
            return  # plain --dns with no harden/lockdown: injection alone, nothing to block

        fd, rules_file = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(rules_file, 'w') as f:
                f.write('\n'.join(rules) + '\n')
            print("DEBUG: enforcement rules:")
            print('\n'.join(rules))
            shell.execute_suppressed(f'{BIN_PFCTL} -e')
            proc = subprocess.run([BIN_PFCTL, '-f', rules_file], capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"DEBUG: pfctl -f FAILED (exit {proc.returncode}): {proc.stderr.strip()}")
            else:
                print("DEBUG: pfctl enforcement loaded")
        finally:
            if os.path.exists(rules_file):
                os.unlink(rules_file)

    def remove_redirection(self, host_ip):
        """Remove pfctl rules for host"""
        from evillimiter.networking.utils_macos import flush_network_settings

        try:
            # Just flush all rules
            flush_network_settings(self.interface)
        except Exception as e:
            print(f"Error removing redirection: {e}")

    def _run_server(self):
        """Main server loop"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Enable SO_ORIGINAL_DST to get original destination
        # This is needed for transparent proxying
        SO_ORIGINAL_DST = 80  # Linux value, might differ on macOS

        try:
            server_socket.bind((self.bind_address, self.port))
            server_socket.listen(128)
            print(f"DEBUG: Proxy listening on {self.bind_address}:{self.port}")

            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    print(f"DEBUG: Connection from {client_addr}")

                    # Handle connection in separate thread
                    handler = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    handler.start()

                except Exception as e:
                    if self.running:
                        print(f"Proxy accept error: {e}")

        finally:
            server_socket.close()

    def _handle_connection(self, client_socket, client_addr):
        """Handle individual client connection"""
        try:
            # Read the first line to determine if HTTP or HTTPS
            client_socket.settimeout(5.0)
            first_line = self._read_line(client_socket)

            if not first_line:
                client_socket.close()
                return

            print(f"DEBUG: First line from {client_addr[0]}: {first_line}")

            # Check if this is HTTP CONNECT (HTTPS) or regular HTTP
            if first_line.startswith(b'CONNECT'):
                self._handle_https(client_socket, client_addr, first_line)
            else:
                self._handle_http(client_socket, client_addr, first_line)

        except Exception as e:
            print(f"Connection handler error: {e}")
        finally:
            client_socket.close()

    def _handle_http(self, client_socket, client_addr, first_line):
        """Handle HTTP requests"""
        try:
            # Read all headers
            headers = {}
            while True:
                line = self._read_line(client_socket)
                if not line:  # Empty line indicates end of headers
                    break
                if b':' in line:
                    name, value = line.split(b':', 1)
                    headers[name.strip().lower()] = value.strip()

            # Parse first line
            parts = first_line.split(b' ')
            if len(parts) < 3:
                return

            method = parts[0].decode('utf-8')
            url = parts[1].decode('utf-8')
            version = parts[2].decode('utf-8')

            # Serve a 302 to the portal URL, or the built-in portal page
            target_url = self.redirect_rules.get(client_addr[0])
            if target_url:
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + target_url

                print(f"DEBUG: Redirecting {client_addr[0]} {method} {url} to {target_url}")

                response = [
                    "HTTP/1.1 302 Found",
                    f"Location: {target_url}",
                    "Connection: close",
                    "Content-Length: 0",
                    "",
                    ""
                ]
                client_socket.send('\r\n'.join(response).encode())
            else:
                body = self.portal_html.encode('utf-8')
                headers = [
                    "HTTP/1.1 200 OK",
                    "Content-Type: text/html; charset=utf-8",
                    f"Content-Length: {len(body)}",
                    "Connection: close",
                    "",
                    ""
                ]
                client_socket.send('\r\n'.join(headers).encode() + body)

        except Exception as e:
            print(f"HTTP handler error: {e}")

    def _handle_https(self, client_socket, client_addr, first_line):
        """Handle HTTPS CONNECT requests"""
        # Parse CONNECT request
        parts = first_line.split(b' ')
        if len(parts) < 3:
            return

        try:
            # Read headers until empty line
            while True:
                line = self._read_line(client_socket)
                if not line:
                    break

            # Check if we should redirect this host
            if client_addr[0] in self.redirect_rules:
                target_url = self.redirect_rules[client_addr[0]]
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'https://' + target_url

                # Send 302 redirect via HTTP (since we can't do HTTPS yet)
                response = [
                    "HTTP/1.1 302 Found",
                    f"Location: {target_url}",
                    "Connection: close",
                    "Content-Length: 0",
                    "",
                    ""
                ]
                client_socket.send('\r\n'.join(response).encode())
                print(f"DEBUG: Redirected HTTPS {client_addr[0]} to {target_url}")
            else:
                # No redirect - refuse CONNECT
                response = [
                    "HTTP/1.1 503 Service Unavailable",
                    "Connection: close",
                    "Content-Length: 0",
                    "",
                    ""
                ]
                client_socket.send('\r\n'.join(response).encode())
        except Exception as e:
            print(f"HTTPS handler error: {e}")

    def _read_line(self, sock):
        """Read a line from socket"""
        line = b''
        while True:
            char = sock.recv(1)
            if not char:
                break
            line += char
            if line.endswith(b'\r\n'):
                break
        return line.strip()

    def _load_rules(self, rules):
        """Load PF rules in correct order with proper anchors"""
        # Create temp files
        fd, rule_file = tempfile.mkstemp(suffix='.pf', text=True)
        os.close(fd)

        try:
            # Split rules into NAT and filter
            nat_rules = [r for r in rules if r.startswith('rdr ')]
            filter_rules = [r for r in rules if not r.startswith('rdr ')]

            # Write rules with proper structure
            with open(rule_file, 'w') as f:
                # NAT rules first
                f.write('nat-anchor "com.apple/*"\n')
                f.write('rdr-anchor "com.apple/*"\n')
                f.write('rdr-anchor "evil-redirections"\n\n')

                # NAT anchor block
                f.write('anchor "evil-redirections" {\n')
                for rule in nat_rules:
                    f.write(rule + '\n')
                f.write('}\n\n')

                # Filter rules next
                f.write('scrub-anchor "com.apple/*"\n')
                f.write('anchor "com.apple/*"\n')
                f.write('anchor "evil-filters" {\n')
                for rule in filter_rules:
                    f.write(rule + '\n')
                f.write('}\n')

            # Enable pf
            shell.execute_suppressed('{} -e'.format(BIN_PFCTL))

            # Load the rules
            result = shell.execute_suppressed('{} -f {}'.format(BIN_PFCTL, rule_file))
            if result != 0:
                raise Exception(f"Failed to load rules (exit code {result})")

        finally:
            # Clean up
            if os.path.exists(rule_file):
                os.unlink(rule_file)