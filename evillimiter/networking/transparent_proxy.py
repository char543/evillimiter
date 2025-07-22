import socket
import threading
import ssl
import os
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import urlparse
import struct
import tempfile
import subprocess


class TransparentProxy:
    def __init__(self, interface='0.0.0.0', port=8080):
        # Store network interface name for pfctl rules
        self.interface = interface
        # Use 0.0.0.0 for binding to accept connections on all interfaces
        self.bind_address = '0.0.0.0'
        self.port = port
        self.running = False
        self.thread = None
        self.redirect_rules = {}  # {host_ip: redirect_target}
        
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
        
    def setup_redirection(self, host_ip):
        """Setup pfctl rules to redirect traffic through the proxy"""
        from evillimiter.networking.utils_macos import enable_pfctl
        import subprocess

        # Import all needed utils
        from evillimiter.networking.utils_macos import (
            enable_pfctl, enable_ip_forwarding, flush_network_settings, load_pfctl_rules
        )
        
        # Enable packet filter and IP forwarding
        enable_pfctl()
        enable_ip_forwarding()
        
        # Flush existing rules
        flush_network_settings(self.interface)
        
        # Create rules file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            rules = [
                "set skip on lo0",
                f"rdr on {self.interface} proto tcp from {host_ip} to any port 80 -> 127.0.0.1 port {self.port}",
                f"rdr on {self.interface} proto tcp from {host_ip} to any port 443 -> 127.0.0.1 port {self.port}",
                f"rdr on {self.interface} proto udp from {host_ip} to any port 53 -> 127.0.0.1 port 53",
                "pass out all keep state",
                f"pass in proto tcp from {host_ip} to 127.0.0.1 port {self.port}",
                f"pass in proto udp from {host_ip} to 127.0.0.1 port 53"
            ]
            rules_str = '\n'.join(rules)
            f.write(rules_str)
            rules_file = f.name
            print("DEBUG: Generated pfctl rules:")
            print(rules_str)
            
        try:
            # Load the rules using utils_macos helper
            print("\nDEBUG: Loading rules...")
            if not load_pfctl_rules(rules_file):
                raise RuntimeError("Failed to load pf rules")

            # Show the loaded rules
            print("\nDEBUG: Verifying rules:")
            subprocess.run(['pfctl', '-s', 'rules'], check=False)
        finally:
            os.unlink(rules_file)

    def remove_redirection(self, host_ip):
        """Remove pfctl rules for host"""
        import subprocess
        
        try:
            # Flush all rules
            subprocess.run(['pfctl', '-F', 'all'], check=True)
            
            # Load a basic allow-all ruleset
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write("set skip on lo0\npass all\n")
                rules_file = f.name
                
            subprocess.run(['pfctl', '-f', rules_file], check=True)
            os.unlink(rules_file)
            
            # Disable pf if no more redirections
            if not self.redirect_rules:
                subprocess.run(['pfctl', '-d'], check=True)
                
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
            
            # Check if we should redirect this host
            if client_addr[0] in self.redirect_rules:
                target_url = self.redirect_rules[client_addr[0]]
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + target_url
                    
                print(f"DEBUG: Redirecting {client_addr[0]} {method} {url} to {target_url}")
                
                # Send 302 redirect
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
                # No redirect rule - send 404
                response = [
                    "HTTP/1.1 404 Not Found",
                    "Connection: close",
                    "Content-Length: 0",
                    "",
                    ""
                ]
                client_socket.send('\r\n'.join(response).encode())
                
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