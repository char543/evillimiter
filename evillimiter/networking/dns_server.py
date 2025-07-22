import socket
import threading
import struct
from evillimiter.console.io import IO


class SimpleDNSServer:
    def __init__(self, interface='0.0.0.0', port=5354):
        self.interface = interface
        self.port = port
        self.running = False
        self.thread = None
        self.redirect_ip = '127.0.0.1'  # Default redirect IP
        self.domain_mappings = {}  # {domain: ip}
        
    def set_redirect_ip(self, ip):
        """Set the default IP to redirect to"""
        self.redirect_ip = ip
        
    def add_domain_mapping(self, domain, ip):
        """Add specific domain -> IP mapping"""
        self.domain_mappings[domain] = ip
        print(f"DEBUG: Added DNS mapping: {domain} -> {ip}")
        
    def start(self):
        """Start the DNS server"""
        if self.running:
            return
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.interface, self.port))
            self.running = True
            self.thread = threading.Thread(target=self._server_loop, daemon=True)
            self.thread.start()
            print(f"DEBUG: DNS server started on {self.interface}:{self.port}")
        except Exception as e:
            print(f"ERROR: Failed to start DNS server: {e}")
            
    def stop(self):
        """Stop the DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
            
    def _server_loop(self):
        """Main server loop"""
        print(f"DEBUG: DNS server loop started, listening on {self.interface}:{self.port}")
        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)
                print(f"DEBUG: Received {len(data)} bytes from {addr}")
                response = self._process_dns_query(data, addr)
                if response:
                    self.socket.sendto(response, addr)
                    print(f"DEBUG: Sent response to {addr}")
            except Exception as e:
                if self.running:
                    print(f"DNS server error: {e}")
                    
    def _process_dns_query(self, data, addr):
        """Process DNS query and return response"""
        try:
            # Parse DNS header
            if len(data) < 12:
                return None
                
            # Extract transaction ID and flags
            transaction_id = struct.unpack('>H', data[0:2])[0]
            flags = struct.unpack('>H', data[2:4])[0]
            
            # Check if it's a query (QR bit = 0)
            if flags & 0x8000:
                return None
                
            # Parse question
            question_start = 12
            domain_parts = []
            pos = question_start
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if length > 63:  # Compressed label
                    break
                pos += 1
                if pos + length > len(data):
                    break
                domain_parts.append(data[pos:pos + length].decode('ascii', errors='ignore'))
                pos += length
                
            if pos + 4 > len(data):
                return None
                
            domain = '.'.join(domain_parts)
            qtype = struct.unpack('>H', data[pos:pos+2])[0]
            qclass = struct.unpack('>H', data[pos+2:pos+4])[0]
            
            print(f"DEBUG: DNS query for {domain} from {addr[0]}")
            
            # Only handle A records (IPv4)
            if qtype != 1:
                return None
                
            # Determine redirect IP
            redirect_ip = self.domain_mappings.get(domain, self.redirect_ip)
            
            # Create DNS response
            response = self._create_dns_response(transaction_id, domain, redirect_ip, data[question_start:pos+4])
            return response
            
        except Exception as e:
            print(f"DNS query processing error: {e}")
            return None
            
    def _create_dns_response(self, transaction_id, domain, ip, question_section):
        """Create DNS response packet"""
        try:
            # DNS Header (12 bytes)
            flags = 0x8180  # Response, Authoritative, No error
            qdcount = 1     # 1 question
            ancount = 1     # 1 answer
            nscount = 0     # 0 authority records
            arcount = 0     # 0 additional records
            
            header = struct.pack('>HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)
            
            # Question section (copy from original query)
            question = question_section
            
            # Answer section
            # Name (pointer to question)
            name_pointer = struct.pack('>H', 0xC00C)  # Compression pointer to offset 12
            
            # Type A, Class IN, TTL 300, Data length 4
            answer_header = struct.pack('>HHIH', 1, 1, 300, 4)
            
            # IP address (4 bytes)
            ip_parts = [int(x) for x in ip.split('.')]
            ip_bytes = struct.pack('>BBBB', *ip_parts)
            
            response = header + question + name_pointer + answer_header + ip_bytes
            return response
            
        except Exception as e:
            print(f"DNS response creation error: {e}")
            return None