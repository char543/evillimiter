import platform
import evillimiter.console.shell as shell

BROADCAST = 'ff:ff:ff:ff:ff:ff'

# OS detection
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

if IS_MACOS:
    # macOS-specific binaries
    BIN_PFCTL = shell.locate_bin('pfctl')
    BIN_DNCTL = shell.locate_bin('dnctl')
    BIN_SYSCTL = shell.locate_bin('sysctl')
    BIN_IFCONFIG = shell.locate_bin('ifconfig')
    IP_FORWARD_LOC = 'net.inet.ip.forwarding'
    IP6_FORWARD_LOC = 'net.inet6.ip6.forwarding'
    
    # For compatibility
    BIN_TC = None
    BIN_IPTABLES = None
else:
    # Linux-specific binaries
    BIN_TC = shell.locate_bin('tc')
    BIN_IPTABLES = shell.locate_bin('iptables')
    BIN_SYSCTL = shell.locate_bin('sysctl')
    IP_FORWARD_LOC = 'net.ipv4.ip_forward'
    IP6_FORWARD_LOC = 'net.ipv6.conf.all.forwarding'
    
    # For compatibility
    BIN_PFCTL = None
    BIN_DNCTL = None
    BIN_IFCONFIG = None

# Public DoH/DoT resolver IPs to block so clients fall back to plain DNS we see
DOH_RESOLVER_IPS = [
    '1.1.1.1', '1.0.0.1',                # Cloudflare
    '8.8.8.8', '8.8.4.4',                # Google
    '9.9.9.9', '149.112.112.112',        # Quad9
    '94.140.14.14', '94.140.15.15',      # AdGuard
    '208.67.222.222', '208.67.220.220',  # OpenDNS
]

# Canary domains: answering NXDOMAIN makes clients disable auto-DoH / Private Relay
DOH_CANARY_DOMAINS = [
    'use-application-dns.net',   # Firefox auto-DoH canary
    'mask.icloud.com',           # Apple iCloud Private Relay
    'mask-h2.icloud.com',        # Apple iCloud Private Relay
]


# OS connectivity-check domains. In catch-all (--to) redirection these are left
# to resolve normally so the device does not pop its captive-portal sheet.
CAPTIVE_CHECK_DOMAINS = [
    'captive.apple.com', 'captive.g.aaplimg.com',
    'connectivitycheck.gstatic.com', 'connectivitycheck.android.com',
    'clients3.google.com', 'www.google.com',
    'www.msftconnecttest.com', 'www.msftncsi.com', 'dns.msftncsi.com',
]
