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
    
    # For compatibility
    BIN_TC = None
    BIN_IPTABLES = None
else:
    # Linux-specific binaries
    BIN_TC = shell.locate_bin('tc')
    BIN_IPTABLES = shell.locate_bin('iptables')
    BIN_SYSCTL = shell.locate_bin('sysctl')
    IP_FORWARD_LOC = 'net.ipv4.ip_forward'
    
    # For compatibility
    BIN_PFCTL = None
    BIN_DNCTL = None
    BIN_IFCONFIG = None