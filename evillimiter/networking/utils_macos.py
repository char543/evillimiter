import re
import netifaces
from scapy.all import ARP, sr1

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL, BIN_SYSCTL, BIN_IFCONFIG, IP_FORWARD_LOC


def get_default_interface():
    """
    Returns the default IPv4 interface
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][1]


def get_default_gateway():
    """
    Returns the default IPv4 gateway address
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][0]


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface 
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get('netmask')


def get_mac_by_ip(interface, address):
    """
    Resolves hardware address from IP by sending ARP request
    and receiving ARP response
    """
    # ARP packet with operation 1 (who-is)
    packet = ARP(op=1, pdst=address)
    response = sr1(packet, timeout=3, verbose=0, iface=interface)

    if response is not None:
        return response.hwsrc


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    return interface in netifaces.interfaces()


def flush_network_settings(interface):
    """
    Flushes all pfctl rules and dummynet pipes
    related to the given interface
    """
    import subprocess
    from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL

    try:
        # Flush pfctl rules with timeout
        subprocess.run([BIN_PFCTL, '-F', 'all'], timeout=3, check=False)

        # Try to disable pfctl first
        subprocess.run([BIN_PFCTL, '-d'], timeout=3, check=False)

        # Delete all dummynet pipes with timeout
        subprocess.run([BIN_DNCTL, 'pipe', 'flush'], timeout=3, check=False)

    except subprocess.TimeoutExpired:
        print("Warning: Timeout while flushing network settings - continuing anyway")
    except Exception as e:
        print(f"Warning: Error flushing network settings: {e} - continuing anyway")

    return True  # Continue even if flush fails


def validate_ip_address(ip):
    return re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', ip) is not None


def validate_mac_address(mac):
    return re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac) is not None


def create_dummynet_pipe(pipe_id, bandwidth):
    """
    Creates a dummynet pipe with specified bandwidth limit
    """
    return shell.execute_suppressed('{} pipe {} config bw {}'.format(BIN_DNCTL, pipe_id, bandwidth)) == 0


def delete_dummynet_pipe(pipe_id):
    """
    Deletes a dummynet pipe
    """
    return shell.execute_suppressed('{} pipe delete {}'.format(BIN_DNCTL, pipe_id)) == 0


def enable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=1'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def disable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=0'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def enable_pfctl():
    """
    Enable packet filter (pfctl) on macOS
    """
    return shell.execute_suppressed('{} -e'.format(BIN_PFCTL)) == 0


def disable_pfctl():
    """
    Disable packet filter (pfctl) on macOS
    """
    return shell.execute_suppressed('{} -d'.format(BIN_PFCTL)) == 0


def load_pfctl_rules(rules_file):
    """
    Load pfctl rules from a file
    """
    return shell.execute_suppressed('{} -f {}'.format(BIN_PFCTL, rules_file)) == 0