import re
import platform
import netifaces
from scapy.all import ARP, Ether, srp1 # pylint: disable=no-name-in-module

import evillimiter.console.shell as shell
from evillimiter.common.globals import IS_MACOS, IS_LINUX, BIN_SYSCTL, IP_FORWARD_LOC

if IS_LINUX:
    from evillimiter.common.globals import BIN_TC, BIN_IPTABLES
elif IS_MACOS:
    from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL


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
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=address)
    response = srp1(packet, timeout=3, verbose=0, iface=interface)

    if response is not None:
        return response[ARP].hwsrc


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    return interface in netifaces.interfaces()


def flush_network_settings(interface):
    """
    Flushes all firewall rules and traffic control entries
    related to the given interface
    """
    if IS_LINUX:
        # reset default policy
        shell.execute_suppressed('{} -P INPUT ACCEPT'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -P OUTPUT ACCEPT'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -P FORWARD ACCEPT'.format(BIN_IPTABLES))

        # flush all chains in all tables (including user-defined)
        shell.execute_suppressed('{} -t mangle -F'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -t nat -F'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -F'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -X'.format(BIN_IPTABLES))

        # delete root qdisc for given interface
        shell.execute_suppressed('{} qdisc del dev {} root'.format(BIN_TC, interface))
    elif IS_MACOS:
        # Flush pfctl rules
        shell.execute_suppressed('{} -F all 2>/dev/null'.format(BIN_PFCTL))
        
        # Delete all dummynet pipes - use list first to avoid hanging
        try:
            # Get list of pipes
            import subprocess
            result = subprocess.run([BIN_DNCTL, 'list'], capture_output=True, text=True, timeout=2)
            # Delete each pipe individually
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip() and 'pipe' in line:
                        # Extract pipe number
                        parts = line.split()
                        if len(parts) > 1:
                            pipe_num = parts[1]
                            shell.execute_suppressed('{} pipe delete {}'.format(BIN_DNCTL, pipe_num))
        except:
            pass
        
        # Reset pfctl
        shell.execute_suppressed('{} -d 2>/dev/null'.format(BIN_PFCTL))


def validate_ip_address(ip):
    return re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', ip) is not None


def validate_mac_address(mac):
    return re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac) is not None


def create_qdisc_root(interface):
    """
    Creates a root qdisc or enables traffic control for a given interface
    """
    if IS_LINUX:
        return shell.execute_suppressed('{} qdisc add dev {} root handle 1:0 htb'.format(BIN_TC, interface)) == 0
    elif IS_MACOS:
        # Enable pfctl - this is what we need for traffic control on macOS
        result = shell.execute_suppressed('{} -e 2>/dev/null'.format(BIN_PFCTL))
        # pfctl returns 1 if already enabled, 0 if newly enabled - both are success
        return result == 0 or result == 1


def delete_qdisc_root(interface):
    if IS_LINUX:
        return shell.execute_suppressed('{} qdisc del dev {} root handle 1:0 htb'.format(BIN_TC, interface))
    elif IS_MACOS:
        # Disable pfctl on macOS
        return shell.execute_suppressed('{} -d'.format(BIN_PFCTL))


def enable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=1'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def disable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=0'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8


class BitRate(object):
    def __init__(self, rate=0):
        self.rate = rate

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        r = self.rate

        while True:
            if r >= 1000:
                r /= 1000
                counter += 1
            else:
                unit = ''
                if counter == 0:
                    unit = 'bit'
                elif counter == 1:
                    unit = 'kbit'
                elif counter == 2:
                    unit = 'mbit'
                elif counter == 3:
                    unit = 'gbit'
                
                return '{}{}'.format(int(r), unit)
            
            if counter > 3:
                raise Exception('Bitrate limit exceeded')

    def __mul__(self, other):
        if isinstance(other, BitRate):
            return BitRate(int(self.rate * other.rate))
        return BitRate(int(self.rate * other))

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])
    
        return '{}{}'.format(fmt % num, string[end:])

    @classmethod
    def from_rate_string(cls, rate_string):
        return cls(BitRate._bit_value(rate_string))

    @staticmethod
    def _bit_value(rate_string):
        number = 0  # rate number
        offset = 0  # string offset

        for c in rate_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break

        unit = rate_string[offset:].lower()

        if unit == 'bit':
            return number
        elif unit == 'kbit':
            return number * 1000
        elif unit == 'mbit':
            return number * 1000 ** 2
        elif unit == 'gbit':
            return number * 1000 ** 3
        else:
            raise Exception('Invalid bitrate')


class ByteValue(object):
    def __init__(self, value=0):
        self.value = value

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        v = self.value

        while True:
            if v >= 1024:
                v /= 1024
                counter += 1
            else:
                unit = ''
                if counter == 0:
                    unit = 'b'
                elif counter == 1:
                    unit = 'kb'
                elif counter == 2:
                    unit = 'mb'
                elif counter == 3:
                    unit = 'gb'
                elif counter == 4:
                    unit = 'tb'
                
                return '{}{}'.format(int(v), unit)
            
            if counter > 3:
                raise Exception('Byte value limit exceeded')

    def __int__(self):
        return self.value

    def __add__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value + other.value))
        return ByteValue(int(self.value + other))

    def __sub__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value - other.value))
        return ByteValue(int(self.value - other))

    def __mul__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value * other.value))
        return ByteValue(int(self.value * other))

    def __ge__(self, other):
        if isinstance(other, ByteValue):
            return self.value >= other.value
        return self.value >= other

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])

        return '{}{}'.format(fmt % num, string[end:])

    @classmethod
    def from_byte_string(cls, byte_string):
        return cls(ByteValue._byte_value(byte_string))

    @staticmethod
    def _byte_value(byte_string):
        number = 0  # rate number
        offset = 0  # string offset

        for c in byte_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break

        unit = byte_string[offset:].lower()

        if unit == 'b':
            return number
        elif unit == 'kb':
            return number * 1024
        elif unit == 'mb':
            return number * 1024 ** 2
        elif unit == 'gb':
            return number * 1024 ** 3
        elif unit == 'tb':
            return number * 1024 ** 4
        else:
            raise Exception('Invalid byte string')


def get_ip_range(gateway_ip, netmask):
    """
    Get IP range from gateway IP and netmask
    """
    import netaddr
    network = netaddr.IPNetwork(f"{gateway_ip}/{netmask}")
    return list(network)


# ---------------------------------------------------------------------------
# IPv6 support helpers
# ---------------------------------------------------------------------------

def _looks_like_mac(token):
    return token.count(':') == 5 and all(
        1 <= len(p) <= 2 and all(c in '0123456789abcdefABCDEF' for c in p)
        for p in token.split(':')
    )


def _normalize_mac(mac):
    # ndp may print octets without leading zeros (e.g. '0:1a:2b:...')
    return ':'.join(p.rjust(2, '0').lower() for p in mac.split(':'))


def enable_ipv6_forwarding():
    from evillimiter.common.globals import BIN_SYSCTL, IP6_FORWARD_LOC
    return shell.execute_suppressed('{} -w {}=1'.format(BIN_SYSCTL, IP6_FORWARD_LOC)) == 0


def disable_ipv6_forwarding():
    from evillimiter.common.globals import BIN_SYSCTL, IP6_FORWARD_LOC
    return shell.execute_suppressed('{} -w {}=0'.format(BIN_SYSCTL, IP6_FORWARD_LOC)) == 0


def solicit_ipv6_neighbors(interface, count=2):
    """
    Pings the link-local all-nodes multicast group so on-link IPv6 devices
    answer and populate the neighbor cache. Best-effort; ignores failures.
    """
    from evillimiter.common.globals import IS_MACOS
    if IS_MACOS:
        cmd = 'ping6 -c {} ff02::1%{}'.format(count, interface)
    else:
        cmd = 'ping -6 -c {} -I {} ff02::1'.format(count, interface)
    shell.execute_suppressed(cmd, root=False)


def get_ipv6_neighbor_map(interface):
    """
    Returns {mac: [ipv6, ...]} from the OS IPv6 neighbor cache.
    """
    from evillimiter.common.globals import IS_MACOS
    mac_to_ipv6 = {}
    try:
        out = shell.output('ndp -an', root=False) if IS_MACOS else shell.output('ip -6 neigh', root=False)
    except Exception:
        return mac_to_ipv6

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if IS_MACOS:
            addr, mac = parts[0], parts[1]
        else:
            addr = parts[0]
            mac = parts[parts.index('lladdr') + 1] if 'lladdr' in parts else ''
        addr = addr.split('%')[0]
        if ':' not in addr or not _looks_like_mac(mac):
            continue
        mac = _normalize_mac(mac)
        mac_to_ipv6.setdefault(mac, [])
        if addr not in mac_to_ipv6[mac]:
            mac_to_ipv6[mac].append(addr)
    return mac_to_ipv6


def get_host_ipv6_addresses(mac, interface, solicit=True):
    """
    Discovers the IPv6 addresses of a device (by MAC) via the neighbor cache.
    """
    if solicit:
        solicit_ipv6_neighbors(interface)
    return get_ipv6_neighbor_map(interface).get(_normalize_mac(mac), [])


def split_ipv6_addresses(addresses):
    """
    Splits IPv6 addresses into (link_local, routable).
    """
    link_local = [a for a in addresses if a.lower().startswith('fe80')]
    routable = [a for a in addresses if not a.lower().startswith('fe80')]
    return link_local, routable


def get_gateway_ipv6(interface):
    """
    Returns (address, mac) of the default IPv6 router, or (None, None).
    The router address is typically a link-local (fe80::) address.
    """
    from evillimiter.common.globals import IS_MACOS
    gateway = None
    try:
        if IS_MACOS:
            out = shell.output('netstat -rn -f inet6', root=False)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'default':
                    gateway = parts[1]
                    break
        else:
            out = shell.output('ip -6 route show default', root=False)
            parts = out.split()
            if 'via' in parts:
                gateway = parts[parts.index('via') + 1]
    except Exception:
        return (None, None)

    if gateway is None:
        return (None, None)

    addr = gateway.split('%')[0]
    solicit_ipv6_neighbors(interface)
    for mac, addrs in get_ipv6_neighbor_map(interface).items():
        if addr in addrs:
            return (addr, mac)
    return (addr, None)


def sniff_ipv6_addresses(interface, duration=4):
    """
    Passively sniffs IPv6 traffic for `duration` seconds and returns
    {mac: [ipv6 source addresses]} seen on the wire. Catches routable and
    temporary (privacy) addresses the neighbor cache alone often misses.
    """
    from scapy.all import sniff, IPv6, Ether  # pylint: disable=no-name-in-module
    found = {}

    def _handle(pkt):
        try:
            if pkt.haslayer(IPv6) and pkt.haslayer(Ether):
                mac = _normalize_mac(pkt[Ether].src)
                src = pkt[IPv6].src
                if src and src != '::':
                    found.setdefault(mac, [])
                    if src not in found[mac]:
                        found[mac].append(src)
        except Exception:
            pass

    try:
        sniff(iface=interface, timeout=duration, store=False, prn=_handle,
              lfilter=lambda p: p.haslayer(IPv6))
    except Exception:
        pass
    return found
