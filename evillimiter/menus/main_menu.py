import time
import socket
import curses
import netaddr
import netifaces
import threading
import collections
from terminaltables import SingleTable

import evillimiter.networking.utils as netutils
from .menu import CommandMenu
from evillimiter.networking.utils import BitRate
from evillimiter.console.io import IO
from evillimiter.console.chart import BarChart
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limit import create_limiter, Direction
from evillimiter.common.globals import DOH_RESOLVER_IPS, DOH_CANARY_DOMAINS
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.ndp_spoof import NDPSpoofer
from evillimiter.networking.dns_server import SimpleDNSServer
from evillimiter.networking.scan import HostScanner
from evillimiter.networking.monitor import BandwidthMonitor
from evillimiter.networking.watch import HostWatcher


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('analyze', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('watch', self._watch_handler)
        watch_add_parser = watch_parser.add_subparser('add', self._watch_add_handler)
        watch_add_parser.add_parameter('id')
        watch_remove_parser = watch_parser.add_subparser('remove', self._watch_remove_handler)
        watch_remove_parser.add_parameter('id')
        watch_set_parser = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set_parser.add_parameter('attribute')
        watch_set_parser.add_parameter('value')

        # Unified redirect command with all options
        redirect_parser = self.parser.add_subparser('redirect', self._redirect_handler)
        redirect_parser.add_parameter('id')
        redirect_parser.add_parameterized_flag('--to', 'to')
        redirect_parser.add_parameterized_flag('--dns', 'dns')
        redirect_parser.add_flag('--harden', 'harden')
        redirect_parser.add_flag('--lockdown', 'lockdown')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.parser.add_subparser('quit', self._quit_handler)
        self.parser.add_subparser('exit', self._quit_handler)

        self.version = version          # application version
        self.interface = interface      # specified IPv4 interface
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # range of IP address calculated from gateway IP and netmask
        self.iprange = list(netaddr.IPNetwork('{}/{}'.format(self.gateway_ip, self.netmask)))

        self.host_scanner = HostScanner(self.interface, self.iprange)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        gateway_ipv6, gateway_mac6 = netutils.get_gateway_ipv6(self.interface)
        self.ndp_spoofer = NDPSpoofer(self.interface, gateway_ipv6, gateway_mac6, self.arp_spoofer.our_mac)
        self.dns_server = None  # Will be initialized when DNS redirection is needed
        self.limiter = create_limiter(self.interface)
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1)
        self.host_watcher = HostWatcher(self.host_scanner, self._reconnect_callback)

        # holds discovered hosts
        self.hosts = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()
        # start the IPv6 (NDP) spoof thread if an IPv6 gateway was found
        if self.ndp_spoofer.start():
            IO.ok('ipv6 interception active (gateway {}).'.format(self.ndp_spoofer.gateway_ipv6))
        # start the bandwidth monitor thread
        self.bandwidth_monitor.start()
        # start the host watch thread
        self.host_watcher.start()

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()

        IO.ok('cleaning up... stand by...')

        self.arp_spoofer.stop()
        self.ndp_spoofer.stop()
        self.bandwidth_monitor.stop()
        
        if self.dns_server:
            self.dns_server.stop()

        for host in self.hosts:
            self._free_host(host)

    def _scan_handler(self, args):
        """
        Handles 'scan' command-line argument
        (Re)scans for hosts on the network
        """
        try:
            if args.iprange is not None:
                iprange = self._parse_iprange(args.iprange)
                if iprange is None:
                    IO.error('invalid ip range.')
                    return
            else:
                # Get IP range from interface configuration
                try:
                    netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
                except (ValueError, KeyError):
                    netmask = '255.255.255.0'
                
                iprange = netutils.get_ip_range(self.gateway_ip, netmask)
        except Exception as e:
            IO.error(f"Error determining IP range: {e}")
            return

        with self.hosts_lock:
            for host in self.hosts:
                self._free_host(host)
            
        IO.spacer()
        hosts = self.host_scanner.scan(iprange)

        self.hosts_lock.acquire()
        self.hosts = hosts
        self.hosts_lock.release()

        IO.ok('{}{}{} hosts discovered.'.format(IO.Fore.LIGHTYELLOW_EX, len(hosts), IO.Style.RESET_ALL))
        IO.spacer()

    def _hosts_handler(self, args):
        """
        Handles 'hosts' command-line argument
        Displays discovered hosts
        """
        table_data = [[
            '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}MAC address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Hostname{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Status{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}IPv6{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        ]]
        
        with self.hosts_lock:
            for host in self.hosts:
                table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host, lock=False), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac,
                    host.name,
                    host.pretty_status(),
                    '\n'.join(host.ipv6) if host.ipv6 else '-'
                ])

        table = SingleTable(table_data, 'Hosts')

        if not args.force and not table.ok:
            IO.error('table does not fit terminal. resize or decrease font size. you can also force the display (--force).')
            return

        IO.spacer()
        IO.print(table.table)
        IO.spacer()

    def _limit_handler(self, args):
        """
        Handles 'limit' command-line argument
        Limits bandwith of host to specified rate
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate is invalid.')
            return

        direction = self._parse_direction_args(args)

        for host in hosts:
            self.arp_spoofer.add(host)
            self.ndp_spoofer.add(host)
            self.limiter.limit(host, direction, rate)
            self.bandwidth_monitor.add(host)

            IO.ok('{}{}{r} {} {}limited{r} to {}.'.format(
                IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction),
                IO.Fore.LIGHTRED_EX, rate, r=IO.Style.RESET_ALL))

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        hosts = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.ndp_spoofer.add(host)
                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)
                IO.ok('{}{}{r} {} {}blocked{r}.'.format(
                    IO.Fore.LIGHTYELLOW_EX, host.ip,
                    Direction.pretty_direction(direction),
                    IO.Fore.RED, r=IO.Style.RESET_ALL))

    def _free_handler(self, args):
        """
        Handles 'free' command-line argument
        Frees the host from all limitations
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self._free_host(host)

    def _add_handler(self, args):
        """
        Handles 'add' command-line argument
        Adds custom host to host list
        """
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('invalid ip address.')
            return

        if args.mac:
            mac = args.mac
            if not netutils.validate_mac_address(mac):
                IO.error('invalid mac address.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if mac is None:
                IO.error('unable to resolve mac address. specify manually (--mac).')
                return

        name = None
        try:
            host_info = socket.gethostbyaddr(ip)
            name = None if host_info is None else host_info[0]
        except socket.herror:
            pass

        host = Host(ip, mac, name)

        with self.hosts_lock:
            if host in self.hosts:
                IO.error('host does already exist.')
                return

            self.hosts.append(host) 

        IO.ok('host added.')

    def _monitor_handler(self, args):
        """
        Handles 'monitor' command-line argument
        Monitors hosts bandwidth usage
        """
        def get_bandwidth_results():
            with self.hosts_lock:
                return [x for x in [(y, self.bandwidth_monitor.get(y)) for y in self.hosts] if x[1] is not None]

        def display(stdscr, interval):
            host_results = get_bandwidth_results()
            hname_max_len = max([len(x[0].name) for x in host_results])

            header_off = [
                ('ID', 5), ('IP address', 18), ('Hostname', hname_max_len + 2),
                ('Current (per s)', 20), ('Total', 16), ('Packets', 0)
            ]

            y_rst = 1
            x_rst = 2

            while True:
                y_off = y_rst
                x_off = x_rst

                stdscr.clear()

                for header in header_off:
                    stdscr.addstr(y_off, x_off, header[0])
                    x_off += header[1]

                y_off += 2
                x_off = x_rst

                for host, result in host_results:
                    result_data = [
                        str(self._get_host_id(host)),
                        host.ip,
                        host.name,
                        '{}↑ {}↓'.format(result.upload_rate, result.download_rate),
                        '{}↑ {}↓'.format(result.upload_total_size, result.download_total_size),
                        '{}↑ {}↓'.format(result.upload_total_count, result.download_total_count)
                    ]

                    for j, string in enumerate(result_data):
                        stdscr.addstr(y_off, x_off, string)
                        x_off += header_off[j][1]

                    y_off += 1
                    x_off = x_rst

                y_off += 2
                stdscr.addstr(y_off, x_off, 'press \'ctrl+c\' to exit.')

                try:
                    stdscr.refresh()
                    time.sleep(interval)
                    host_results = get_bandwidth_results()
                except KeyboardInterrupt:
                    return
                    

        interval = 0.5  # in s
        if args.interval:
            if not args.interval.isdigit():
                IO.error('invalid interval.')
                return

            interval = int(args.interval) / 1000    # from ms to s

        if len(get_bandwidth_results()) == 0:
            IO.error('no hosts to be monitored.')
            return

        try:
            curses.wrapper(display, interval)
        except curses.error:
            IO.error('monitor error occurred. maybe terminal too small?')

    def _analyze_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            IO.error('no hosts to be analyzed.')
            return
        
        duration = 30 # in s
        if args.duration:
            if not args.duration.isdigit():
                IO.error('invalid duration.')
                return

            duration = int(args.duration)

        hosts_to_be_freed = set()
        host_values = {}

        for host in hosts:
            if not host.spoofed:
                hosts_to_be_freed.add(host)

            self.arp_spoofer.add(host)
            self.bandwidth_monitor.add(host)

            host_result = self.bandwidth_monitor.get(host)
            host_values[host] = {}
            host_values[host]['prev'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('analyzing traffic for {}s.'.format(duration))
        time.sleep(duration)

        error_occurred = False
        for host in hosts:
            host_result = self.bandwidth_monitor.get(host)

            if host_result is None:
                # host reconnected during analysis
                IO.error('host reconnected during analysis.')
                error_occurred = True
            else:
                host_values[host]['current'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('cleaning up...')
        for host in hosts_to_be_freed:
            self._free_host(host)

        if error_occurred:
            return

        upload_chart = BarChart(max_bar_length=29)
        download_chart = BarChart(max_bar_length=29)

        for host in hosts:
            upload_value = host_values[host]['current'][0] - host_values[host]['prev'][0]
            download_value = host_values[host]['current'][1] - host_values[host]['prev'][1]

            prefix = '{}{}{} ({}, {})'.format(
                IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL,
                host.ip,
                host.name
            )
            
            upload_chart.add_value(upload_value.value, prefix, upload_value)
            download_chart.add_value(download_value.value, prefix, download_value)

        upload_table = SingleTable([[upload_chart.get()]], 'Upload')
        download_table = SingleTable([[download_chart.get()]], 'Download')

        upload_table.inner_heading_row_border = False
        download_table.inner_heading_row_border = False

        IO.spacer()
        IO.print(upload_table.table)
        IO.print(download_table.table)
        IO.spacer()

    def _watch_handler(self, args):
        if len(args) == 0:
            watch_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}MAC address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            set_table_data = [[
                '{}Attribute{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Value{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            hist_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Old IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}New IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Time{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            iprange = self.host_watcher.iprange
            interval = self.host_watcher.interval

            set_table_data.append([
                '{}range{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{} addresses'.format(len(iprange)) if iprange is not None else 'default'
            ])

            set_table_data.append([
                '{}interval{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{}s'.format(interval)
            ])

            for host in self.host_watcher.hosts:
                watch_table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac
                ])

            for recon in self.host_watcher.log_list:
                hist_table_data.append([
                    recon['old'].mac,
                    recon['old'].ip,
                    recon['new'].ip,
                    recon['time']
                ])

            watch_table = SingleTable(watch_table_data, "Watchlist")
            set_table = SingleTable(set_table_data, "Settings")
            hist_table = SingleTable(hist_table_data, 'Reconnection History')

            IO.spacer()
            IO.print(watch_table.table)
            IO.spacer()
            IO.print(set_table.table)
            IO.spacer()
            IO.print(hist_table.table)
            IO.spacer()

    def _watch_add_handler(self, args):
        """
        Handles 'watch add' command-line argument
        Adds host to the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.add(host)

    def _watch_remove_handler(self, args):
        """
        Handles 'watch remove' command-line argument
        Removes host from the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.remove(host)

    def _watch_set_handler(self, args):
        """
        Handles 'watch set' command-line argument
        Modifies settings of the reconnection reconnection watcher
        """
        if args.attribute.lower() in ('range', 'iprange', 'ip_range'):
            iprange = self._parse_iprange(args.value)
            if iprange is not None:
                self.host_watcher.iprange = iprange
            else:
                IO.error('invalid ip range.')
        elif args.attribute.lower() in ('interval'):
            if args.value.isdigit():
                self.host_watcher.interval = int(args.value)
            else:
                IO.error('invalid interval.')
        else:
            IO.error('{}{}{} is an invalid settings attribute.'.format(IO.Fore.LIGHTYELLOW_EX, args.attribute, IO.Style.RESET_ALL))

    def _portal_handler(self, args):
        """
        DEPRECATED: Use 'redirect' command instead.
        This will be removed in a future version.
        """
        action = args.action.lower()
        
        if action == 'enable':
            hosts = self._get_hosts_by_ids(args.id)
            if hosts is None or len(hosts) == 0:
                return
                
            # Get redirect IP (default to gateway IP)
            redirect_ip = args.redirect_ip if args.redirect_ip else self.gateway_ip
            if not netutils.validate_ip_address(redirect_ip):
                IO.error('invalid redirect IP address.')
                return
                
            # Initialize DNS server if not already done
            if not self.dns_server:
                self.dns_server = SimpleDNSServer()
                self.dns_server.set_redirect_ip(redirect_ip)
                self.dns_server.start()
            else:
                # Update redirect IP
                self.dns_server.set_redirect_ip(redirect_ip)
                
            # Add hosts to DNS redirection and ARP spoofer
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)
                # Add pfctl rule to redirect DNS traffic from this host
                self.limiter._generate_dns_redirect_rules(host, '127.0.0.1')
                IO.ok('{}{}{} redirected to captive portal at {}{}{}.'.format(
                    IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Style.RESET_ALL,
                    IO.Fore.LIGHTGREEN_EX, redirect_ip, IO.Style.RESET_ALL
                ))
                
        elif action == 'disable':
            hosts = self._get_hosts_by_ids(args.id)
            if hosts is None or len(hosts) == 0:
                return
                
            if not self.dns_server:
                IO.error('captive portal is not enabled.')
                return
                
            # Remove hosts from DNS redirection (would need to implement host-specific rule removal)
            for host in hosts:
                # For now, just notify - implementing selective rule removal would require more complex logic
                IO.ok('{}{}{} removed from captive portal.'.format(
                    IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Style.RESET_ALL
                ))
                
        else:
            IO.error('invalid action. use "enable" or "disable".')

    def _redirect_handler(self, args):
        """Handle redirect command with options:
        redirect <id>                          # Default: redirect to local proxy
        redirect <id> --to <ip|domain>        # Redirect all traffic to IP or domain
        redirect <id> --dns <domain>=<ip>     # Domain-specific redirection
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return
            
        # Parse arguments
        target_ip = None
        dns_mappings = None
        
        if hasattr(args, 'to') and args.to:
            target = args.to
            # Clean up the target (remove http://, https://, trailing slashes)
            target = target.lower()
            target = target.replace('http://', '').replace('https://', '')
            target = target.split('/')[0]  # Remove paths
            
            if netutils.validate_ip_address(target):
                target_ip = target
            else:
                # It's a domain, try to resolve it
                try:
                    addr_info = socket.getaddrinfo(target, None)
                    target_ip = addr_info[0][4][0]  # Get first IPv4 address
                except (socket.gaierror, IndexError):
                    IO.error(f'Could not resolve domain: {target}')
                    return
            
        if hasattr(args, 'dns') and args.dns:
            try:
                domain, ip = args.dns.split('=')
                if not netutils.validate_ip_address(ip):
                    IO.error('Invalid DNS mapping IP address')
                    return
                dns_mappings = {domain: ip}
            except ValueError:
                IO.error("Invalid --dns format. Use: --dns domain=ip")
                return

        # Resolve our own IPv4 on the interface (portal / rdr target)
        local_ip = netutils.get_local_ip_address(self.interface)
        if local_ip is None:
            IO.error('could not determine local IPv4 address for {}.'.format(self.interface))
            return

        # Single DNS server bound to 0.0.0.0:5354
        if not self.dns_server:
            self.dns_server = SimpleDNSServer(port=5354)
            if not self.dns_server.start():
                IO.error('failed to start DNS server (is port 5354 already in use?).')
                return

        # Decide redirection mode from the arguments
        if dns_mappings:
            # selective: map given domains, resolve everything else normally
            self.dns_server.catch_all = False
            for domain, ip in dns_mappings.items():
                self.dns_server.add_domain_mapping(domain, ip)
            portal_url = None
            include_http = False
        else:
            # captive-portal: DNS answers everything with us; HTTP 302 to portal
            self.dns_server.catch_all = True
            self.dns_server.set_redirect_ip(local_ip)
            if getattr(args, 'to', None):
                portal_url = args.to if args.to.startswith(('http://', 'https://')) else 'http://' + args.to
                # allow the portal's own host to resolve for real so the 302 target loads
                try:
                    from urllib.parse import urlparse
                    portal_host = urlparse(portal_url).hostname
                    if portal_host and not netutils.validate_ip_address(portal_host):
                        self.dns_server.add_allow(portal_host)
                except Exception:
                    pass
            else:
                portal_url = None  # proxy serves its built-in page
            include_http = True

        # Hardening ladder: --harden pushes encrypted DNS back to plain DNS;
        # --lockdown blocks everything except our DNS + portal (implies harden).
        lockdown = bool(getattr(args, 'lockdown', False))
        harden = lockdown or bool(getattr(args, 'harden', False))
        doh_ips = DOH_RESOLVER_IPS if harden else None
        if harden:
            for _canary in DOH_CANARY_DOMAINS:
                self.dns_server.add_deny(_canary)

        for host in hosts:
            if not host.spoofed:
                self.arp_spoofer.add(host)
            self.ndp_spoofer.add(host)

            try:
                _, routable6 = netutils.split_ipv6_addresses(host.ipv6)
                self.limiter.proxy.setup_redirection(host.ip, local_ip, portal_url, include_http,
                                                     block_ipv6=routable6, harden=harden,
                                                     lockdown=lockdown, doh_ips=doh_ips)

                if dns_mappings:
                    domain = list(dns_mappings.keys())[0]
                    ip = dns_mappings[domain]
                    IO.ok('{}{}{r} DNS: {} -> {}.'.format(
                        IO.Fore.LIGHTYELLOW_EX, host.ip, domain, ip, r=IO.Style.RESET_ALL))
                elif portal_url:
                    IO.ok('{}{}{r} redirected to portal {}.'.format(
                        IO.Fore.LIGHTYELLOW_EX, host.ip, portal_url, r=IO.Style.RESET_ALL))
                else:
                    IO.ok('{}{}{r} redirected to the built-in portal page.'.format(
                        IO.Fore.LIGHTYELLOW_EX, host.ip, r=IO.Style.RESET_ALL))
            except Exception as e:
                IO.error('failed to set up redirection for {}: {}'.format(host.ip, e))

    def _reconnect_callback(self, old_host, new_host):
        """
        Callback that is called when a watched host reconnects
        Method will run in a separate thread
        """
        with self.hosts_lock:
            if old_host in self.hosts:
                self.hosts[self.hosts.index(old_host)] = new_host
            else:
                return

        self.arp_spoofer.remove(old_host, restore=False)
        self.arp_spoofer.add(new_host)
        self.ndp_spoofer.remove(old_host, restore=False)
        self.ndp_spoofer.add(new_host)

        self.host_watcher.remove(old_host)
        self.host_watcher.add(new_host)

        self.limiter.replace(old_host, new_host)
        self.bandwidth_monitor.replace(old_host, new_host)

    def _clear_handler(self, args):
        """
        Handler for the 'clear' command-line argument
        Clears the terminal window and re-prints the banner
        """
        IO.clear()
        IO.print(get_main_banner(self.version))
        self._print_help_reminder()

    def _help_handler(self, args):
        """
        Handles the 'help' command: prints all commands plus the redirect modes.
        """
        Y = IO.Fore.LIGHTYELLOW_EX
        G = IO.Fore.LIGHTGREEN_EX
        R = IO.Style.RESET_ALL
        B = IO.Style.BRIGHT

        commands = [
            ('scan (--range [range])', 'scan the network for online hosts; run this first.',
             ['scan', 'scan --range 192.168.0.0/24']),
            ('hosts (--force)', 'list scanned hosts with IDs, MACs and IPv6 addresses.', []),
            ('limit [IDs] [rate] (--upload|--download)', 'limit host bandwidth (IPv4 and IPv6).',
             ['limit 4 100kbit', 'limit 2,3 1mbit --download', 'limit all 200kbit']),
            ('block [IDs] (--upload|--download)', 'cut a host off the internet (IPv4 and IPv6).',
             ['block 2', 'block all']),
            ('redirect [IDs] (--dns d=IP) (--to IP|URL) (--harden) (--lockdown)',
             'capture host DNS and HTTP; see redirect modes below.',
             ['redirect 2 --dns google.com=66.254.114.41',
              'redirect 2 --dns ads.example=1.2.3.4 --harden',
              'redirect 2 --to http://portal.local/',
              'redirect 2 --lockdown']),
            ('free [IDs]', 'remove every limit, block and redirect from a host.',
             ['free 3,4', 'free all']),
            ('add [IP] (--mac MAC)', 'add a host to the list manually.', ['add 192.168.0.24']),
            ('monitor (--interval ms)', 'show live per-host bandwidth usage.', ['monitor']),
            ('analyze [IDs] (--duration s)', 'capture and summarise host traffic.',
             ['analyze all --duration 60']),
            ('watch add|remove [ID]  /  watch set [attr] [value]',
             're-apply rules automatically when a host reconnects.',
             ['watch add 2', 'watch set interval 5']),
            ('clear', 'clear the terminal.', []),
            ('quit', 'quit and flush all rules.', []),
        ]

        out = ['', f'{B}Commands{R}', '']
        for cmd, desc, examples in commands:
            out.append(f'  {Y}{cmd}{R}')
            out.append(f'      {desc}')
            for ex in examples:
                out.append(f'      {G}e.g. {ex}{R}')
            out.append('')

        out += [
            f'{B}Redirect modes{R}',
            '',
            f'  {Y}--dns d=IP{R}   point one domain at an IP for this host; everything else',
            '               resolves normally. forces IPv4 so it cannot leak over v6.',
            f'  {Y}--to IP|URL{R}  send a 302 to this target for the host HTTP (port 80).',
            f'  {Y}(no flag){R}    serve the built-in portal page on HTTP.',
            f'  {Y}--harden{R}     also block DoT (853) and known DoH resolver IPs, and answer',
            '               the Firefox / Apple Private Relay canaries with NXDOMAIN, so the',
            '               host falls back to the plain DNS you control. internet still works.',
            f'  {Y}--lockdown{R}   block everything except your DNS and portal (implies --harden);',
            '               herds the host to a captive portal, like Cisco / UniFi.',
            '',
            f'  {B}note{R}: HTTPS content cannot be swapped without a trusted cert on the device.',
            '        redirect controls DNS and plain HTTP. an HTTPS site whose domain is',
            '        pointed elsewhere shows a certificate error, not the new content.',
            '',
        ]
        IO.print('\n'.join(out))

    def _quit_handler(self, args):
        self.interrupt_handler(False)
        self.stop()

    def _get_host_id(self, host, lock=True):
        ret = None

        if lock:
            self.hosts_lock.acquire()

        for i, host_ in enumerate(self.hosts):
            if host_ == host:
                ret = i
                break
        
        if lock:
            self.hosts_lock.release()

        return ret

    def _print_help_reminder(self):
        Y = IO.Fore.LIGHTYELLOW_EX
        R = IO.Style.RESET_ALL
        B = IO.Style.BRIGHT

        rows = [
            ('scan',          'find devices on the network'),
            ('hosts',         'list what was found, with their IDs'),
            ('limit 3 1mbit', 'throttle host #3 to 1 mbit/s'),
            ('block 3',       'cut host #3 off the internet'),
            ('free 3',        'remove all limits/blocks from host #3'),
            ('help  or  ?',   'full command reference'),
        ]
        lines = ['{B}quick start:{R}'.format(B=B, R=R)]
        for cmd, desc in rows:
            pad = ' ' * max(2, 18 - len(cmd))
            lines.append('  {Y}{cmd}{R}{pad}{desc}'.format(Y=Y, R=R, cmd=cmd, pad=pad, desc=desc))
        IO.print('\n'.join(lines))

    def _get_hosts_by_ids(self, ids_string):
        if ids_string == 'all':
            with self.hosts_lock:
                return self.hosts.copy()

        ids = ids_string.split(',')
        hosts = set()

        with self.hosts_lock:
            for id_ in ids:
                is_mac = netutils.validate_mac_address(id_)
                is_ip = netutils.validate_ip_address(id_)
                is_id_ = id_.isdigit()

                if not is_mac and not is_ip and not is_id_:
                    IO.error('invalid identifier(s): \'{}\'.'.format(ids_string))
                    return

                if is_mac or is_ip:
                    found = False
                    for host in self.hosts:
                        if host.mac == id_.lower() or host.ip == id_:
                            found = True
                            hosts.add(host)
                            break
                    if not found:
                        IO.error('no host matching {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                else:
                    id_ = int(id_)
                    if len(self.hosts) == 0 or id_ not in range(len(self.hosts)):
                        IO.error('no host with id {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                    hosts.add(self.hosts[id_])

        return hosts

    def _parse_direction_args(self, args):
        direction = Direction.NONE

        if args.upload:
            direction |= Direction.OUTGOING
        if args.download:
            direction |= Direction.INCOMING

        return Direction.BOTH if direction == Direction.NONE else direction

    def _parse_dns_args(self, dns_args):
        """
        Parse DNS arguments to create domain mappings
        Supports formats:
        - Single domain: 'example.com' -> redirect to default IP
        - Multiple domains: 'example.com test.com' -> redirect to default IP
        - Domain with IP: 'example.com=192.168.1.100' -> specific redirect
        - Mixed: 'example.com test.com=192.168.1.200'
        """
        if not dns_args:
            return []
            
        # Split the string into individual arguments
        args_list = dns_args.split()
        
        mappings = {}
        domains_only = []
        
        for arg in args_list:
            if '=' in arg:
                # Domain with specific IP mapping
                parts = arg.split('=', 1)
                domain = parts[0].strip()
                ip = parts[1].strip()
                
                # Validate IP
                if not netutils.validate_ip_address(ip):
                    # Try to resolve domain name to IP
                    try:
                        import socket
                        resolved_ip = socket.gethostbyname(ip)
                        ip = resolved_ip
                    except:
                        IO.error('invalid IP address or unresolvable domain: {}'.format(ip))
                        return None
                        
                mappings[domain] = ip
            else:
                # Domain only, use default redirect IP
                domains_only.append(arg.strip())
                
        # If we have domains without specific IPs, return as list
        if domains_only and not mappings:
            return domains_only
        elif domains_only:
            # Mix of both - add domains_only with default IP
            for domain in domains_only:
                mappings[domain] = self.dns_server.redirect_ip if self.dns_server else self.gateway_ip
                
        return mappings if mappings else domains_only

    def _parse_iprange(self, range):
        try:
            if '-' in range:
                return list(netaddr.iter_iprange(*range.split('-')))
            else:
                return list(netaddr.IPNetwork(range))
        except netaddr.core.AddrFormatError:
            return

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.ndp_spoofer.remove(host)
            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)
            
            # DNS redirection removal would need to be implemented in the limiter
            # For now, the pfctl rules handle this at the network level
