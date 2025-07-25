import threading
import tempfile
import os
import warnings

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL
from .transparent_proxy import TransparentProxy


class MacOSLimiter(object):
    class HostLimitIDs(object):
        def __init__(self, upload_id, download_id):
            self.upload_id = upload_id
            self.download_id = download_id

    def __init__(self, interface):
        self.interface = interface
        self._host_dict = {}
        self._host_dict_lock = threading.Lock()
        self._rules_file = None
        self._active_rules = []  # Keep track of all active rules
        self._dns_rules = {}  # Keep track of DNS redirect rules per host
        self.proxy = TransparentProxy(interface=interface, port=8080)
        self.proxy.start()

    def limit(self, host, direction, rate):
        """
        Limits the upload/download traffic of a host
        to a specified rate using pfctl and dummynet
        """
        host_ids = self._new_host_limit_ids(host, direction)

        # Create dummynet pipes for bandwidth limiting
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # Convert rate to kbps format for dnctl
            rate_kbps = rate.rate // 1000  # Convert bits to kbps
            result = shell.execute_suppressed('{} pipe {} config bw {}Kbit/s'.format(BIN_DNCTL, host_ids.upload_id, rate_kbps))
            if result != 0:
                print(f"Warning: Failed to create upload pipe {host_ids.upload_id}")
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            rate_kbps = rate.rate // 1000  # Convert bits to kbps  
            result = shell.execute_suppressed('{} pipe {} config bw {}Kbit/s'.format(BIN_DNCTL, host_ids.download_id, rate_kbps))
            if result != 0:
                print(f"Warning: Failed to create download pipe {host_ids.download_id}")

        # Generate and load pfctl rules
        self._generate_pfctl_rules(host, direction, host_ids, rate)

        host.limited = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': rate, 'direction': direction }

    def block(self, host, direction):
        """
        Blocks traffic from/to a host using pfctl
        """
        host_ids = self._new_host_limit_ids(host, direction)

        # Generate and load pfctl blocking rules
        self._generate_pfctl_blocking_rules(host, direction)

        host.blocked = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': None, 'direction': direction }

    def unlimit(self, host, direction):
        if not host.limited and not host.blocked:
            return
            
        with self._host_dict_lock:
            host_ids = self._host_dict[host]['ids']

            if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                self._delete_dummynet_pipe(host_ids.upload_id)
            if (direction & Direction.INCOMING) == Direction.INCOMING:
                self._delete_dummynet_pipe(host_ids.download_id)

            del self._host_dict[host]

        # Remove rules for this host and regenerate
        self._remove_host_rules(host, direction)
        self._load_all_pfctl_rules()

        host.limited = False
        host.blocked = False

    def replace(self, old_host, new_host):
        self._host_dict_lock.acquire()
        info = self._host_dict[old_host] if old_host in self._host_dict else None
        self._host_dict_lock.release()

        if info is not None:
            self.unlimit(old_host, Direction.BOTH)

            if info['rate'] is None:
                self.block(new_host, info['direction'])
            else:
                self.limit(new_host, info['direction'], info['rate'])

    def _new_host_limit_ids(self, host, direction):
        """
        Get limit information for corresponding host
        If not present, create new 
        """
        host_ids = None

        self._host_dict_lock.acquire()
        present = host in self._host_dict
        self._host_dict_lock.release()

        if present:
                host_ids = self._host_dict[host]['ids']
                self.unlimit(host, direction)
        
        return MacOSLimiter.HostLimitIDs(*self._create_ids()) if host_ids is None else host_ids

    def _create_ids(self):
        """
        Returns unique IDs that are
        currently not in use
        """
        def generate_id(*exc):
            """
            Generates a unique, unused ID
            exc: IDs that will not be used (exceptions)
            """
            id_ = 1
            with self._host_dict_lock:
                while True:
                    if id_ not in exc:
                        v = (x for x in self._host_dict.values())
                        ids = (x['ids'] for x in v)
                        if id_ not in (x for y in ids for x in [y.upload_id, y.download_id]):
                            return id_
                    id_ += 1

        id1 = generate_id()
        return (id1, generate_id(id1))

    def _delete_dummynet_pipe(self, pipe_id):
        """
        Deletes a dummynet pipe
        """
        shell.execute_suppressed('{} pipe delete {}'.format(BIN_DNCTL, pipe_id))

    def _generate_pfctl_rules(self, host, direction, host_ids, rate):
        """
        Generates pfctl rules for bandwidth limiting
        """
        new_rules = []
        
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # For upload limiting, match packets from the host
            rule = 'dummynet out quick on {} inet from {} to any pipe {}'.format(
                self.interface, host.ip, host_ids.upload_id)
            new_rules.append(rule)
            self._active_rules.append(rule)
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # For download limiting, match packets to the host
            rule = 'dummynet in quick on {} inet from any to {} pipe {}'.format(
                self.interface, host.ip, host_ids.download_id)
            new_rules.append(rule)
            self._active_rules.append(rule)
        
        self._load_all_pfctl_rules()

    def _generate_dns_redirect_rules(self, host, redirect_ip):
        """
        Generates pfctl NAT rules for DNS redirection to our DNS server
        """
        # Redirect DNS queries regardless of destination DNS server
        # Use 'pass' to ensure the rule matches
        dns_nat_udp = 'rdr pass on {} inet proto udp from {} to any port 53 -> {} port 5354'.format(
            self.interface, host.ip, redirect_ip)
        dns_nat_tcp = 'rdr pass on {} inet proto tcp from {} to any port 53 -> {} port 5354'.format(
            self.interface, host.ip, redirect_ip)
        
        # Store DNS rules separately so they persist
        self._dns_rules[host.ip] = [dns_nat_udp, dns_nat_tcp]
        
        # Load all rules including NAT
        self._load_all_rules()

    def _generate_pfctl_blocking_rules(self, host, direction):
        """
        Generates pfctl rules for blocking traffic
        """
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            rule = 'block out quick on {} from {}'.format(self.interface, host.ip)
            self._active_rules.append(rule)
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            rule = 'block in quick on {} to {}'.format(self.interface, host.ip)
            self._active_rules.append(rule)
        
        self._load_all_pfctl_rules()

    def _regenerate_pfctl_rules(self):
        """
        Regenerates all pfctl rules for currently limited/blocked hosts
        """
        # Clear existing rules and rebuild from host dict
        self._active_rules = []
        
        with self._host_dict_lock:
            for host, info in self._host_dict.items():
                direction = info['direction']
                rate = info['rate']
                host_ids = info['ids']
                
                if rate is None:  # Blocked host
                    if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                        self._active_rules.append('block out quick on {} from {}'.format(self.interface, host.ip))
                    if (direction & Direction.INCOMING) == Direction.INCOMING:
                        self._active_rules.append('block in quick on {} to {}'.format(self.interface, host.ip))
                else:  # Limited host
                    if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                        self._active_rules.append('dummynet out quick on {} inet from {} to any pipe {}'.format(
                            self.interface, host.ip, host_ids.upload_id))
                    if (direction & Direction.INCOMING) == Direction.INCOMING:
                        self._active_rules.append('dummynet in quick on {} inet from any to {} pipe {}'.format(
                            self.interface, host.ip, host_ids.download_id))
        
        self._load_all_pfctl_rules()

    def _load_all_pfctl_rules(self):
        """
        Loads all accumulated pfctl rules
        """
        # Create temporary rules file
        if self._rules_file is None:
            fd, self._rules_file = tempfile.mkstemp(suffix='.pf', text=True)
            os.close(fd)
        
        # Combine DNS rules and active rules
        all_dns_rules = []
        for host_ip, rules in self._dns_rules.items():
            all_dns_rules.extend(rules)
        
        all_rules = all_dns_rules + self._active_rules
        
        # Debug: print what we're writing
        print(f"DEBUG: Writing {len(all_rules)} rules to {self._rules_file}")
        for rule in all_rules:
            print(f"DEBUG: Rule: {rule}")
        
        with open(self._rules_file, 'w') as f:
            # Write all rules (DNS rules first, then active rules)
            f.write('\n'.join(all_rules))
            f.write('\n')
        
        # Also save a copy for debugging
        debug_file = '/tmp/evillimiter_debug.pf'
        with open(debug_file, 'w') as f:
            f.write('\n'.join(self._active_rules))
            f.write('\n')
        print(f"DEBUG: Rules also saved to {debug_file}")
        
        # Ensure pfctl is enabled before loading rules
        shell.execute_suppressed('{} -e'.format(BIN_PFCTL))
        
        # Load the filter rules
        result = shell.execute_suppressed('{} -f {}'.format(BIN_PFCTL, self._rules_file))
        print(f"DEBUG: pfctl -f result: {result}")
    
    def _load_all_rules(self):
        """
        Loads both filter and NAT rules for pfctl
        """
        # First load filter rules
        self._load_all_pfctl_rules()
        
        # Then load NAT rules if any
        if self._dns_rules:
            # Create temporary file with both NAT and filter rules
            fd, combined_file = tempfile.mkstemp(suffix='.pf', text=True)
            os.close(fd)
            
            with open(combined_file, 'w') as f:
                # Write NAT rules first (separate section)
                for rules in self._dns_rules.values():
                    f.write('\n'.join(rules))
                    f.write('\n')
                
                # Then write filter rules
                if self._active_rules:
                    f.write('\n'.join(self._active_rules))
                    f.write('\n')
            
            # Enable pfctl if not already enabled
            shell.execute_suppressed('{} -e'.format(BIN_PFCTL))
            
            # Load NAT rules first with -N flag
            result_nat = shell.execute_suppressed('{} -N -f {}'.format(BIN_PFCTL, combined_file))
            # Then load filter rules with -R flag  
            result_filter = shell.execute_suppressed('{} -R -f {}'.format(BIN_PFCTL, combined_file))
            print(f"DEBUG: pfctl NAT result: {result_nat}, filter result: {result_filter}")
            
            # Debug: show what was loaded
            with open(combined_file, 'r') as f:
                print(f"DEBUG: Combined rules file contents:")
                print(f.read())
            
            # Clean up
            os.unlink(combined_file)

    def _remove_host_rules(self, host, direction):
        """
        Remove rules for a specific host
        """
        # Filter out rules for this host
        self._active_rules = [rule for rule in self._active_rules 
                            if not (host.ip in rule and self.interface in rule)]
        
        # Also remove DNS rules for this host
        if host.ip in self._dns_rules:
            del self._dns_rules[host.ip]

    def cleanup(self):
        """
        Cleanup temporary files
        """
        if self._rules_file and os.path.exists(self._rules_file):
            os.unlink(self._rules_file)


class Direction:
    NONE = 0
    OUTGOING = 1
    INCOMING = 2
    BOTH = 3

    def pretty_direction(direction):
        if direction == Direction.OUTGOING:
            return 'upload'
        elif direction == Direction.INCOMING:
            return 'download'
        elif direction == Direction.BOTH:
            return 'upload / download'
        else:
            return '-'