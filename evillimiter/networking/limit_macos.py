import threading
import tempfile
import os
import warnings

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL


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

    def limit(self, host, direction, rate):
        """
        Limits the upload/download traffic of a host
        to a specified rate using pfctl and dummynet
        """
        host_ids = self._new_host_limit_ids(host, direction)

        # Create dummynet pipes for bandwidth limiting
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            shell.execute_suppressed('{} pipe {} config bw {}'.format(BIN_DNCTL, host_ids.upload_id, rate))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            shell.execute_suppressed('{} pipe {} config bw {}'.format(BIN_DNCTL, host_ids.download_id, rate))

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

        # Regenerate pfctl rules without this host
        self._regenerate_pfctl_rules()

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
        rules = []
        
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            rules.append('pass out quick on {} from {} to any dnpipe {}'.format(
                self.interface, host.ip, host_ids.upload_id))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            rules.append('pass in quick on {} from any to {} dnpipe {}'.format(
                self.interface, host.ip, host_ids.download_id))
        
        self._load_pfctl_rules(rules)

    def _generate_pfctl_blocking_rules(self, host, direction):
        """
        Generates pfctl rules for blocking traffic
        """
        rules = []
        
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            rules.append('block out quick on {} from {}'.format(self.interface, host.ip))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            rules.append('block in quick on {} to {}'.format(self.interface, host.ip))
        
        self._load_pfctl_rules(rules)

    def _regenerate_pfctl_rules(self):
        """
        Regenerates all pfctl rules for currently limited/blocked hosts
        """
        rules = []
        
        with self._host_dict_lock:
            for host, info in self._host_dict.items():
                direction = info['direction']
                rate = info['rate']
                host_ids = info['ids']
                
                if rate is None:  # Blocked host
                    if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                        rules.append('block out quick on {} from {}'.format(self.interface, host.ip))
                    if (direction & Direction.INCOMING) == Direction.INCOMING:
                        rules.append('block in quick on {} to {}'.format(self.interface, host.ip))
                else:  # Limited host
                    if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                        rules.append('pass out quick on {} from {} to any dnpipe {}'.format(
                            self.interface, host.ip, host_ids.upload_id))
                    if (direction & Direction.INCOMING) == Direction.INCOMING:
                        rules.append('pass in quick on {} from any to {} dnpipe {}'.format(
                            self.interface, host.ip, host_ids.download_id))
        
        self._load_pfctl_rules(rules)

    def _load_pfctl_rules(self, rules):
        """
        Loads pfctl rules from a list
        """
        # Create temporary rules file
        if self._rules_file is None:
            fd, self._rules_file = tempfile.mkstemp(suffix='.pf', text=True)
            os.close(fd)
        
        with open(self._rules_file, 'w') as f:
            f.write('\n'.join(rules))
            f.write('\n')
        
        # Load the rules
        shell.execute_suppressed('{} -f {}'.format(BIN_PFCTL, self._rules_file))

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