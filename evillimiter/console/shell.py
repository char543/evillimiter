import os
import platform
import subprocess
from evillimiter.console.io import IO

DEVNULL = open(os.devnull, 'w')


def execute(command, root=True):
    if root and platform.system() == 'Darwin':
        # On macOS, ensure we use the full path to sudo
        return subprocess.call('/usr/bin/sudo ' + command, shell=True)
    elif root:
        return subprocess.call('sudo ' + command, shell=True)
    else:
        return subprocess.call(command, shell=True)


def execute_suppressed(command, root=True):
    if root and platform.system() == 'Darwin':
        # On macOS, ensure we use the full path to sudo
        return subprocess.call('/usr/bin/sudo ' + command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    elif root:
        return subprocess.call('sudo ' + command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    else:
        return subprocess.call(command, shell=True, stdout=DEVNULL, stderr=DEVNULL)


def output(command, root=True):
    if root and platform.system() == 'Darwin':
        # On macOS, ensure we use the full path to sudo
        return subprocess.check_output('/usr/bin/sudo ' + command, shell=True).decode('utf-8')
    elif root:
        return subprocess.check_output('sudo ' + command, shell=True).decode('utf-8')
    else:
        return subprocess.check_output(command, shell=True).decode('utf-8')


def output_suppressed(command, root=True):
    if root and platform.system() == 'Darwin':
        # On macOS, ensure we use the full path to sudo
        return subprocess.check_output('/usr/bin/sudo ' + command, shell=True, stderr=DEVNULL).decode('utf-8')
    elif root:
        return subprocess.check_output('sudo ' + command, shell=True, stderr=DEVNULL).decode('utf-8')
    else:
        return subprocess.check_output(command, shell=True, stderr=DEVNULL).decode('utf-8')


def locate_bin(name):
    try:
        # On macOS, add common system paths
        if platform.system() == 'Darwin':
            paths = ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
            for path in paths:
                full_path = os.path.join(path, name)
                if os.path.exists(full_path) and os.access(full_path, os.X_OK):
                    return full_path
        
        return output_suppressed('which {}'.format(name)).replace('\n', '')
    except subprocess.CalledProcessError:
        IO.error('missing util: {}, check your PATH'.format(name))
        return None