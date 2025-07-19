import evillimiter.console.shell as shell
import platform

BROADCAST = 'ff:ff:ff:ff:ff:ff'

# macOS-specific binaries
BIN_PFCTL = shell.locate_bin('pfctl')
BIN_DNCTL = shell.locate_bin('dnctl')
BIN_SYSCTL = shell.locate_bin('sysctl')
BIN_IFCONFIG = shell.locate_bin('ifconfig')

# IP forwarding on macOS
IP_FORWARD_LOC = 'net.inet.ip.forwarding'

# Determine if running on Apple Silicon
IS_APPLE_SILICON = platform.machine() == 'arm64'