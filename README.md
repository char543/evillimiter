# EvilLimiter - macOS Support

This document describes the macOS-specific features and setup for EvilLimiter.

## Overview

EvilLimiter has been updated to support macOS alongside Linux. The macOS implementation uses:

- **pfctl** (Packet Filter) for firewall rules and traffic blocking
- **dummynet** via **dnctl** for bandwidth limiting
- **sysctl** for IP forwarding configuration
- Standard networking libraries (netifaces, scapy) for interface detection and packet manipulation

## System Requirements

- macOS 10.15 (Catalina) or later
- Python 3.7 or later
- Administrator/root privileges
- Xcode Command Line Tools (for development)

## Installation

1. **Install python, pip & dependencies:**

   ```bash
   brew install python pipx
   pipx ensurepath
   ```

2. **Install the package:**

   Clone the repo then:

   ```bash
   cd evillimiter
   pipx install .
   ```

## macOS-Specific Features

### Bandwidth Limiting

- Uses **dummynet pipes** instead of Linux traffic control (tc)
- Configured via `dnctl` command
- Integrates with pfctl for packet classification

### Firewall Rules

- Uses **pfctl** instead of iptables
- Rules are dynamically generated and loaded from temporary files
- Supports both blocking and bandwidth limiting rules

### Network Interface Handling

- Compatible with macOS network interface naming (en0, en1, etc.)
- Uses netifaces library for cross-platform interface detection
- Supports both Intel and Apple Silicon Macs

## Usage

The usage is identical to the Linux version:

```bash
# Run with administrator privileges
sudo evillimiter

# Or with specific interface
sudo evillimiter -i en0
```

## Platform Differences

| Feature         | Linux               | macOS                  |
| --------------- | ------------------- | ---------------------- |
| Traffic Control | tc (htb qdisc)      | dummynet pipes         |
| Firewall        | iptables            | pfctl                  |
| IP Forwarding   | net.ipv4.ip_forward | net.inet.ip.forwarding |
| Interface Names | eth0, wlan0         | en0, en1               |

## Troubleshooting

### Common Issues

1. **"Missing util" errors:**

   - Ensure you're running on a supported macOS version
   - Check that system utilities are in standard locations (/usr/bin, /sbin, etc.)

2. **Permission denied:**

   - EvilLimiter requires root privileges on macOS
   - Run with `sudo`

3. **pfctl errors:**

   - Disable any other firewall software
   - Check that pfctl is not already in use by other applications

4. **Network interface not found:**
   - Use `ifconfig` to list available interfaces
   - Specify the interface manually with `-i` flag

### Testing Installation

Run the test script to verify macOS compatibility:

```bash
python3 test_macos.py
```

## Security Considerations

- pfctl rules are temporary and removed when the application exits
- IP forwarding is restored to original state on cleanup
- Temporary rule files are securely created and cleaned up

## Architecture Support

EvilLimiter supports both:

- Intel Macs (x86_64)
- Apple Silicon Macs (arm64)

The implementation automatically detects the architecture and uses appropriate system paths.

## Known Limitations

1. **System Integrity Protection (SIP):** Some operations may be restricted on systems with SIP enabled
2. **Network Extensions:** macOS network extensions may interfere with packet manipulation
3. **Sandboxing:** The application must run outside of App Store sandbox restrictions

## Development

For developers working on macOS support:

- Main platform detection in `evillimiter/common/globals.py`
- macOS-specific limiter in `evillimiter/networking/limit_macos.py`
- Cross-platform utilities in `evillimiter/networking/utils.py`
- Shell execution handling in `evillimiter/console/shell.py`
