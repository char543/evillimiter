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

1. **Install Python:**

   ```bash
   brew install python
   ```

2. **Clone into a folder macOS does _not_ protect:**

   This tool runs as **root**, and macOS (TCC / System Integrity Protection)
   blocks root from reading certain folders. If the project — or its Python
   virtualenv — lives in a protected folder, `sudo` fails with
   `Operation not permitted`.

   **Avoid** these locations: `~/Downloads`, `~/Desktop`, `~/Documents`,
   iCloud Drive, and external or network volumes.

   **Use** a plain folder under your home directory instead, for example:

   ```bash
   # any of these are fine (not TCC-protected):
   #   ~/evillimiter        ~/src/evillimiter        ~/dev/evillimiter
   git clone https://github.com/<you>/evillimiter.git ~/evillimiter
   cd ~/evillimiter
   ```

3. **Create a project-local virtualenv and install dependencies:**

   Keeping the venv inside the project folder (not under `~/Library`) is what
   lets `sudo` run it without hitting TCC.

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
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

Run from the project folder using the virtualenv's Python:

```bash
# Run with administrator privileges
sudo PYTHONDONTWRITEBYTECODE=1 .venv/bin/python bin/evillimiter

# Or with a specific interface
sudo PYTHONDONTWRITEBYTECODE=1 .venv/bin/python bin/evillimiter -i en0
```

`PYTHONDONTWRITEBYTECODE=1` stops Python from writing `.pyc` cache files as
root inside the virtualenv. Without it, root-owned cache files accumulate and
later break `pip` with `Permission denied`. `sudo` drops environment variables
by default, so the variable is set inline, before the command.

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

2. **Permission denied / Operation not permitted:**

   - EvilLimiter requires root privileges on macOS, so run it with `sudo`
   - `Operation not permitted` under `sudo` means the project or its virtualenv
     sits in a TCC-protected folder (`~/Downloads`, `~/Desktop`, `~/Documents`,
     iCloud, external/network volumes). Move it to a plain home folder such as
     `~/evillimiter` (see Installation)
   - `Permission denied` from `pip`/`pipx` usually means an earlier `sudo` run
     left root-owned `.pyc` files in the virtualenv. Delete the venv with
     `sudo rm -rf .venv`, recreate it, and always launch with
     `PYTHONDONTWRITEBYTECODE=1` (see Usage)

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
