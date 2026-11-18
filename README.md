# EvilLimiter - macOS Support

This document describes the macOS-specific features and setup for EvilLimiter.

## Overview

EvilLimiter has been updated to support macOS alongside Linux. The macOS implementation uses:

- **pfctl** (Packet Filter) for firewall rules and traffic blocking
- **dummynet** via **dnctl** for bandwidth limiting
- **sysctl** for IP forwarding configuration
- Standard networking libraries (netifaces, scapy) for interface detection and packet manipulation

## Feature status

| Feature | Status |
| ------- | ------ |
| Host discovery (`scan`, `hosts`), including IPv6 | Working |
| Bandwidth limiting (`limit`, IPv4 and IPv6) | Working (queue sized to the rate) |
| Blocking (`block`, IPv4 and IPv6) | Working |
| DNS redirection (`redirect --dns` / `--to`) | Working, via DNS injection |
| Enforcement (`--harden` / `--lockdown`, force-IPv4) | Working |
| HTTPS/HTTP interception (`redirect --mitm`) | Works for clients that trust the CA or don't strictly validate |

Redirection is done by **DNS injection**: the tool sniffs the target's DNS
(while ARP-spoofed) and injects forged answers, which is reliable on macOS where
transparent `pf rdr` is not. `--dns` maps one domain to an IP; `--to` maps every
domain to one IP; `--harden` blocks DoT/DoH and the Private-Relay/DoH canaries so
the device falls back to the plain DNS we forge; `--lockdown` allows only DNS,
DHCP and the target.

`--mitm` adds a full HTTPS/HTTP intercepting proxy: a local CA (generated once in
`~/.evillimiter/ca/`) mints a per-host certificate on the fly, the proxy
terminates TLS, relays to the real site, and logs every request. It intercepts
any client that trusts the CA (install `evillimiter-ca.crt` on devices you
control) or that does not strictly validate certificates. A strict browser on a
pinned or HSTS-preloaded site still needs the CA installed on the device, which
is a property of TLS, not of this tool.

## System Requirements

- macOS 10.15 (Catalina) or later
- Python 3.7 or later
- Administrator/root privileges
- Xcode Command Line Tools (for development)

## Quick start

The fastest path is the launcher script, `run.sh` in the repo root. It:

- clones the project to `~/evillimiter` only if it isn't already there, otherwise reuses the existing checkout;
- creates the virtualenv and installs dependencies on the first run only, skipping it if `.venv` exists;
- runs the tool as root, passing any arguments straight through.

```bash
# existing checkout
~/evillimiter/run.sh

# with arguments (e.g. choose the interface)
~/evillimiter/run.sh -i en0

# force a fresh dependency install
rm -rf ~/evillimiter/.venv && ~/evillimiter/run.sh
```

On a brand-new machine, save `run.sh` first (or `curl` its raw URL) and run it; it will clone and set everything up. The setup steps run as your user, so the virtualenv stays user-owned, and only the tool itself runs under `sudo`.

For the manual steps, see [Installation](#installation) below.

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

The easiest way to run is the launcher: `~/evillimiter/run.sh` (see [Quick start](#quick-start)). To run manually from the project folder with the virtualenv's Python:

```bash
# Run with administrator privileges
sudo .venv/bin/python bin/evillimiter

# Or with a specific interface
sudo .venv/bin/python bin/evillimiter -i en0
```

The launcher `bin/evillimiter` disables Python bytecode writing itself
(`sys.dont_write_bytecode = True`), so running as root never leaves root-owned
`.pyc` files in the virtualenv that would later break `pip`. You no longer need
to pass `PYTHONDONTWRITEBYTECODE`.

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
