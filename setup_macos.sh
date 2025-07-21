#!/bin/bash
# Setup script for evillimiter on macOS

echo "Setting up macOS for evillimiter..."

# Enable IP forwarding
echo "Enabling IP forwarding..."
sudo sysctl -w net.inet.ip.forwarding=1

# Enable pfctl
echo "Enabling pfctl..."
sudo pfctl -e 2>/dev/null || true

# Load dummynet kernel extension if needed
echo "Checking dummynet..."
if ! kextstat | grep -q dummynet; then
    echo "Loading dummynet kernel extension..."
    sudo kextload /System/Library/Extensions/dummynet.kext 2>/dev/null || true
fi

# Disable ICMP redirects (can interfere with spoofing)
echo "Disabling ICMP redirects..."
sudo sysctl -w net.inet.ip.redirect=0
sudo sysctl -w net.inet.icmp.drop_redirect=1

echo "Setup complete!"
echo ""
echo "To test if ARP spoofing is working:"
echo "1. Run: sudo tcpdump -i en0 host <target_ip> -n"
echo "2. Start evillimiter and limit the target"
echo "3. Check if you see traffic from the target in tcpdump"