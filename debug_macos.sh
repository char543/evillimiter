#!/bin/bash
# Debug script for evillimiter on macOS

echo "=== macOS Network Debug ==="
echo "Date: $(date)"
echo ""

echo "1. IP Forwarding Status:"
sysctl net.inet.ip.forwarding
echo ""

echo "2. pfctl Status:"
sudo pfctl -s info 2>/dev/null || echo "pfctl not enabled or error"
echo ""

echo "3. pfctl Rules:"
sudo pfctl -s rules 2>/dev/null || echo "No pfctl rules or error"
echo ""

echo "4. dummynet Pipes:"
sudo dnctl list 2>/dev/null || echo "No dummynet pipes or error"
echo ""

echo "5. Network Interface Info:"
ifconfig en0 | grep -E "(inet |ether )"
echo ""

echo "6. Default Route:"
route -n get default | grep -E "(gateway|interface)"
echo ""

echo "7. ARP Table (gateway):"
arp -a | grep "192.168.1.1"
echo ""

echo "8. Kernel Extensions:"
kextstat | grep -E "(pfctl|dummynet|ipfw)" || echo "No relevant kernel extensions loaded"
echo ""

echo "=== End Debug ==="