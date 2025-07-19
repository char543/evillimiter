#!/usr/bin/env python3
"""
Test script for captive portal DNS redirection functionality.
This simulates the behavior of public Wi-Fi captive portals.
"""

import sys
import time
from evillimiter.networking.dns_spoof import DNSSpoofer
from evillimiter.networking.host import Host

def test_dns_spoofer():
    """Test DNS spoofer functionality"""
    print("Testing DNS Spoofer module...")
    
    # Create test configuration
    interface = "en0"  # Example interface
    redirect_ip = "192.168.1.100"  # Example captive portal server IP
    
    # Create DNS spoofer instance
    dns_spoofer = DNSSpoofer(interface, redirect_ip)
    
    # Create test host
    test_host = Host("192.168.1.50", "aa:bb:cc:dd:ee:ff", "test-host")
    
    print(f"DNS Spoofer created:")
    print(f"  Interface: {interface}")
    print(f"  Redirect IP: {redirect_ip}")
    
    # Add host to spoofer
    dns_spoofer.add(test_host)
    print(f"\nAdded host to DNS spoofer: {test_host.ip}")
    
    # Start DNS spoofer
    dns_spoofer.start()
    print("\nDNS spoofer started. It will now redirect DNS queries from the target host.")
    print("This simulates a captive portal behavior.")
    
    # Run for a short time
    print("\nRunning for 10 seconds...")
    time.sleep(10)
    
    # Stop DNS spoofer
    dns_spoofer.stop()
    print("\nDNS spoofer stopped.")
    
    print("\nTest completed successfully!")

if __name__ == "__main__":
    print("Captive Portal DNS Redirection Test")
    print("===================================")
    print("This test demonstrates DNS redirection functionality")
    print("similar to public Wi-Fi captive portals.\n")
    
    try:
        test_dns_spoofer()
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
    except Exception as e:
        print(f"\nError during test: {e}")
        sys.exit(1)