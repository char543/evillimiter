#!/usr/bin/env python3
"""
Test script for macOS compatibility of evillimiter
"""

import platform
import sys
import os

# Add the current directory to the path so we can import evillimiter
sys.path.insert(0, os.path.dirname(__file__))

def test_imports():
    """Test that all modules can be imported on macOS"""
    print("Testing imports...")
    
    try:
        from evillimiter.common.globals import IS_MACOS, IS_LINUX
        print(f"✓ OS Detection: macOS={IS_MACOS}, Linux={IS_LINUX}")
        
        if IS_MACOS:
            from evillimiter.common.globals import BIN_PFCTL, BIN_DNCTL, BIN_SYSCTL
            print(f"✓ macOS binaries detected: pfctl={BIN_PFCTL}, dnctl={BIN_DNCTL}")
        
        from evillimiter.networking.utils import get_default_interface, get_default_gateway
        print("✓ Network utilities imported")
        
        from evillimiter.networking.limit import create_limiter
        print("✓ Limiter factory imported")
        
        from evillimiter.networking.spoof import ARPSpoofer
        print("✓ ARP spoofer imported")
        
        print("All imports successful!")
        return True
        
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False

def test_network_detection():
    """Test network interface and gateway detection"""
    print("\nTesting network detection...")
    
    try:
        from evillimiter.networking.utils import get_default_interface, get_default_gateway, get_default_netmask
        
        interface = get_default_interface()
        print(f"✓ Default interface: {interface}")
        
        gateway = get_default_gateway()
        print(f"✓ Default gateway: {gateway}")
        
        if interface:
            netmask = get_default_netmask(interface)
            print(f"✓ Netmask for {interface}: {netmask}")
        
        return True
        
    except Exception as e:
        print(f"✗ Network detection error: {e}")
        return False

def test_limiter_creation():
    """Test limiter creation for macOS"""
    print("\nTesting limiter creation...")
    
    try:
        from evillimiter.networking.limit import create_limiter
        from evillimiter.networking.utils import get_default_interface
        
        interface = get_default_interface()
        if not interface:
            print("✗ No default interface found")
            return False
            
        limiter = create_limiter(interface)
        print(f"✓ Limiter created for interface {interface}: {type(limiter).__name__}")
        
        return True
        
    except Exception as e:
        print(f"✗ Limiter creation error: {e}")
        return False

def test_privilege_check():
    """Test privilege detection"""
    print("\nTesting privilege detection...")
    
    try:
        from evillimiter.evillimiter import is_privileged
        
        privileged = is_privileged()
        print(f"✓ Running as root: {privileged}")
        
        if not privileged:
            print("ⓘ Note: Some functionality requires root privileges")
        
        return True
        
    except Exception as e:
        print(f"✗ Privilege check error: {e}")
        return False

def main():
    """Main test function"""
    print(f"Testing evillimiter on {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {sys.version}")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_network_detection,
        test_limiter_creation,
        test_privilege_check
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! evillimiter should work on this macOS system.")
    else:
        print("✗ Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)