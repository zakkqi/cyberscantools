# backend/tests/test_zap_scanner.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.web_vulnerability_scanner import WebVulnerabilityScanner

def test_zap_connection():
    """Test ZAP connectivity"""
    scanner = WebVulnerabilityScanner()
    connected, message = scanner.test_connection()
    print(f"ZAP Connection: {message}")
    return connected

def test_basic_scan():
    """Test basic scan functionality"""
    scanner = WebVulnerabilityScanner()
    
    # Test connection first
    connected, message = scanner.test_connection()
    if not connected:
        print(f"Cannot connect to ZAP: {message}")
        return
    
    # Test scan
    print("\nTesting basic scan on test website...")
    target = "http://testphp.vulnweb.com"
    results = scanner.simple_scan(target)
    
    if 'error' in results:
        print(f"Scan error: {results['error']}")
    else:
        print(f"Scan completed!")
        print(f"Target: {results['target']}")
        print(f"Total alerts: {results['total_alerts']}")
        
        # Show first 3 vulnerabilities
        for i, alert in enumerate(results['alerts'][:3]):
            print(f"\nVulnerability {i+1}:")
            print(f"  Name: {alert['name']}")
            print(f"  Risk: {alert['risk']}")
            print(f"  URL: {alert['url']}")

def test_passive_scan():
    """Test passive scan only"""
    scanner = WebVulnerabilityScanner()
    
    connected, message = scanner.test_connection()
    if not connected:
        print(f"Cannot connect to ZAP: {message}")
        return
    
    print("\nTesting passive scan...")
    results = scanner.passive_scan("http://example.com")
    
    if 'error' in results:
        print(f"Scan error: {results['error']}")
    else:
        print(f"Passive scan completed!")
        print(f"Total alerts: {results['total_alerts']}")

if __name__ == "__main__":
    print("=== ZAP Scanner Test ===\n")
    
    # Test 1: Connection
    print("1. Testing ZAP connection...")
    if test_zap_connection():
        print("✓ ZAP connection successful\n")
        
        # Test 2: Basic scan
        print("2. Testing basic scan...")
        test_basic_scan()
        
        # Test 3: Passive scan
        print("\n3. Testing passive scan...")
        test_passive_scan()
    else:
        print("✗ ZAP connection failed. Please ensure ZAP is running on port 8080")