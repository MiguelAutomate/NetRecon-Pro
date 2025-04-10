#!/usr/bin/env python3
"""
Example: Web Server Security Audit
Demonstrates how to perform a security audit of web servers,
including SSL/TLS configuration and common web ports
"""
import sys
import asyncio
import json
from datetime import datetime
sys.path.append('..')
from netrecon import NetRecon, ScanTools

async def audit_web_server(target: str) -> dict:
    scanner = NetRecon()
    tools = ScanTools()
    
    print(f"Starting security audit of {target}")
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scans": {}
    }
    
    # Check SSL/TLS configuration
    print("Checking SSL/TLS configuration...")
    results["scans"]["ssl"] = await tools.ssl_scan(target)
    
    # Scan common web ports
    print("Scanning web ports...")
    web_ports = "80,443,8080,8443"
    results["scans"]["ports"] = await tools.nmap_scan(
        target,
        ports=web_ports,
        aggressive=True  # Use -sV for service version detection
    )
    
    # DNS information
    print("Gathering DNS information...")
    results["scans"]["dns"] = await tools.nslookup(target)
    
    # WHOIS information
    print("Getting domain information...")
    results["scans"]["whois"] = await tools.whois_lookup(target)
    
    return results

async def main():
    if len(sys.argv) < 2:
        print("Usage: python web_security_audit.py <domain>")
        sys.exit(1)
        
    target = sys.argv[1]
    results = await audit_web_server(target)
    
    # Save results
    filename = f"security_audit_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nAudit complete. Results saved to {filename}")

if __name__ == "__main__":
    asyncio.run(main())