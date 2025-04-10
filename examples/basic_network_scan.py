#!/usr/bin/env python3
"""
Example: Basic Network Scan
Demonstrates basic usage of NetRecon for network scanning
"""
import sys
import asyncio
import json
from datetime import datetime
sys.path.append('..')
from netrecon import NetRecon, ScanTools

async def basic_scan(target: str) -> dict:
    scanner = NetRecon()
    tools = ScanTools()
    
    print(f"Starting basic scan of {target}")
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scans": {}
    }
    
    # Basic connectivity test
    print("Testing connectivity...")
    results["scans"]["ping"] = await tools.ping(target)
    
    # Traceroute to see network path
    print("Running traceroute...")
    results["scans"]["traceroute"] = await tools.traceroute(target)
    
    # Basic port scan of common ports
    print("Scanning common ports...")
    results["scans"]["ports"] = await tools.nmap_scan(
        target,
        ports="21-23,25,53,80,110,143,443,3389"
    )
    
    return results

async def main():
    if len(sys.argv) < 2:
        print("Usage: python basic_network_scan.py <target>")
        sys.exit(1)
        
    target = sys.argv[1]
    results = await basic_scan(target)
    
    # Save results
    filename = f"basic_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nScan complete. Results saved to {filename}")

if __name__ == "__main__":
    asyncio.run(main())