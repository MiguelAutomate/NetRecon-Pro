#!/usr/bin/env python3
"""
NetRecon Pro - Advanced Network Reconnaissance Tool
"""
import argparse
import asyncio
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime
from typing import List, Dict, Union
import subprocess
import ssl
import dns.resolver
import whois
import requests
import yaml
from geoip2.database import Reader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("netrecon")

# Load configuration
with open("config.yaml") as f:
    config = yaml.safe_load(f)

class ScanTools:
    """Collection of network scanning and reconnaissance tools"""
    
    def __init__(self):
        self.timeout = config["scan"]["timeout"]
    
    async def ping(self, target: str) -> Dict:
        """Perform ICMP ping to check host availability"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '3', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def traceroute(self, target: str) -> Dict:
        """Perform traceroute to show network path"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'traceroute', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def nmap_scan(self, target: str, ports: str = None, aggressive: bool = False) -> Dict:
        """Perform port scan using nmap"""
        try:
            cmd = ['nmap', '-oX', '-']
            if aggressive:
                cmd.extend(['-sV', '-sC'])
            if ports:
                cmd.extend(['-p', ports])
            cmd.append(target)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def ssl_scan(self, target: str) -> Dict:
        """Check SSL/TLS configuration"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.connect((target, 443))
                cert = s.getpeercert()
                return {
                    "success": True,
                    "version": s.version(),
                    "cipher": s.cipher(),
                    "certificate": cert
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def nslookup(self, target: str) -> Dict:
        """Perform DNS lookups"""
        try:
            resolver = dns.resolver.Resolver()
            results = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = resolver.resolve(target, record_type)
                    results[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    results[record_type] = []
            return {"success": True, "records": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def whois_lookup(self, target: str) -> Dict:
        """Perform WHOIS lookup"""
        try:
            result = whois.whois(target)
            return {
                "success": True,
                "data": result
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

class NetRecon:
    def __init__(self):
        self.timeout = config["scan"]["timeout"]
        self.max_threads = config["scan"]["max_threads"]
        self.common_ports = config["scan"]["common_ports"]
        self.geoip_reader = Reader(config["geolocation"]["maxmind_db"]) if config["geolocation"].get("maxmind_db") else None
        self.tools = ScanTools()

    async def async_scan_port(self, ip: str, port: int) -> Union[int, None]:
        """Asynchronous port scanner with rate limiting"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

    async def scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan multiple ports asynchronously"""
        open_ports = []
        tasks = [self.async_scan_port(ip, port) for port in ports]
        
        for task in asyncio.as_completed(tasks):
            port = await task
            if port:
                open_ports.append(port)
            time.sleep(0.05)  # Rate limiting
        
        return sorted(open_ports)

    def get_geolocation(self, ip: str) -> Dict:
        """Multi-provider geolocation lookup"""
        try:
            if self.geoip_reader:
                response = self.geoip_reader.city(ip)
                return {
                    "Country": response.country.name,
                    "City": response.city.name,
                    "ISP": "Unknown",
                    "Latitude": response.location.latitude,
                    "Longitude": response.location.longitude,
                    "Source": "MaxMind"
                }
            
            # Fallback to IP-API
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = resp.json()
            if data["status"] == "success":
                return {
                    "Country": data.get("country"),
                    "Region": data.get("regionName"),
                    "City": data.get("city"),
                    "ISP": data.get("isp"),
                    "Latitude": data.get("lat"),
                    "Longitude": data.get("lon"),
                    "Source": "IP-API"
                }
        except Exception as e:
            logger.error(f"Geolocation failed: {e}")
        
        return {"Error": "Geolocation unavailable"}

    def save_results(self, data: Dict, format: str = "json") -> None:
        """Save scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.{format}"
        
        try:
            with open(filename, "w") as f:
                if format == "json":
                    json.dump(data, f, indent=4)
                else:  # CSV
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(data.keys())
                    writer.writerow(data.values())
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    async def comprehensive_scan(self, target: str, scan_type: str = "all", ports: str = None, aggressive: bool = False) -> Dict:
        """Perform a comprehensive scan or specific scan type"""
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "results": {}
        }
        
        try:
            if scan_type in ["all", "ping"]:
                results["results"]["ping"] = await self.tools.ping(target)
                
            if scan_type in ["all", "traceroute"]:
                results["results"]["traceroute"] = await self.tools.traceroute(target)
                
            if scan_type in ["all", "nmap"]:
                results["results"]["nmap"] = await self.tools.nmap_scan(target, ports, aggressive)
                
            if scan_type in ["all", "ssl"]:
                results["results"]["ssl"] = await self.tools.ssl_scan(target)
                
            if scan_type in ["all", "dns"]:
                results["results"]["dns"] = await self.tools.nslookup(target)
                
            if scan_type in ["all", "whois"]:
                results["results"]["whois"] = await self.tools.whois_lookup(target)
                
            # Add geolocation data if available
            results["results"]["geolocation"] = self.get_geolocation(target)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            results["error"] = str(e)
            
        return results

async def main():
    parser = argparse.ArgumentParser(description="NetRecon Pro - Network Scanner")
    parser.add_argument("target", help="IP address or range (CIDR notation)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443' or '1-1024')")
    parser.add_argument("-o", "--output", choices=["json", "csv"], help="Output format")
    args = parser.parse_args()

    scanner = NetRecon()
    results = {"target": args.target, "scans": []}

    try:
        # Validate target
        network = ipaddress.ip_network(args.target, strict=False)
        
        # Determine ports to scan
        ports = scanner.common_ports
        if args.ports:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                ports = list(range(start, end + 1))
            else:
                ports = list(map(int, args.ports.split(",")))

        # Scan each host in the network
        for ip in network.hosts():
            ip_str = str(ip)
            logger.info(f"Scanning {ip_str}...")
            
            scan_result = {
                "ip": ip_str,
                "geolocation": scanner.get_geolocation(ip_str),
                "open_ports": await scanner.scan_ports(ip_str, ports)
            }
            
            results["scans"].append(scan_result)
            print(f"\nResults for {ip_str}:")
            print(json.dumps(scan_result, indent=2))

        # Save results if requested
        if args.output:
            scanner.save_results(results, args.output)

    except ValueError as e:
        logger.error(f"Invalid target: {e}")
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")

if __name__ == "__main__":
    asyncio.run(main())
