#!/usr/bin/env python3
"""
CVE-2026-35616 - FortiClient EMS Authentication Bypass Detector
===============================================================
Detects if a FortiClient EMS server (7.4.5-7.4.6) is vulnerable to
API authentication bypass.

Author: Tu Nombre
Date: April 2026

WARNING: For authorized security testing only.
"""

import requests
import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urljoin

# Disable SSL warnings (for lab environments)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# REAL ENDPOINTS (from Fortinet advisory FG-IR-26-099)
# ============================================================
SENSITIVE_ENDPOINTS = [
    "/api/v1/system/status",
    "/api/v1/tenants",
    "/api/v1/admin/users",
    "/api/v1/deployments",
    "/api/v1/logs/events",
    "/api/v1/init",
    "/api/v1/health",
]

class CVE202635616Detector:
    def __init__(self, target, timeout=8, verbose=False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'CVE-2026-35616-Detector/1.0',
            'Accept': 'application/json'
        })
        self.results = []
    
    def log(self, msg, level="INFO"):
        prefix = {
            "INFO": "[*]",
            "GOOD": "[+]",
            "BAD": "[-]",
            "VULN": "[!]",
            "ERROR": "[X]"
        }.get(level, "[*]")
        print(f"{prefix} {msg}")
    
    def test_endpoint(self, endpoint):
        """Test if an endpoint is accessible without authentication"""
        url = urljoin(self.target, endpoint)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            result = {
                "endpoint": endpoint,
                "status_code": response.status_code,
                "vulnerable": response.status_code in [200, 204],
                "content_length": len(response.content)
            }
            
            if result["vulnerable"] and response.text:
                result["preview"] = response.text[:200].replace('\n', ' ')
            
            return result
            
        except Exception as e:
            return {"endpoint": endpoint, "error": str(e)[:50], "vulnerable": False}
    
    def scan(self):
        """Run the scan"""
        self.log(f"Target: {self.target}")
        self.log(f"Checking {len(SENSITIVE_ENDPOINTS)} endpoints...")
        print("-" * 60)
        
        for endpoint in SENSITIVE_ENDPOINTS:
            result = self.test_endpoint(endpoint)
            self.results.append(result)
            
            if result.get("vulnerable"):
                self.log(f"{endpoint} → HTTP {result['status_code']} (VULNERABLE)", "VULN")
            elif result.get("error"):
                self.log(f"{endpoint} → {result['error']}", "ERROR")
            else:
                self.log(f"{endpoint} → HTTP {result['status_code']} (Protected)")
        
        print("-" * 60)
        return self.get_summary()
    
    def get_summary(self):
        """Generate summary report"""
        vulnerable = [r for r in self.results if r.get("vulnerable")]
        
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_endpoints": len(self.results),
            "vulnerable_count": len(vulnerable),
            "is_vulnerable": len(vulnerable) > 0,
            "vulnerable_endpoints": [
                {"endpoint": r["endpoint"], "status": r["status_code"]}
                for r in vulnerable
            ]
        }

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-35616 - FortiClient EMS Vulnerability Detector"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL (e.g., https://192.168.1.100:8443)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )
    
    args = parser.parse_args()
    
    # Fix target URL
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    print("=" * 60)
    print("CVE-2026-35616 - FortiClient EMS Detector")
    print("Affects: versions 7.4.5 through 7.4.6")
    print("=" * 60)
    
    detector = CVE202635616Detector(target, verbose=args.verbose)
    summary = detector.scan()
    
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("\n" + "=" * 60)
        print("RESULTADO")
        print("=" * 60)
        
        if summary["is_vulnerable"]:
            print(f"\n[!] VULNERABLE: {summary['vulnerable_count']} endpoints accesibles sin autenticación\n")
            for ep in summary["vulnerable_endpoints"]:
                print(f"    → {ep['endpoint']}")
            print("\n[!] Aplicar hotfix de Fortinet inmediatamente (FG-IR-26-099)")
        else:
            print("\n[+] NO VULNERABLE: No se detectaron endpoints sin protección")
    
    sys.exit(1 if summary["is_vulnerable"] else 0)

if __name__ == "__main__":
    main()
