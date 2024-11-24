#!/usr/bin/env python3

import sys
import subprocess
import re
import requests
from urllib.parse import urlparse

# Colors for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

# Banner
print(f"{YELLOW}\n"
      "╔══════════════════════════════════════╗\n"
      "║     Basic Web Vulnerability Scanner   ║\n"
      "║        For Educational Purpose        ║\n"
      "╚══════════════════════════════════════╝{NC}")

# Check if required tools are installed
def check_requirements():
    print(f"{YELLOW}\n[*] Checking requirements...{NC}")
    tools = ["curl", "nmap", "whatweb"]
    for tool in tools:
        try:
            subprocess.check_output(["which", tool])
        except subprocess.CalledProcessError:
            print(f"{RED}[-] {tool} is not installed. Please install it first.{NC}")
            sys.exit(1)
    print(f"{GREEN}[+] All required tools are installed{NC}")

# Validate URL format
def validate_url(url):
    if not re.match(r"^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/?.*$", url):
        print(f"{RED}[-] Invalid URL format. Please use http:// or https://{NC}")
        sys.exit(1)

# Check if target is up
def check_host_up(target):
    print(f"{YELLOW}\n[*] Checking if host is up...{NC}")
    try:
        response = requests.head(target)
        if response.status_code == 200:
            print(f"{GREEN}[+] Host is up and running{NC}")
            return True
        else:
            print(f"{RED}[-] Host seems to be down{NC}")
            return False
    except requests.exceptions.RequestException:
        print(f"{RED}[-] Host seems to be down{NC}")
        return False

# Check HTTP headers
def check_headers(target):
    print(f"{YELLOW}\n[*] Analyzing HTTP headers...{NC}")
    try:
        response = requests.head(target)
        headers = response.headers
        
        # Check for security headers
        if "X-Frame-Options" not in headers:
            print(f"{RED}[-] Missing X-Frame-Options header (Clickjacking vulnerability){NC}")
        if "X-XSS-Protection" not in headers:
            print(f"{RED}[-] Missing X-XSS-Protection header{NC}")
        if "Content-Security-Policy" not in headers:
            print(f"{RED}[-] Missing Content-Security-Policy header{NC}")
        if "X-Content-Type-Options" not in headers:
            print(f"{RED}[-] Missing X-Content-Type-Options header{NC}")
        
        print(f"{GREEN}[+] Headers analysis complete{NC}")
    except requests.exceptions.RequestException:
        print(f"{RED}[-] Error checking headers{NC}")

# Check for common vulnerabilities using WhatWeb
def check_whatweb(target):
    print(f"{YELLOW}\n[*] Scanning with WhatWeb...{NC}")
    try:
        subprocess.run(["whatweb", "-q", target], check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}[-] Error running WhatWeb{NC}")

# Port scanning with nmap
def port_scan(target):
    print(f"{YELLOW}\n[*] Performing quick port scan...{NC}")
    try:
        subprocess.run(["nmap", "-T4", "-F", urlparse(target).netloc], check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}[-] Error running nmap{NC}")

# Directory enumeration
def directory_scan(target):
    print(f"{YELLOW}\n[*] Checking for common directories...{NC}")
    common_dirs = ["admin", "login", "wp-admin", "backup", "config", "test", "dashboard", "api"]
    for dir in common_dirs:
        url = f"{target}/{dir}/"
        try:
            response = requests.head(url)
            if response.status_code != 404:
                print(f"{RED}[-] Found accessible directory: {url} (HTTP {response.status_code}){NC}")
        except requests.exceptions.RequestException:
            pass

# SSL check
def check_ssl(target):
    print(f"{YELLOW}\n[*] Checking SSL/TLS...{NC}")
    if target.startswith("https://"):
        try:
            subprocess.run(["openssl", "s_client", "-servername", urlparse(target).netloc, "-connect", f"{urlparse(target).netloc}:443"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
            expire_date = subprocess.check_output(["openssl", "x509", "-noout", "-dates"], universal_newlines=True)
            expire_date = expire_date.split("notAfter=")[1].strip()
            print(f"{GREEN}[+] SSL Certificate expires: {expire_date}{NC}")
        except (subprocess.CalledProcessError, IndexError):
            print(f"{RED}[-] Could not retrieve SSL certificate information{NC}")
    else:
        print(f"{RED}[-] Not using HTTPS{NC}")

def main():
    if len(sys.argv) != 2:
        print(f"{RED}Usage: {sys.argv[0]} <url>{NC}")
        sys.exit(1)

    target = sys.argv[1]
    validate_url(target)
    check_requirements()

    if check_host_up(target):
        check_headers(target)
        check_whatweb(target)
        port_scan(target)
        directory_scan(target)
        check_ssl(target)
        
        print(f"{GREEN}\n[+] Scan completed{NC}")

if __name__ == "__main__":
    main()
 
