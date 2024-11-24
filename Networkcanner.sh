#!/bin/bash

# Web Vulnerability Scanner
# For educational purposes and authorized testing only

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${YELLOW}
╔══════════════════════════════════════╗
║     Basic Web Vulnerability Scanner   ║
║        For Educational Purpose        ║
╚══════════════════════════════════════╝${NC}"

# Check if required tools are installed
check_requirements() {
    echo -e "\n${YELLOW}[*] Checking requirements...${NC}"
    tools=("curl" "nmap" "nikto" "whatweb")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[-] $tool is not installed. Please install it first.${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}[+] All required tools are installed${NC}"
}

# Validate URL format
validate_url() {
    if [[ ! $1 =~ ^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/?.*$ ]]; then
        echo -e "${RED}[-] Invalid URL format. Please use http:// or https://${NC}"
        exit 1
    fi
}

# Check if target is up
check_host_up() {
    local target=$1
    echo -e "\n${YELLOW}[*] Checking if host is up...${NC}"
    
    if curl -s --head "$target" &> /dev/null; then
        echo -e "${GREEN}[+] Host is up and running${NC}"
        return 0
    else
        echo -e "${RED}[-] Host seems to be down${NC}"
        return 1
    fi
}

# Check HTTP headers
check_headers() {
    local target=$1
    echo -e "\n${YELLOW}[*] Analyzing HTTP headers...${NC}"
    
    headers=$(curl -s -I "$target")
    
    # Check for security headers
    if ! echo "$headers" | grep -qi "X-Frame-Options"; then
        echo -e "${RED}[-] Missing X-Frame-Options header (Clickjacking vulnerability)${NC}"
    fi
    
    if ! echo "$headers" | grep -qi "X-XSS-Protection"; then
        echo -e "${RED}[-] Missing X-XSS-Protection header${NC}"
    fi
    
    if ! echo "$headers" | grep -qi "Content-Security-Policy"; then
        echo -e "${RED}[-] Missing Content-Security-Policy header${NC}"
    fi
    
    if ! echo "$headers" | grep -qi "X-Content-Type-Options"; then
        echo -e "${RED}[-] Missing X-Content-Type-Options header${NC}"
    fi
    
    echo -e "${GREEN}[+] Headers analysis complete${NC}"
}

# Check for common vulnerabilities using WhatWeb
check_whatweb() {
    local target=$1
    echo -e "\n${YELLOW}[*] Scanning with WhatWeb...${NC}"
    whatweb -q "$target"
}

# Port scanning with nmap
port_scan() {
    local target=$1
    echo -e "\n${YELLOW}[*] Performing quick port scan...${NC}"
    nmap -T4 -F "$target"
}

# Directory enumeration
directory_scan() {
    local target=$1
    echo -e "\n${YELLOW}[*] Checking for common directories...${NC}"
    
    common_dirs=("admin" "login" "wp-admin" "backup" "config" "test" "dashboard" "api")
    
    for dir in "${common_dirs[@]}"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$target/$dir/")
        if [ "$response" != "404" ]; then
            echo -e "${RED}[-] Found accessible directory: $target/$dir/ (HTTP $response)${NC}"
        fi
    done
}

# SSL check
check_ssl() {
    local target=$1
    echo -e "\n${YELLOW}[*] Checking SSL/TLS...${NC}"
    
    if [[ $target == https://* ]]; then
        expire_date=$(echo | openssl s_client -servername "${target#https://}" -connect "${target#https://}":443 2>/dev/null | openssl x509 -noout -dates | grep "notAfter" | cut -d'=' -f2)
        if [ ! -z "$expire_date" ]; then
            echo -e "${GREEN}[+] SSL Certificate expires: $expire_date${NC}"
        else
            echo -e "${RED}[-] Could not retrieve SSL certificate information${NC}"
        fi
    else
        echo -e "${RED}[-] Not using HTTPS${NC}"
    fi
}

# Main function
main() {
    if [ $# -ne 1 ]; then
        echo -e "${RED}Usage: $0 <url>${NC}"
        exit 1
    fi

    target=$1
    validate_url "$target"
    check_requirements

    if check_host_up "$target"; then
        check_headers "$target"
        check_whatweb "$target"
        port_scan "${target#http*://}"
        directory_scan "$target"
        check_ssl "$target"
        
        echo -e "\n${GREEN}[+] Scan completed${NC}"
    fi
}

# Run main function with provided argument
main "$@"
