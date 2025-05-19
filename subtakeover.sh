#!/bin/bash
echo "SubTakeover Scanner"

# Input validation and sanitization
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Strip protocol if present
DOMAIN="${1#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

TEMP_DIR=$(mktemp -d -t subtake-XXXXXXXXXX)

# Phase 1: Subdomain Enumeration
echo "[+] Running Subfinder on $DOMAIN"
subfinder -d "$DOMAIN" -o "$TEMP_DIR/subfinder.txt"

# Check if subdomains were found
if [ ! -s "$TEMP_DIR/subfinder.txt" ]; then
    echo "[!] No subdomains found via Subfinder"
    rm -rf "$TEMP_DIR"
    exit 2
fi

# Phase 2: ShrewdEye API Integration (with error handling)
echo "[+] Querying ShrewdEye API"
API_DATA=$(curl -sf "https://shrewdeye.app/api/v1/domains/$DOMAIN")

if [ $? -ne 0 ] || [ -z "$API_DATA" ]; then
    echo "[!] Failed to query ShrewdEye API"
else
    DOWNLOAD_URL=$(echo "$API_DATA" | jq -r '.download_link // empty')
    
    if [ -n "$DOWNLOAD_URL" ]; then
        echo "[+] Downloading ShrewdEye domains"
        curl -sf "$DOWNLOAD_URL" -o "$TEMP_DIR/shrewdeye.txt"
        
        if [ -s "$TEMP_DIR/shrewdeye.txt" ]; then
            cat "$TEMP_DIR/subfinder.txt" "$TEMP_DIR/shrewdeye.txt" | sort -u > "$TEMP_DIR/combined.txt"
            mv "$TEMP_DIR/combined.txt" "$TEMP_DIR/subfinder.txt"
        fi
    fi
fi

# Phase 3: Subdomain Takeover Check (with empty file check)
echo "[+] Scanning for vulnerable subdomains with Subzy"
if [ -s "$TEMP_DIR/subfinder.txt" ]; then
    subzy run \
        --targets "$TEMP_DIR/subfinder.txt" \
        --concurrency 15 \
        --timeout 20 \
        --https true \
        --hide_fails true \
        --output "$TEMP_DIR/results.json" \
        --verify_ssl
else
    echo "[!] No subdomains to scan"
    rm -rf "$TEMP_DIR"
    exit 3
fi

# Results processing with better error checking
echo -e "\n[+] Scan Results:"
if [ -s "$TEMP_DIR/results.json" ]; then
    jq -e '.results[] | select(.vulnerable == true)' "$TEMP_DIR/results.json" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        jq -r '.results[] | select(.vulnerable == true) | "\(.subdomain) | \(.service)"' "$TEMP_DIR/results.json"
    else
        echo "No vulnerable subdomains found"
    fi
else
    echo "No scan results generated"
fi

# Cleanup
rm -rf "$TEMP_DIR"
echo -e "\n[+] Temporary files removed"