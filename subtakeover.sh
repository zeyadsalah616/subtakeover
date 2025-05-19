#!/bin/bash
echo "🔍 SubTakeover Scanner V2"

# Input validation
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Clean domain input
DOMAIN="${1#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

# Create temp dir
TEMP_DIR=$(mktemp -d -t subtake-XXXXXXXXXX)

# Subdomain enumeration
echo "[+] Running Subfinder on $DOMAIN"
subfinder -d "$DOMAIN" -silent -o "$TEMP_DIR/subfinder.txt"

# Optional: ShrewdEye enrichment
echo "[+] Querying ShrewdEye API"
API_DATA=$(curl -sf "https://shrewdeye.app/api/v1/domains/$DOMAIN")

if [ $? -eq 0 ] && [ -n "$API_DATA" ]; then
    DOWNLOAD_URL=$(echo "$API_DATA" | jq -r '.download_link // empty')
    if [ -n "$DOWNLOAD_URL" ]; then
        echo "[+] Downloading ShrewdEye results"
        curl -sf "$DOWNLOAD_URL" -o "$TEMP_DIR/shrewdeye.txt"
        cat "$TEMP_DIR/subfinder.txt" "$TEMP_DIR/shrewdeye.txt" | sort -u > "$TEMP_DIR/combined.txt"
        mv "$TEMP_DIR/combined.txt" "$TEMP_DIR/subfinder.txt"
    fi
fi

# Subdomain takeover check
echo "[+] Running Subzy"
subzy run \
    --targets "$TEMP_DIR/subfinder.txt" \
    --concurrency 15 \
    --timeout 20 \
    --https true \
    --hide_fails true \
    --output "$TEMP_DIR/results.json" \
    --verify_ssl

# Extract vulnerable domains
echo -e "\n[+] Parsing Subzy Results"
if jq -e '.results[] | select(.vulnerable == true)' "$TEMP_DIR/results.json" > /dev/null 2>&1; then
    jq -r '.results[] | select(.vulnerable == true) | .subdomain' "$TEMP_DIR/results.json" > "$TEMP_DIR/vuln_subs.txt"
else
    echo "[✓] No vulnerable subdomains found"
    rm -rf "$TEMP_DIR"
    exit 0
fi

# Post-processing: resolve and verify CNAMEs
echo -e "\n[+] Verifying CNAMEs using dig:"
while read -r sub; do
    echo -e "\n🔗 $sub"
    
    # Resolve A/CNAME records
    DIG_OUTPUT=$(dig +short "$sub" CNAME)
    if [ -n "$DIG_OUTPUT" ]; then
        echo "CNAME: $DIG_OUTPUT"
        
        # Check if CNAME is dangling (NXDOMAIN check)
        STATUS=$(dig +short "$DIG_OUTPUT" | head -n 1)
        if [ -z "$STATUS" ]; then
            echo "[!] Possibly dangling CNAME: $DIG_OUTPUT (no IP resolves)"
        else
            echo "[✓] CNAME resolves to: $STATUS"
        fi
    else
        echo "No CNAME found, checking A record..."
        A_RECORD=$(dig +short "$sub" A)
        if [ -z "$A_RECORD" ]; then
            echo "[!] No A record — could be dangling"
        else
            echo "[✓] A record resolves to: $A_RECORD"
        fi
    fi
done < "$TEMP_DIR/vuln_subs.txt"

# Cleanup
echo -e "\n[+] Cleanup"
rm -rf "$TEMP_DIR"
echo "[✓] Done"
