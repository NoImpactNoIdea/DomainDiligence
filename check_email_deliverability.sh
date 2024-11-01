#!/bin/bash

# Check if necessary tools are installed
missing_tools=()
for tool in dig whois curl jq openssl; do
    if ! command -v "$tool" &>/dev/null; then
        missing_tools+=("$tool")
    fi
done

# Check for 'timeout' or 'gtimeout'
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        alias timeout='gtimeout'
    else
        missing_tools+=("timeout or gtimeout")
    fi
fi

# Exit if any tools are missing
if [ "${#missing_tools[@]}" -gt 0 ]; then
    echo "This script requires the following tools to be installed: ${missing_tools[*]}"
    echo "Please install the missing tools and try again."
    exit 1
fi

# Validate input
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Extract the domain
domain=$(echo "$1" | sed -E 's|^(https?://)?([^/]+).*|\2|')

# Initialize summary
summary=""

# Function to add space for readability
space() {
    echo ""
}

# Function to check SPF record
check_spf() {
    spf_record=$(dig +short "$domain" TXT | grep -i "v=spf1")
    if [ -z "$spf_record" ]; then
        echo "🛑 SPF Record: Not found. It's recommended to set up an SPF record for better email deliverability."
        summary+="🛑 SPF Record: Not found\n"
    else
        echo "✅ SPF Record: Found - $spf_record"
        summary+="✅ SPF Record: Found\n"
    fi
    space
}

# Function to check DMARC record
check_dmarc() {
    dmarc_record=$(dig +short _dmarc."$domain" TXT)
    if [ -z "$dmarc_record" ]; then
        echo "🛑 DMARC Record: Not found. Setting up DMARC is important for email protection and reputation."
        summary+="🛑 DMARC Record: Not found\n"
    else
        echo "✅ DMARC Record: Found - $dmarc_record"
        summary+="✅ DMARC Record: Found\n"
        if echo "$dmarc_record" | grep -q "p=none"; then
            echo "⚠️ DMARC Policy is set to 'none'. Consider setting it to 'quarantine' or 'reject' to better protect your domain."
        fi
    fi
    space
}

# Function to check DKIM records (common selectors)
check_dkim() {
    selectors=("default" "selector1" "selector2" "google" "amazon")
    dkim_found=0
    for selector in "${selectors[@]}"; do
        dkim_record=$(dig +short "$selector._domainkey.$domain" TXT)
        if [ -n "$dkim_record" ]; then
            echo "✅ DKIM Record ($selector): Found - $dkim_record"
            summary+="✅ DKIM Record ($selector): Found\n"
            dkim_found=1
        fi
    done
    if [ $dkim_found -eq 0 ]; then
        echo "🛑 DKIM Record: Not found. Setting up DKIM is important for email integrity and deliverability."
        summary+="🛑 DKIM Record: Not found\n"
    fi
    space
}

# Function to check MX records
check_mx() {
    mx_record=$(dig +short "$domain" MX)
    if [ -z "$mx_record" ]; then
        echo "🛑 MX Records: Not found. MX records are necessary for receiving emails."
        summary+="🛑 MX Records: Not found\n"
    else
        echo "✅ MX Records:"
        echo "$mx_record" | while read -r line; do
            priority=$(echo "$line" | awk '{print $1}')
            mx_host=$(echo "$line" | awk '{print $2}')
            echo "   - Priority: $priority, Host: $mx_host"
        done
        summary+="✅ MX Records: Found\n"
    fi
    space
}

# Function to check domain expiration date
check_expiration() {
    expiry_date=$(whois "$domain" | grep -Ei "Expiry Date|Expiration Date|paid-till" | head -n 1 | awk -F: '{print $2}' | xargs)
    if [ -z "$expiry_date" ]; then
        echo "⚠️ Expiration Date: Not found. Ensure your domain registration is up-to-date to avoid disruptions."
        summary+="⚠️ Expiration Date: Not found\n"
    else
        echo "✅ Expiration Date: $expiry_date"
        summary+="✅ Expiration Date: $expiry_date\n"
    fi
    space
}

# Function to check Google Safe Browsing status
check_safe_browsing() {
    echo "👀 Checking Google Safe Browsing status..."
    response=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{
            "client": {
                "clientId":      "yourcompany",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": "http://'"$domain"'"},
                    {"url": "http://www.'"$domain"'"}
                ]
            }
        }' \
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY")

    if [[ "$response" == *"matches"* ]]; then
        echo "⚠️ Warning: $domain may be flagged by Google Safe Browsing."
        summary+="⚠️ Google Safe Browsing: Potential issues detected\n"
    else
        echo "✅ Google Safe Browsing: $domain appears to be in good standing."
        summary+="✅ Google Safe Browsing: No issues detected\n"
    fi
    space
}

# Function to check DNS-based Blacklists (DNSBL)
check_blacklist() {
    echo "👀 Checking DNS-based Blacklists (DNSBL)..."
    blacklist=("zen.spamhaus.org" "bl.spamcop.net" "b.barracudacentral.org" "dnsbl.sorbs.net")
    ips=$(dig +short "$domain" A)
    if [ -z "$ips" ]; then
        echo "⚠️ Could not resolve IP address for $domain."
        summary+="⚠️ DNSBL Check: IP address could not be resolved\n"
        space
        return
    fi
    blacklisted=0
    for ip in $ips; do
        reversed_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
        for bl in "${blacklist[@]}"; do
            listed=$(dig +short "$reversed_ip.$bl" A)
            if [[ "$listed" =~ ^127\.0\.0\.[2-9]$|^127\.0\.0\.[1-2][0-9]$ ]]; then
                echo "⚠️ Blacklist Alert: $ip ($domain) is listed on $bl."
                blacklisted=1
            elif [ -n "$listed" ]; then
                echo "⚠️ Unexpected response from $bl for $ip: $listed"
            else
                echo "✅ $ip is not listed on $bl."
            fi
        done
    done
    if [ $blacklisted -eq 1 ]; then
        summary+="⚠️ DNSBL Check: Domain is blacklisted\n"
    else
        summary+="✅ DNSBL Check: Domain is not blacklisted\n"
    fi
    space
}

# Function to check DNSSEC
check_dnssec() {
    echo "👀 Checking DNSSEC..."
    dnskey=$(dig DNSKEY "$domain" +short)
    if [ -z "$dnskey" ]; then
        echo "🛑 DNSSEC: Not enabled for $domain."
        summary+="🛑 DNSSEC: Not enabled\n"
    else
        echo "✅ DNSSEC: Enabled for $domain."
        summary+="✅ DNSSEC: Enabled\n"
    fi
    space
}

# Function to check TLS configuration
check_tls() {
    echo "👀 Checking TLS configuration..."
    if timeout 10 bash -c "</dev/tcp/$domain/443" &>/dev/null; then
        cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates)
        if [ -n "$cert_info" ]; then
            echo "✅ TLS Certificate Info:"
            echo "$cert_info"
            summary+="✅ TLS Certificate: Valid\n"
        else
            echo "⚠️ TLS: Unable to retrieve certificate information."
            summary+="⚠️ TLS Certificate: Unable to retrieve info\n"
        fi
    else
        echo "⚠️ TLS: Port 443 is closed or not accepting connections."
        summary+="⚠️ TLS: Port 443 is closed\n"
    fi
    space
}

# Function to check reverse DNS (PTR) records
check_reverse_dns() {
    echo "👀 Checking Reverse DNS (PTR) records..."
    ips=$(dig +short "$domain" A)
    for ip in $ips; do
        ptr_record=$(dig +short -x "$ip")
        if [ -n "$ptr_record" ]; then
            echo "✅ PTR Record for $ip: $ptr_record"
            summary+="✅ PTR Record for $ip: Found\n"
        else
            echo "🛑 PTR Record: Not found for IP $ip."
            summary+="🛑 PTR Record for $ip: Not found\n"
        fi
    done
    space
}

# Function to check MTA-STS policy
check_mta_sts() {
    echo "👀 Checking MTA-STS policy..."
    mta_sts_record=$(dig +short "_mta-sts.$domain" TXT)
    if [ -z "$mta_sts_record" ]; then
        echo "🛑 MTA-STS Record: Not found."
        summary+="🛑 MTA-STS Record: Not found\n"
    else
        echo "✅ MTA-STS Record: Found - $mta_sts_record"
        summary+="✅ MTA-STS Record: Found\n"
        # Fetch the policy file
        policy_url="https://mta-sts.$domain/.well-known/mta-sts.txt"
        policy_response=$(curl -s -o /dev/null -w "%{http_code}" "$policy_url")
        if [ "$policy_response" -eq 200 ]; then
            echo "✅ MTA-STS Policy File: Accessible at $policy_url"
            summary+="✅ MTA-STS Policy File: Accessible\n"
        else
            echo "⚠️ MTA-STS Policy File: Not accessible at $policy_url"
            summary+="⚠️ MTA-STS Policy File: Not accessible\n"
        fi
    fi
    space
}

# Function to check TLS Reporting (TLS-RPT)
check_tls_rpt() {
    echo "👀 Checking TLS Reporting (TLS-RPT)..."
    tls_rpt_record=$(dig +short "_smtp._tls.$domain" TXT)
    if [ -z "$tls_rpt_record" ]; then
        echo "🛑 TLS-RPT Record: Not found."
        summary+="🛑 TLS-RPT Record: Not found\n"
    else
        echo "✅ TLS-RPT Record: Found - $tls_rpt_record"
        summary+="✅ TLS-RPT Record: Found\n"
    fi
    space
}

# Function to check BIMI record
check_bimi() {
    echo "👀 Checking BIMI record..."
    bimi_record=$(dig +short "default._bimi.$domain" TXT)
    if [ -z "$bimi_record" ]; then
        echo "🛑 BIMI Record: Not found."
        summary+="🛑 BIMI Record: Not found\n"
    else
        echo "✅ BIMI Record: Found - $bimi_record"
        summary+="✅ BIMI Record: Found\n"
    fi
    space
}

# Function to check SMTP Banner
check_smtp_banner() {
    echo "👀 Checking SMTP Banner..."
    mx_hosts=$(dig +short "$domain" MX | awk '{print $2}')
    for mx in $mx_hosts; do
        # Skip known providers
        if [[ "$mx" == *"google.com." ]]; then
            echo "✅ $mx is managed by Google. Skipping SMTP banner retrieval."
            summary+="✅ SMTP Banner for $mx: Skipped (Google server)\n"
            continue
        fi
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/$mx/25; echo -e 'QUIT\r\n' >&3; cat <&3 | head -n 1")
        if [ -n "$banner" ]; then
            echo "✅ SMTP Banner for $mx: $banner"
            summary+="✅ SMTP Banner for $mx: Retrieved\n"
        else
            echo "⚠️ SMTP Banner: Unable to retrieve banner from $mx."
            summary+="⚠️ SMTP Banner for $mx: Not retrieved\n"
        fi
    done
    space
}

# Function to check Open Relay status (basic test)
check_open_relay() {
    echo "👀 Checking for Open Relay (basic test)..."
    mx_hosts=$(dig +short "$domain" MX | awk '{print $2}')
    for mx in $mx_hosts; do
        # Skip known providers
        if [[ "$mx" == *"google.com." ]]; then
            echo "✅ $mx is managed by Google. Skipping open relay test."
            summary+="✅ $mx: Open relay test skipped (Google server)\n"
            continue
        fi
        response=$(timeout 5 bash -c "exec 3<>/dev/tcp/$mx/25; echo -e 'HELO test.com\r\nMAIL FROM:<test@test.com>\r\nRCPT TO:<nonexistent@$domain>\r\nQUIT\r\n' >&3; cat <&3")
        if echo "$response" | grep -qE "554|550|5[0-9][0-9]"; then
            echo "✅ $mx is not an open relay."
            summary+="✅ $mx: Not an open relay\n"
        else
            echo "⚠️ $mx may be an open relay."
            summary+="⚠️ $mx: Potential open relay\n"
        fi
    done
    space
}

# Function to check CAA records
check_caa() {
    echo "👀 Checking CAA records..."
    caa_records=$(dig +short "$domain" CAA)
    if [ -z "$caa_records" ]; then
        echo "⚠️ CAA Records: Not found. Consider adding CAA records to restrict which certificate authorities can issue certificates for your domain."
        summary+="⚠️ CAA Records: Not found\n"
    else
        echo "✅ CAA Records:"
        echo "$caa_records"
        summary+="✅ CAA Records: Found\n"
    fi
    space
}

# Function to check for HSTS
check_hsts() {
    echo "👀 Checking HSTS..."
    response=$(curl -sI "https://$domain")
    if echo "$response" | grep -qi "Strict-Transport-Security"; then
        echo "✅ HSTS: Enabled."
        summary+="✅ HSTS: Enabled\n"
    else
        echo "⚠️ HSTS: Not enabled."
        summary+="⚠️ HSTS: Not enabled\n"
    fi
    space
}

# Function to check for zone transfer (AXFR)
check_zone_transfer() {
    echo "👀 Checking for DNS zone transfer vulnerability..."
    ns_servers=$(dig +short NS "$domain")
    vulnerable=0
    for ns in $ns_servers; do
        ns_ip=$(dig +short "$ns")
        if [ -z "$ns_ip" ]; then
            echo "⚠️ Could not resolve IP address for nameserver $ns."
            continue
        fi
        axfr=$(dig AXFR "$domain" @"$ns" 2>&1)
        if echo "$axfr" | grep -qE "Transfer failed|timed out|connection refused|no servers could be reached"; then
            echo "✅ Zone transfer not allowed on $ns."
        elif [ -z "$axfr" ]; then
            echo "✅ Zone transfer not allowed on $ns."
        else
            echo "⚠️ Zone transfer allowed on $ns! This is a security risk."
            vulnerable=1
        fi
    done
    if [ $vulnerable -eq 1 ]; then
        summary+="⚠️ Zone Transfer: Vulnerable\n"
    else
        summary+="✅ Zone Transfer: Secure\n"
    fi
    space
}

# Function to check WHOIS information
# Function to check WHOIS information
# Function to check WHOIS information
check_whois() {
    echo "👀 Retrieving WHOIS information..."
    whois_data=$(whois "$domain" | tr -dc '\11\12\15\40-\176')

    # Extract Registrar (case-insensitive, flexible field separator)
    registrar=$(echo "$whois_data" | awk -F':[ \t]*' '
        BEGIN { IGNORECASE = 1 }
        /^Registrar:/ {print $2; exit}
        /^Registrar Name:/ {print $2; exit}
        /^Sponsoring Registrar:/ {print $2; exit}
    ' | xargs)

    # Extract Domain Status
    status=$(echo "$whois_data" | awk -F':[ \t]*' '
        BEGIN { IGNORECASE = 1 }
        /^Domain Status:/ {print $2}
    ' | paste -sd ", " - | xargs)

    # Fallback if no status found
    if [ -z "$status" ]; then
        status="Unknown"
    fi

    # Output results
    if [ -n "$registrar" ]; then
        echo "✅ Registrar: $registrar"
    else
        echo "⚠️ Registrar information not found."
        registrar="Unknown"
    fi

    echo "✅ Domain Status: $status"

    space
}

# Function to check HTTP headers
check_http_headers() {
    echo "👀 Checking HTTP security headers..."
    headers=$(curl -sI "https://$domain")
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        echo "✅ Content-Security-Policy header is set."
    else
        echo "⚠️ Content-Security-Policy header is missing."
    fi
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        echo "✅ X-Frame-Options header is set."
    else
        echo "⚠️ X-Frame-Options header is missing."
    fi
    if echo "$headers" | grep -qi "X-XSS-Protection"; then
        echo "✅ X-XSS-Protection header is set."
    else
        echo "⚠️ X-XSS-Protection header is missing."
    fi
    summary+="✅ HTTP Headers: Checked\n"
    space
}

# Function to check if the domain is using a CDN
check_cdn() {
    echo "👀 Checking for CDN usage..."
    cdn=$(dig +short CNAME "$domain")
    if [[ "$cdn" == *"cloudfront.net."* ]] ||
        [[ "$cdn" == *"akamai.net."* ]] ||
        [[ "$cdn" == *"cdn.cloudflare.net."* ]] ||
        [[ "$cdn" == *"fastly.net."* ]] ||
        [[ "$cdn" == *"edgekey.net."* ]] ||
        [[ "$cdn" == *"edgesuite.net."* ]] ||
        [[ "$cdn" == *"cdn.shopify.com."* ]]; then
        echo "✅ CDN detected: $cdn"
        summary+="✅ CDN: Detected\n"
    else
        echo "⚠️ No CDN detected or CDN not recognized."
        summary+="⚠️ CDN: Not detected\n"
    fi
    space
}

# Function to check if the domain has a valid SSL certificate
check_ssl_cert() {
    echo "👀 Checking SSL certificate validity..."
    cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates)
    if [ -n "$cert_info" ]; then
        start_date=$(echo "$cert_info" | grep "notBefore" | cut -d= -f2)
        end_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        echo "✅ SSL Certificate Validity:"
        echo "   - Start Date: $start_date"
        echo "   - Expiry Date: $end_date"
        summary+="✅ SSL Certificate: Valid from $start_date to $end_date\n"
    else
        echo "⚠️ SSL: Unable to retrieve certificate information."
        summary+="⚠️ SSL Certificate: Unable to retrieve info\n"
    fi
    space
}

# Run checks
echo "Checking email deliverability settings and domain reputation for $domain..."
space
check_spf
check_dmarc
check_dkim
check_mx
check_expiration
check_safe_browsing
check_blacklist
check_dnssec
check_tls
check_reverse_dns
check_mta_sts
check_tls_rpt
check_bimi
check_smtp_banner
check_open_relay
check_caa
check_hsts
check_zone_transfer
check_whois
check_http_headers
check_cdn
check_ssl_cert

echo "✅ Completed domain health and email deliverability check for $domain."
echo ""
echo "Summary of checks:"
echo -e "$summary"
