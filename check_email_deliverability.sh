#!/bin/bash

GOOGLE_SAFE_BROWSING_API_KEY="AIzaSyDwQtctMKUxmJoQItMO5OCKNY0a8_2p0V8"

missing_tools=()
for tool in dig whois curl jq openssl; do
    if ! command -v "$tool" &>/dev/null; then
        missing_tools+=("$tool")
    fi
done

if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        alias timeout='gtimeout'
    else
        missing_tools+=("timeout or gtimeout")
    fi
fi

if [ "${#missing_tools[@]}" -gt 0 ]; then
    echo "Required tools missing: ${missing_tools[*]}. Please install them and retry."
    exit 1
fi

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$(echo "$1" | sed -E 's|^(https?://)?([^/]+).*|\2|')

get_root_domain() {
    IFS='.' read -r -a domain_parts <<<"$domain"
    num_parts="${#domain_parts[@]}"
    if [ "$num_parts" -ge 2 ]; then
        root_domain="${domain_parts[$((num_parts - 2))]}.${domain_parts[$((num_parts - 1))]}"
    else
        root_domain="$domain"
    fi
}
get_root_domain

summary=""

space() {
    echo ""
}

check_spf() {
    echo "Checking SPF record..."
    if ! dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "$domain" TXT 2>&1); then
        echo "DNS query error for SPF record: $dig_output"
        summary+="SPF Record: DNS query error\n"
    else
        spf_record=$(echo "$dig_output" | grep -i "v=spf1")
        if [ -z "$spf_record" ]; then
            if [ "$domain" != "$root_domain" ]; then
                echo "No SPF record found for $domain. Checking root domain $root_domain..."
                if ! root_dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "$root_domain" TXT 2>&1); then
                    echo "DNS query error for SPF record on root domain: $root_dig_output"
                    summary+="SPF Record: DNS query error on root domain\n"
                else
                    spf_record=$(echo "$root_dig_output" | grep -i "v=spf1")
                    if [ -z "$spf_record" ]; then
                        echo "SPF record not found for subdomain or root domain."
                        summary+="🛑 SPF Record: Not found\n"
                    else
                        echo "SPF record found on root domain: $spf_record"
                        summary+="⚠️  SPF Record: Found on root domain\n"
                    fi
                fi
            else
                echo "SPF record not found."
                summary+="🛑 SPF Record: Not found\n"
            fi
        else
            echo "SPF record found: $spf_record"
            summary+="✅ SPF Record: Found\n"
        fi
    fi
    space
}

check_dmarc() {
    echo "Checking DMARC record..."
    if ! dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "_dmarc.$domain" TXT 2>&1); then
        echo "DNS query error for DMARC record: $dig_output"
        summary+="DMARC Record: DNS query error\n"
    else
        dmarc_record="$dig_output"
        if [ -z "$dmarc_record" ]; then
            if [ "$domain" != "$root_domain" ]; then
                echo "No DMARC record found for $domain. Checking root domain $root_domain..."
                if ! root_dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "_dmarc.$root_domain" TXT 2>&1); then
                    echo "DNS query error for DMARC record on root domain: $root_dig_output"
                    summary+="DMARC Record: DNS query error on root domain\n"
                else
                    dmarc_record="$root_dig_output"
                    if [ -z "$dmarc_record" ]; then
                        echo "DMARC record not found for subdomain or root domain."
                        summary+="🛑 DMARC Record: Not found\n"
                    else
                        echo "DMARC record found on root domain: $dmarc_record"
                        dmarc_policy=$(echo "$dmarc_record" | grep -o 'p=[^;"]*' | cut -d= -f2)
                        if [ -n "$dmarc_policy" ]; then
                            echo "DMARC policy is set to '$dmarc_policy'."
                            summary+="⚠️  DMARC Policy: $dmarc_policy (Set to Reject or Quarantine)\n"
                            if [ "$dmarc_policy" = "none" ]; then
                                echo "DMARC policy is 'none': Reject || Quarantine.."
                            elif [ "$dmarc_policy" = "quarantine" ]; then
                                echo "DMARC policy is 'quarantine'."
                            elif [ "$dmarc_policy" = "reject" ]; then
                                echo "DMARC policy is 'reject'."
                            else
                                echo "DMARC policy is unrecognized: '$dmarc_policy'."
                            fi
                        else
                            echo "Could not determine DMARC policy from the record."
                            summary+="🛑 DMARC Policy: Not found or unrecognized\n"
                        fi
                        summary+="⚠️  DMARC Record: Found on root domain\n"
                    fi
                fi
            else
                echo "DMARC record not found."
                summary+="🛑 DMARC Record: Not found\n"
            fi
        else
            echo "DMARC record found: $dmarc_record"
            dmarc_policy=$(echo "$dmarc_record" | grep -o 'p=[^;"]*' | cut -d= -f2)
            if [ -n "$dmarc_policy" ]; then
                echo "DMARC policy is set to '$dmarc_policy'."
                summary+="⚠️  DMARC Policy: $dmarc_policy (Set to Reject or Quarantine)\n"
                if [ "$dmarc_policy" = "none" ]; then
                    echo "DMARC policy is 'none'. Reject or Quarantine should be used instead."
                elif [ "$dmarc_policy" = "quarantine" ]; then
                    echo "DMARC policy is 'quarantine'."
                elif [ "$dmarc_policy" = "reject" ]; then
                    echo "DMARC policy is 'reject'."
                else
                    echo "DMARC policy is unrecognized: '$dmarc_policy'."
                fi
            else
                echo "Could not determine DMARC policy from the record."
                summary+="🛑 DMARC Policy: Not found or unrecognized\n"
            fi
            summary+="✅ DMARC Record: Found\n"
        fi
    fi
    space
}

check_dkim() {
    echo "Checking DKIM records..."
    selectors=(
        "default" "selector1" "selector2" "google" "amazonses" "mail" "smtp" "dkim"
        "dkim1" "dkim2" "dkim1024" "dkim2048" "s1" "s2" "k1" "k2"
        "mandrill" "mandrillapp" "sendgrid" "sendgrid2" "smtpapi"
        "mailchimp" "sparkpost" "mailgun" "zoho" "protection"
        "cm" "cm1" "cm2" "pm"
    )
    dkim_found=0
    for selector in "${selectors[@]}"; do
        if dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "$selector._domainkey.$domain" TXT 2>&1); then
            dkim_record="$dig_output"
            if [ -n "$dkim_record" ]; then
                echo "DKIM record found for selector '$selector' on $domain: $dkim_record"
                summary+="✅ DKIM Record ($selector) on $domain: Found\n"
                dkim_found=1
            fi
        fi
        if [ "$domain" != "$root_domain" ]; then
            if dig_output=$(dig @8.8.8.8 +time=5 +tries=3 +short "$selector._domainkey.$root_domain" TXT 2>&1); then
                dkim_record="$dig_output"
                if [ -n "$dkim_record" ]; then
                    echo "DKIM record found for selector '$selector' on $root_domain: $dkim_record"
                    summary+="✅ DKIM Record ($selector) on $root_domain: Found\n"
                    dkim_found=1
                fi
            fi
        fi
    done
    if [ "$dkim_found" -eq 0 ]; then
        echo "DKIM record not found."
        summary+="🛑 DKIM Record: Not found\n"
    fi
    space
}

check_mx() {
    echo "Checking MX records..."
    mx_record=$(dig +short "$domain" MX)
    if [ -z "$mx_record" ]; then
        echo "MX records not found: (Receiving Emails)"
        summary+="🛑 MX Records: Not found\n"
    else
        echo "MX records found:"
        echo "$mx_record" | while read -r line; do
            priority=$(echo "$line" | awk '{print $1}')
            mx_host=$(echo "$line" | awk '{print $2}')
            echo "   - Priority: $priority, Host: $mx_host"
        done
        summary+="✅ MX Records: Found\n"
    fi
    space
}

check_expiration() {
    echo "Checking domain expiry date..."
    expiry_date=$(whois "$domain" | grep -Ei "Expiry Date|Expiration Date|paid-till" | head -n 1 | awk -F: '{print $2}' | xargs)
    if [ -z "$expiry_date" ]; then
        echo "Expiry date not found."
        summary+="🛑 Expiry Date: Not found\n"
    else
        echo "Expiry date: $expiry_date"
        summary+="✅ Expiry Date: $expiry_date\n"
    fi
    space
}

check_safe_browsing() {
    echo "Checking Google Safe Browsing status..."
    if [ -z "$GOOGLE_SAFE_BROWSING_API_KEY" ]; then
        echo "Missing API KEY."
        summary+="🔐 Google Safe Browsing: API key not set\n"
        space
        return
    fi
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
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$GOOGLE_SAFE_BROWSING_API_KEY")

    if [[ "$response" == *"matches"* ]]; then
        echo "Forgeworks Alert: $domain will be flagged by Google Safe Browsing."
        summary+="🛑 Google Safe Browsing: Potential issues detected\n"
    else
        echo "Google Safe Browsing: $domain appears to be in good standing."
        summary+="✅ Google Safe Browsing: No issues found\n"
    fi
    space
}

check_blacklist() {
    echo "Checking DNS-based Blacklists (DNSBL)..."
    blacklist=("zen.spamhaus.org" "bl.spamcop.net" "b.barracudacentral.org" "dnsbl.sorbs.net")
    ips=$(dig +short "$domain" A)
    if [ -z "$ips" ]; then
        echo "Could not resolve IP address for $domain."
        summary+="🛑 DNSBL Check: IP address could not be resolved\n"
        space
        return
    fi
    blacklisted=0
    for ip in $ips; do
        reversed_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
        for bl in "${blacklist[@]}"; do
            listed=$(dig +short "$reversed_ip.$bl" A 2>&1)
            dig_status=$?
            if [ $dig_status -ne 0 ]; then
                echo "DNS query error for blacklist $bl: $listed"
                continue
            fi
            if [[ "$listed" =~ ^127\.0\.0\.[2-9]$|^127\.0\.0\.[1-2][0-9]$ ]]; then
                echo "Blacklist alert: $ip ($domain) is listed on $bl."
                blacklisted=1
            elif [ -n "$listed" ]; then
                echo "Unexpected response from $bl for $ip: $listed"
            else
                echo "$ip is not listed on $bl."
            fi
        done
    done
    if [ $blacklisted -eq 1 ]; then
        summary+="🛑 DNSBL Check: Domain is blacklisted\n"
    else
        summary+="✅ DNSBL Check: Domain is not blacklisted\n"
    fi
    space
}

check_dnssec() {
    echo "Checking DNSSEC..."
    dnskey=$(dig DNSKEY "$domain" +short)
    if [ -z "$dnskey" ]; then
        echo "DNSSEC: not enabled for $domain."
    else
        echo "DNSSEC is enabled for $domain."
    fi
    space
}

check_tls() {
    echo "Checking TLS configuration..."
    if timeout 10 bash -c "</dev/tcp/$domain/443" &>/dev/null; then
        cert_info=$(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -dates)
        if [ -n "$cert_info" ]; then
            echo "TLS certificate information:"
            echo "$cert_info"
            summary+="✅ TLS Certificate: Valid\n"
        else
            echo "Unable to retrieve TLS certificate information."
            summary+="🛑 TLS Certificate: Unable to retrieve info\n"
        fi
    else
        echo "Port 443 is closed or not accepting connections."
        summary+="⚠️  TLS: Port 443 is closed\n"
    fi
    space
}

check_reverse_dns() {
    echo "Checking Reverse DNS (PTR: Maps IP to a Domain) records..."
    ips=$(dig +short "$domain" A)
    for ip in $ips; do
        ptr_record=$(dig +short -x "$ip")
        if [ -n "$ptr_record" ]; then
            echo "PTR record for $ip: $ptr_record"
            summary+="✅ PTR Record for $ip: Found\n"
        else
            echo "PTR record not found for IP $ip."
            summary+="🛑 PTR Record for $ip: Not found\n"
        fi
    done
    space
}

check_mta_sts() {
    echo "Checking MTA-STS policy..."
    mta_sts_record=$(dig +short "_mta-sts.$domain" TXT)
    if [ -z "$mta_sts_record" ]; then
        echo "MTA-STS record not found."
    else
        echo "MTA-STS record found: $mta_sts_record"
        summary+="MTA-STS Record: Found\n"
        policy_url="https://mta-sts.$domain/.well-known/mta-sts.txt"
        policy_response=$(curl -s -o /dev/null -w "%{http_code}" "$policy_url")
        if [ "$policy_response" -eq 200 ]; then
            echo "MTA-STS policy file accessible at $policy_url"
        else
            echo "MTA-STS policy file is not accessible at $policy_url"
        fi
    fi
    space
}

check_tls_rpt() {
    echo "Checking TLS Reporting (TLS:RPT)..."
    tls_rpt_record=$(dig +short "_smtp._tls.$domain" TXT)
    if [ -z "$tls_rpt_record" ]; then
        echo "TLS-RPT record: Not found."
    else
        echo "TLS-RPT record found: $tls_rpt_record"
    fi
    space
}

check_bimi() {
    echo "Checking BIMI record..."
    bimi_record=$(dig +short "default._bimi.$domain" TXT)
    if [ -z "$bimi_record" ]; then
        echo "BIMI record not found."
    else
        echo "BIMI record found: $bimi_record"
    fi
    space
}

check_smtp_banner() {
    echo "Checking SMTP banner..."
    mx_hosts=$(dig +short "$domain" MX | awk '{print $2}')
    for mx in $mx_hosts; do
        if [[ "$mx" == *"google.com." ]]; then
            echo "$mx is managed by GOOGLES. Skipping SMTP banner retrieval."
            continue
        fi
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/$mx/25; echo -e 'QUIT\r\n' >&3; cat <&3 | head -n 1")
        if [ -n "$banner" ]; then
            echo "SMTP banner for $mx: $banner"
        else
            echo "Unable to retrieve SMTP banner from $mx."
        fi
    done
    space
}

check_open_relay() {
    echo "Checking for open relay (basic test)..."
    mx_hosts=$(dig +short "$domain" MX | awk '{print $2}')
    for mx in $mx_hosts; do
        if [[ "$mx" == *"google.com." ]]; then
            echo "$mx is managed by GOOGLE. Skipping open relay test."
            continue
        fi
        response=$(timeout 5 bash -c "exec 3<>/dev/tcp/$mx/25; echo -e 'HELO test.com\r\nMAIL FROM:<test@test.com>\r\nRCPT TO:<nonexistent@$domain>\r\nQUIT\r\n' >&3; cat <&3")
        if echo "$response" | grep -qE "554|550|5[0-9][0-9]"; then
            echo "$mx is not an open relay."
        else
            echo "$mx may be an open relay."
        fi
    done
    space
}

check_caa() {
    echo "Checking CAA records..."
    caa_records=$(dig +short "$domain" CAA)
    if [ -z "$caa_records" ]; then
        echo "CAA records not found."
    else
        echo "CAA records found:"
        echo "$caa_records"
    fi
    space
}

check_hsts() {
    echo "Checking HSTS..."
    response=$(curl -sI "https://$domain")
    if echo "$response" | grep -qi "Strict-Transport-Security"; then
        echo "HSTS is enabled."
        summary+="✅ HSTS: Enabled\n"
    else
        echo "HSTS is not enabled."
        summary+="🛑 HSTS: Not enabled\n"
    fi
    space
}

check_zone_transfer() {
    echo "Checking for DNS zone transfer vulnerability..."
    ns_servers=$(dig +short NS "$domain")
    vulnerable=0
    for ns in $ns_servers; do
        ns_ip=$(dig +short "$ns")
        if [ -z "$ns_ip" ]; then
            echo "Could not resolve IP address for nameserver $ns."
            continue
        fi
        axfr=$(dig AXFR "$domain" @"$ns" 2>&1)
        if echo "$axfr" | grep -qE "Transfer failed|timed out|connection refused|no servers could be reached"; then
            echo "Zone transfer: Not allowed on $ns."
        elif [ -z "$axfr" ]; then
            echo "Zone transfer: Not allowed on $ns."
        else
            echo "Zone transfer allowed on $ns! This is a security risk."
            vulnerable=1
        fi
    done
    if [ $vulnerable -eq 1 ]; then
        summary+="🛑 Zone Transfer: Vulnerable\n"
    else
        summary+="✅ Zone Transfer: Secure\n"
    fi
    space
}

check_whois() {
    echo "Retrieving WHOIS information..."
    whois_data=$(whois "$domain" | tr -dc '\11\12\15\40-\176')

    registrar=$(echo "$whois_data" | awk -F':[ \t]*' '
        BEGIN { IGNORECASE = 1 }
        /^Registrar:/ {print $2; exit}
        /^Registrar Name:/ {print $2; exit}
        /^Sponsoring Registrar:/ {print $2; exit}
    ' | xargs)

    status=$(echo "$whois_data" | awk -F':[ \t]*' '
        BEGIN { IGNORECASE = 1 }
        /^Domain Status:/ {print $2}
    ' | paste -sd ", " - | xargs)

    if [ -z "$status" ]; then
        status="Unknown"
    fi

    if [ -n "$registrar" ]; then
        echo "Registrar: $registrar"
        summary+="✅ Registrar: $registrar\n"
    else
        echo "Registrar information not found."
        summary+="🛑 Registrar: Not found\n"
    fi

    echo "Domain status: $status"
    summary+="✅ Domain Status: $status\n"

    space
}

check_http_headers() {
    echo "Checking HTTP security headers..."
    headers=$(curl -sI "https://$domain")
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        echo "Content-Security-Policy header is set."
        summary+="✅ Content-Security-Policy: Set\n"
    else
        echo "Content-Security-Policy header is missing."
        summary+="🛑 Content-Security-Policy: Missing\n"
    fi
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        echo "X-Frame-Options header is set."
        summary+="✅ X-Frame-Options: Set\n"
    else
        echo "X-Frame-Options header is missing."
        summary+="🛑 X-Frame-Options: Missing\n"
    fi
    if echo "$headers" | grep -qi "X-XSS-Protection"; then
        echo "X-XSS-Protection header is set."
        summary+="✅ X-XSS-Protection: Set\n"
    else
        echo "X-XSS-Protection header is missing."
        summary+="🛑 X-XSS-Protection: Missing\n"
    fi
    space
}

check_cdn() {
    echo "Checking for CDN usage..."
    cdn=$(dig +short CNAME "$domain")
    if [[ "$cdn" == *"cloudfront.net."* ]] ||
        [[ "$cdn" == *"akamai.net."* ]] ||
        [[ "$cdn" == *"akamaihd.net."* ]] ||
        [[ "$cdn" == *"edgesuite.net."* ]] ||
        [[ "$cdn" == *"edgekey.net."* ]] ||
        [[ "$cdn" == *"fastly.net."* ]] ||
        [[ "$cdn" == *"cachefly.net."* ]] ||
        [[ "$cdn" == *"stackpathdns.com."* ]] ||
        [[ "$cdn" == *"cdn77.net."* ]] ||
        [[ "$cdn" == *"cdn.jsdelivr.net."* ]] ||
        [[ "$cdn" == *"cdnsun.net."* ]] ||
        [[ "$cdn" == *"cdngc.net."* ]] ||
        [[ "$cdn" == *"gccdn.net."* ]] ||
        [[ "$cdn" == *"googlehosted.com."* ]] ||
        [[ "$cdn" == *"internapcdn.net."* ]] ||
        [[ "$cdn" == *"kxcdn.com."* ]] ||
        [[ "$cdn" == *"lswcdn.net."* ]] ||
        [[ "$cdn" == *"netdna-cdn.com."* ]] ||
        [[ "$cdn" == *"netdna-ssl.com."* ]] ||
        [[ "$cdn" == *"netdna.com."* ]] ||
        [[ "$cdn" == *"hwcdn.net."* ]] ||
        [[ "$cdn" == *"clients.turbobytes.net."* ]] ||
        [[ "$cdn" == *"resrc.it."* ]] ||
        [[ "$cdn" == *"afxcdn.net."* ]] ||
        [[ "$cdn" == *"lxdns.com."* ]] ||
        [[ "$cdn" == *"cotcdn.net."* ]] ||
        [[ "$cdn" == *"speedcdn.net."* ]] ||
        [[ "$cdn" == *"cdncloud.net.au."* ]] ||
        [[ "$cdn" == *"rncdn1.com."* ]] ||
        [[ "$cdn" == *"cdnsba.com."* ]] ||
        [[ "$cdn" == *"gccdn.net."* ]] ||
        [[ "$cdn" == *"mwcloudcdn.com."* ]] ||
        [[ "$cdn" == *"qiniucdn.com."* ]] ||
        [[ "$cdn" == *"bitgravity.com."* ]] ||
        [[ "$cdn" == *"cdn.bitgravity.com."* ]] ||
        [[ "$cdn" == *"cdn.shopify.com."* ]] ||
        [[ "$cdn" == *"cloudflare.com."* ]] ||
        [[ "$cdn" == *"cloudflare.net."* ]] ||
        [[ "$cdn" == *"edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"systemcdn.net."* ]] ||
        [[ "$cdn" == *"worldssl.net."* ]] ||
        [[ "$cdn" == *"azureedge.net."* ]] ||
        [[ "$cdn" == *"voxcdn.net."* ]] ||
        [[ "$cdn" == *"simplecdn.net."* ]] ||
        [[ "$cdn" == *"akamaihd.net."* ]] ||
        [[ "$cdn" == *"cdn.sfr.net."* ]] ||
        [[ "$cdn" == *"sfrcdn.net."* ]] ||
        [[ "$cdn" == *"att-dsa.net."* ]] ||
        [[ "$cdn" == *"vo.msecnd.net."* ]] ||
        [[ "$cdn" == *"wac.bdcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.0006.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.0007.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.0009.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.000a.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.000b.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"wpc.000c.edgecastcdn.net."* ]] ||
        [[ "$cdn" == *"cdn1.hkbn.net."* ]] ||
        [[ "$cdn" == *"cdn2.hkbn.net."* ]]; then
        echo "CDN detected: $cdn"
    else
        echo "No CDN detected or CDN not recognized."
    fi
    space
}

check_ssl_cert() {
    echo "Checking SSL certificate validity..."
    cert_info=$(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -dates)
    if [ -n "$cert_info" ]; then
        start_date=$(echo "$cert_info" | grep "notBefore" | cut -d= -f2)
        end_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        echo "SSL Certificate Validity:"
        echo "   - Start Date: $start_date"
        echo "   - Expiry Date: $end_date"
        summary+="✅ SSL Certificate: Valid from $start_date to $end_date\n"
    else
        echo "Unable to retrieve SSL certificate information."
        summary+="🛑 SSL Certificate: Unable to retrieve info\n"
    fi
    space
}

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

echo -e "Completed domain health and email deliverability check for $domain."
echo ""
echo "•••••••••••••••••••••••••••••••••••••"
echo "•••••••••••••••••••••••••••••••••••••"
echo -e "••••••••• Summary of Checks •••••••••"
echo "•••••••••••••••••••••••••••••••••••••"
echo -e "•••••••••••••••••••••••••••••••••••••\n\n"
echo -e "$summary"
