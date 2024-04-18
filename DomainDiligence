#!/bin/bash

# check commands installation
command_exists() {
    type "$1" &>/dev/null
}

# dig | whois | curl
if ! command_exists dig || ! command_exists whois || ! command_exists curl; then
    echo "This script requires 'dig' | 'whois' | 'curl' to be installed."
    echo "Please install missing tools and try again."
    exit 1
fi

# validate input (domain)
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# extract the domain
domain=$(echo "$1" | sed -E 's|^(https?://)?([^/]+).*|\2|')

echo "💬 Gathering DNS and non-sensitive WHOIS information for $domain..."

# HTTP response
echo "Checking HTTP response:"
curl -I --silent "$domain" | head -n 10

# DNS information
echo "🚨 DNS Records:"
echo "A Records:"
dig +noall +answer $domain A
echo "MX Records:"
dig +noall +answer $domain MX
echo "TXT Records:"
dig +noall +answer $domain TXT
echo "NS Records:"
dig +noall +answer $domain NS
echo "SOA Record:"
dig +noall +answer $domain SOA
echo "CNAME Records:"
dig +noall +answer $domain CNAME
echo "ANY Records:"
dig +noall +answer $domain ANY

# WHOIS information (focused on non-sensitive data)
echo "🚨 WHOIS Information:"
whois_output=$(whois $domain)
echo "$whois_output" | grep "Registrar:\|Domain Status:\|Name Server:"
# Display registrar, domain status, and name servers from the WHOIS output

echo "Completed DNS and WHOIS lookup for $domain."
