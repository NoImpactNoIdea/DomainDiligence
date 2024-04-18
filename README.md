# Domain Inspector Script

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

This Bash script provides a comprehensive look at DNS and selective WHOIS information for a specified domain, focusing on non-sensitive data to comply with privacy regulations.

## Features

- **HTTP Header Check**: Retrieves the HTTP headers of the domain.
- **DNS Records Lookup**: Includes A, MX, TXT, NS, SOA, CNAME, and ANY records.
- **Selective WHOIS Lookup**: Fetches non-sensitive WHOIS information such as the registrar, domain status, and name servers.

## Prerequisites

Ensure `dig`, `whois`, and `curl` are installed on your system.

## Usage

Provide the domain as a single argument:

```bash
./diligence.sh example.com
```
