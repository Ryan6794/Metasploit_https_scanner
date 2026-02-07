HTTP/HTTPS Subdomain Scanner (Metasploit Module)
Overview

The HTTP/HTTPS Subdomain Scanner is a Metasploit auxiliary module designed to enumerate subdomains of a target domain and evaluate their web security posture.
For each resolvable subdomain, the module checks:

Whether HTTPS is supported

Whether HTTP redirects to HTTPS

Which TLS version is negotiated (if HTTPS is available)

This module is useful for reconnaissance, security assessments, and identifying misconfigurations such as plaintext HTTP access or outdated TLS versions.

Features

Subdomain enumeration using a wordlist

DNS resolution validation before scanning

HTTPS availability detection

HTTP to HTTPS redirection analysis

TLS version identification

Configurable network timeout

Graceful handling of unreachable or misconfigured hosts

Requirements

Metasploit Framework 6+

Ruby (included with Metasploit)

Network access to target domains

Tested with Metasploit Framework 6.x.

Installation

Copy the module into your Metasploit auxiliary modules directory:

cp https_subdomain_scanner.rb \
~/.msf4/modules/auxiliary/scanner/http/


Reload Metasploit modules:

msfconsole
msf6 > reload_all

Usage
Basic Example
msf6 > use auxiliary/scanner/http/https_subdomain_scanner
msf6 auxiliary(http_https_subdomain_scanner) > set DOMAIN example.com
msf6 auxiliary(http_https_subdomain_scanner) > run

Using a Custom Subdomain Wordlist
msf6 auxiliary(http_https_subdomain_scanner) > set SUBDOMAIN_FILE /path/to/subdomains.txt

Adjusting Timeout
msf6 auxiliary(http_https_subdomain_scanner) > set TIMEOUT 10

Options
Option	Required	Description	Default
DOMAIN	Yes	Base domain to scan	example.com
SUBDOMAIN_FILE	No	File containing subdomains (one per line)	common.txt
TIMEOUT	Yes	Connection timeout (seconds)	5

If no subdomain file is provided, the module scans only the base domain.

Output Details

For each subdomain, the module reports:

DNS resolution status

HTTPS reachability

HTTP behavior (redirects, plaintext access, errors)

TLS version (if HTTPS is supported)

A summary of findings per host

This makes it easy to identify:

Hosts lacking HTTPS

Hosts exposing HTTP without redirection

Inconsistent TLS deployments across subdomains

Limitations

TLS certificates are not validated (VERIFY_NONE is used)

No cipher suite enumeration

No parallelization (runs sequentially)

Designed for reconnaissance, not exploitation

Legal Disclaimer

This module is intended for authorized security testing and educational purposes only.
You are responsible for obtaining proper authorization before scanning any systems you do not own.

Author

Ryan Lyman