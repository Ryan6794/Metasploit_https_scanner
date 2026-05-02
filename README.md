# HTTP/HTTPS Subdomain Scanner (Metasploit Module)

## Overview

The **HTTP/HTTPS Subdomain Scanner** is a custom auxiliary module for the Metasploit Framework designed to enumerate subdomains and assess their web security posture.

It performs fast, multithreaded reconnaissance to identify:

* HTTPS availability
* HTTP → HTTPS redirection behavior
* TLS version in use
* SSL/TLS certificate details
* Security headers (HSTS, CSP, etc.)
* HTTP/HTTPS response status codes

This module is useful for **reconnaissance, security assessments, and misconfiguration discovery**.

---

## Features

* Multithreaded subdomain scanning
* DNS resolution validation (filters wildcard DNS)
* HTTP and HTTPS endpoint analysis
* HTTP → HTTPS redirection detection
* TLS version extraction (no duplicate connections)
* SSL/TLS certificate inspection:

* Issuer
* Expiration
* SANs
* Self-signed detection
* Security header analysis:

* HSTS
* CSP
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy
* Connection pooling for performance
* Retry logic for unstable hosts
* Export results to:

* JSON
* CSV
* Stores results in Metasploit loot database
* Optional display of failed/unreachable hosts

---

## Requirements

* Metasploit Framework 6+
* Ruby (included with Metasploit)
* Network access to target domains

---


## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/Ryan6794/Metasploit_https_scanner/main/install.sh | bash
```

---

## Manual Installation

Copy the module into your Metasploit modules directory:

```bash
cp https_subdomain_scanner.rb \
~/.msf4/modules/auxiliary/scanner/http/
```

Reload modules:

```bash
msfconsole
msf6 > reload_all
```

---

## Usage

### Basic Example

```bash
msf6 > use auxiliary/scanner/http/https_subdomain_scanner
msf6 auxiliary(http_https_subdomain_scanner) > set DOMAIN example.com
msf6 auxiliary(http_https_subdomain_scanner) > run
```

---

### Common Options

#### Use a Custom Wordlist

```bash
set SUBDOMAIN_FILE /path/to/subdomains.txt
```

#### Increase Speed (More Threads)

```bash
set THREADS 20
```

#### Adjust Timeout

```bash
set TIMEOUT 10
```

#### Enable Output Export

```bash
set EXPORT_JSON true
set EXPORT_CSV true
set EXPORT_PATH ~/Downloads
```

#### Show Failed Hosts (Debug/Testing)

```bash
set SHOW_FAILED true
```

---

## Module Options

| Option         | Required | Description                  | Default     |
| -------------- | -------- | ---------------------------- | ----------- |
| DOMAIN         | Yes      | Base domain to scan          | example.com |
| SUBDOMAIN_FILE | No       | Subdomain wordlist           | common.txt  |
| THREADS        | Yes      | Number of concurrent threads | 10          |
| TIMEOUT        | Yes      | Connection timeout (seconds) | 5           |
| RETRY_COUNT    | Yes      | Request retries              | 1           |
| HTTP_PORT      | Yes      | HTTP port                    | 80          |
| HTTPS_PORT     | Yes      | HTTPS port                   | 443         |
| USER_AGENT     | Yes      | Custom User-Agent            | Browser UA  |
| EXPORT_JSON    | No       | Export JSON results          | false       |
| EXPORT_CSV     | No       | Export CSV results           | false       |
| EXPORT_PATH    | No       | Output directory             | ~/Downloads |
| SHOW_FAILED    | No       | Show unreachable hosts       | false       |

---

## Output Details

For each subdomain, the module reports:

* DNS resolution status
* HTTP status code
* HTTPS status code
* HTTPS support (true/false)
* HTTP → HTTPS redirect behavior
* Page title (if available)
* TLS version (reused from existing connection)
* Security header presence (HTTP & HTTPS)
* Certificate details:

  * Issuer
  * Validity dates
  * Days remaining
  * Self-signed status
  * Subject Alternative Names (SANs)

---

## Example Findings

This module helps quickly identify:

* Subdomains without HTTPS
* Sites exposing plaintext HTTP
* Missing security headers
* Expired or self-signed certificates
* Weak or inconsistent TLS deployments

---

## Performance Notes

* Uses **thread pooling** for high-speed scanning
* Reuses HTTP connections to reduce overhead
* Extracts TLS + certificate info from the same socket (no duplicate handshakes)
* Handles unreliable hosts with retry logic

---

## Limitations

* SSL verification is disabled (`VERIFY_NONE`)
* No cipher suite enumeration
* No deep vulnerability scanning (recon only)
* Dependent on wordlist quality for discovery

---

## Legal Disclaimer

This module is intended for **authorized security testing and educational purposes only**.

You must have explicit permission before scanning any system you do not own.

Unauthorized scanning may violate laws and regulations.

---

## Author

**Ryan Lyman**

---

## Future Improvements

* Cipher suite enumeration
* HTTP/2 detection
* Screenshot capture of web services
* Integration with reporting dashboards
* Passive subdomain enumeration sources

---
