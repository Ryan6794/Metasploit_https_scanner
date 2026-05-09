# !/usr/bin/env bash

set -e

printf "[*] Removing HTTP/HTTPS Subdomain Scanner...\n"

rm -f ~/.msf4/modules/auxiliary/scanner/http/https_subdomain_scanner.rb
rm -f ~/.msf4/data/subdomains/common.txt
rm -rf ~/.msf4/module_cache

printf "[+] Module removed successfully\n"