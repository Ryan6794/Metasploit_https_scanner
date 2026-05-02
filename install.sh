#!/usr/bin/env bash

set -e

echo "[*] Installing HTTP/HTTPS Subdomain Scanner..."

# --- REPO FILES ---
MODULE_URL="https://raw.githubusercontent.com/Ryan6794/Metasploit_https_scanner/main/https_subdomain_scanner.rb"
WORDLIST_URL="https://raw.githubusercontent.com/Ryan6794/Metasploit_https_scanner/main/common.txt"

# --- DETECT METASPLOIT INSTALL TYPE ---
if [ -d "/usr/share/metasploit-framework" ]; then
    MSF_BASE="/usr/share/metasploit-framework"
else
    MSF_BASE="$HOME/.msf4"
fi

# --- PATHS ---
MODULE_DIR="$MSF_BASE/modules/auxiliary/scanner/http"
WORDLIST_DIR="$MSF_BASE/data/subdomains"

# --- CREATE DIRECTORIES ---
echo "[*] Creating directories..."
mkdir -p "$MODULE_DIR"
mkdir -p "$WORDLIST_DIR"

# --- DOWNLOAD FILES ---
echo "[*] Downloading module..."
curl -sSL "$MODULE_URL" -o "$MODULE_DIR/https_subdomain_scanner.rb"

echo "[*] Downloading wordlist..."
curl -sSL "$WORDLIST_URL" -o "$WORDLIST_DIR/common.txt"

# --- PERMISSIONS ---
chmod 644 "$MODULE_DIR/https_subdomain_scanner.rb"
chmod 644 "$WORDLIST_DIR/common.txt"

# --- VERIFY ---
if [[ -f "$MODULE_DIR/https_subdomain_scanner.rb" ]]; then
    echo "[+] Module installed successfully"
else
    echo "[!] Module install failed"
fi

if [[ -f "$WORDLIST_DIR/common.txt" ]]; then
    echo "[+] Wordlist installed successfully"
else
    echo "[!] Wordlist install failed"
fi

echo ""
echo "[*] Installation complete"
echo "[*] Metasploit base detected at: $MSF_BASE"
echo ""
echo "[*] Launch Metasploit:"
echo "    msfconsole"
echo ""
echo "[*] Then run:"
echo "    reload_all"
echo "    use auxiliary/scanner/http/https_subdomain_scanner"
echo ""
echo "[*] Default wordlist path will be:"
echo "    $WORDLIST_DIR/common.txt"