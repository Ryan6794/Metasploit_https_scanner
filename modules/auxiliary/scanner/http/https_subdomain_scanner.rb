##
# This module requires Metasploit framework
# Tested with Metasploit 6+
##

require 'msf/core'
require 'net/http'
require 'uri'
require 'openssl'
require 'socket'

class MetasploitModule < Msf::Auxiliary
  

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP/HTTPS Subdomain Scanner',
      'Description'    => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, and TLS version.
      },
      'Author'         => ['Ryan Lyman'],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Base domain to scan', 'example.com']),
        OptInt.new('TIMEOUT', [true, 'Connection timeout in seconds', 5]),
        OptPath.new('SUBDOMAIN_FILE', [false, 'Subdomain wordlist', File.join(Msf::Config.install_root, 'data', 'subdomains', 'common.txt')])
      ]
    )
  end

  def run
    base_domain = datastore['DOMAIN']
    sub_file = datastore['SUBDOMAIN_FILE']
    timeout = datastore['TIMEOUT']

    subdomains = []

    if sub_file && File.exist?(sub_file)
      ::File.readlines(sub_file).each do |line|
        subdomains << line.strip unless line.strip.empty?
      end
    else
      subdomains << ''  # Scan just the base domain if no file
    end

    subdomains.each do |sub|
      full_domain = sub.empty? ? base_domain : "#{sub}.#{base_domain}"
      if resolves?(full_domain)
        check_https_status(full_domain, timeout)
      else
        print_status("Skipping #{full_domain} — does not resolve")
      end
    end
  end

  def resolves?(host)
    begin
      Socket.gethostbyname(host)
      true
    rescue SocketError
      false
    end
  end

  def get_tls_version(host, port = 443, timeout = 5)
    ctx = OpenSSL::SSL::SSLContext.new
    begin
      tcp_socket = TCPSocket.new(host, port)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ctx)
      ssl_socket.hostname = host
      ssl_socket.connect
      version = ssl_socket.ssl_version
      ssl_socket.close
      tcp_socket.close
      return version
    rescue
      return nil
    end
  end

  def check_https_status(domain, timeout)
    http_url = "http://#{domain}"
    https_url = "https://#{domain}"

    print_status("\n--- Checking #{domain} ---")

    reached = false
    https_supported = false
    http_redirects_to_https = false
    tls_version = nil

    # HTTPS check
    begin
      uri = URI.parse(https_url)
      res = Net::HTTP.start(uri.host, uri.port,
                            use_ssl: true,
                            verify_mode: OpenSSL::SSL::VERIFY_NONE,
                            read_timeout: timeout) do |http|
        http.get(uri.path.empty? ? '/' : uri.path)
      end
      reached = true
      https_supported = true
      tls_version = get_tls_version(domain)
      print_good("✅ Reached via HTTPS (#{https_url}) [Status #{res.code}]")
      print_good("🔐 TLS Version: #{tls_version}") if tls_version
    rescue => e
      print_error("❌ HTTPS error: #{e.message}")
    end

    # HTTP check
    begin
      uri = URI.parse(http_url)
      res = Net::HTTP.start(uri.host, uri.port, read_timeout: timeout) do |http|
        http.get(uri.path.empty? ? '/' : uri.path)
      end
      reached = true
      if res.is_a?(Net::HTTPRedirection)
        location = res['location']
        if location.start_with?('https://')
          http_redirects_to_https = true
          print_good("🔁 HTTP redirects to HTTPS (#{location})")
        else
          print_status("⚠️ HTTP redirects but not to HTTPS (#{location})")
        end
      elsif res.is_a?(Net::HTTPSuccess)
        print_status("❌ HTTP reachable but NOT redirected to HTTPS (#{http_url})")
      else
        print_status("⚠️ HTTP response code: #{res.code}")
      end
    rescue => e
      print_error("⚠️ HTTP error: #{e.message}")
    end

    # Summary
    print_status("\nSummary for #{domain}:")
    if reached
      print_good("🔒 HTTPS supported") if https_supported
      print_error("❌ HTTPS not supported") unless https_supported
      print_good("➡️ HTTP redirects to HTTPS") if http_redirects_to_https
      print_status("⚠️ HTTP does NOT redirect to HTTPS") unless http_redirects_to_https
      print_good("🔐 TLS version: #{tls_version}") if tls_version
    else
      print_error("❌ Could not reach the website")
    end
  end
end
