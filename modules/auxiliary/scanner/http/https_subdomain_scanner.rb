##
# This module requires Metasploit framework
# Tested with Metasploit 6+
##

require 'msf/core'
require 'net/http'
require 'uri'
require 'openssl'
require 'socket'
require 'fileutils'

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP/HTTPS Subdomain Scanner',
      'Description' => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, and TLS version.
        Results are stored as Metasploit loot with optional file logging.
      },
      'Author'      => ['Ryan Lyman'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Base domain to scan', 'example.com']),
        OptInt.new('TIMEOUT', [true, 'Connection timeout in seconds', 5]),
        OptPath.new('SUBDOMAIN_FILE', [false, 'Subdomain wordlist',
          File.join(Msf::Config.install_root, 'data', 'subdomains', 'common.txt')
        ]),
        OptString.new('LOGFILE', [false, 'Optional log file (created if missing)'])
      ]
    )
  end

  def run
    base_domain = datastore['DOMAIN']
    sub_file    = datastore['SUBDOMAIN_FILE']
    timeout     = datastore['TIMEOUT']
    logfile     = datastore['LOGFILE']

    # Touch logfile early so Ctrl+C still leaves a file
    if logfile
      FileUtils.mkdir_p(File.dirname(logfile)) rescue nil
      ::File.open(logfile, 'a') {}
    end

    subdomains = []

    if sub_file && File.exist?(sub_file)
      ::File.readlines(sub_file).each do |line|
        subdomains << line.strip unless line.strip.empty?
      end
    else
      subdomains << ''
    end

    subdomains.each do |sub|
      full_domain = sub.empty? ? base_domain : "#{sub}.#{base_domain}"
      next unless resolves?(full_domain)

      result = check_https_status(full_domain, timeout)
      next unless result

      store_loot_result(result)
      log_result(logfile, result) if logfile
    end
  end

  def resolves?(host)
    Addrinfo.getaddrinfo(host, nil)
    true
  rescue
    false
  end

  def get_tls_version(host, port = 443)
    ctx = OpenSSL::SSL::SSLContext.new
    tcp = TCPSocket.new(host, port)
    ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
    ssl.hostname = host
    ssl.connect
    version = ssl.ssl_version
    ssl.close
    tcp.close
    version
  rescue
    nil
  end

  def check_https_status(domain, timeout)
    http_url  = "http://#{domain}"
    https_url = "https://#{domain}"

    reached_https = false
    reached_http  = false
    https_supported = false
    http_redirects_to_https = false
    tls_version = nil

    # HTTPS
    begin
      uri = URI.parse(https_url)
      Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
        read_timeout: timeout
      ) { |http| http.get('/') }

      reached_https = true
      https_supported = true
      tls_version = get_tls_version(domain)
    rescue
    end

    # HTTP
    begin
      uri = URI.parse(http_url)
      res = Net::HTTP.start(
        uri.host,
        uri.port,
        read_timeout: timeout
      ) { |http| http.get('/') }

      reached_http = true

      if res.is_a?(Net::HTTPRedirection)
        location = res['location']
        http_redirects_to_https = location&.start_with?('https://')
      end
    rescue
    end

    return nil unless reached_http || reached_https

    print_status("Checking #{domain}")

    print_good("HTTPS supported") if https_supported
    print_error("HTTPS not supported") unless https_supported

    if reached_http
      if http_redirects_to_https
        print_good("HTTP redirects to HTTPS")
      else
        print_status("HTTP does not redirect to HTTPS")
      end
    end

    print_good("TLS version: #{tls_version}") if tls_version

    {
      domain: domain,
      https: https_supported,
      http_redirect: http_redirects_to_https,
      tls: tls_version
    }
  end

  #
  # Canonical Metasploit storage
  #
  def store_loot_result(result)
    loot_data = <<~DATA
      Domain: #{result[:domain]}
      HTTPS Supported: #{result[:https]}
      HTTP Redirects to HTTPS: #{result[:http_redirect]}
      TLS Version: #{result[:tls] || 'N/A'}
    DATA

    store_loot(
      'https.subdomain.scan',
      'text/plain',
      result[:domain],
      loot_data,
      "#{result[:domain]} HTTPS scan"
    )
  end

  #
  # Optional raw logfile
  #
  def log_result(logfile, result)
    ::File.open(logfile, 'a') do |f|
      f.puts(
        "#{result[:domain]} | " \
        "HTTPS=#{result[:https]} | " \
        "HTTP->HTTPS=#{result[:http_redirect]} | " \
        "TLS=#{result[:tls] || 'N/A'}"
      )
    end
  end
end
