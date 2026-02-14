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
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP/HTTPS Subdomain Scanner (Multithreaded)',
      'Description' => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, and TLS version.
        Results are stored as Metasploit loot with optional file logging.
        Uses multithreading for faster scanning.
      },
      'Author'      => ['Ryan Lyman'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Base domain to scan', 'example.com']),
        OptInt.new('TIMEOUT', [true, 'Connection timeout in seconds', 5]),
        OptInt.new('THREADS', [true, 'Number of concurrent threads', 10]),
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
    threads     = datastore['THREADS']

    @mutex = Mutex.new
    @results = []

    # Ensure logfile exists early (even if interrupted)
    if logfile
      FileUtils.mkdir_p(File.dirname(logfile)) rescue nil
      ::File.open(logfile, 'a') {}
    end

    # Build subdomain list
    subdomains = []

    if sub_file && File.exist?(sub_file)
      ::File.readlines(sub_file).each do |line|
        subdomains << line.strip unless line.strip.empty?
      end
    else
      subdomains << ''
    end

    # Create work queue
    queue = Queue.new

    subdomains.each do |sub|
      full_domain = sub.empty? ? base_domain : "#{sub}.#{base_domain}"
      queue << full_domain
    end

    print_status("Loaded #{queue.size} targets")
    print_status("Starting scan with #{threads} threads...")

    workers = []

    threads.times do |i|
      workers << Rex::ThreadFactory.spawn("scanner-worker-#{i}", false) do
        loop do
          begin
            domain = queue.pop(true)
          rescue ThreadError
            break
          end

          next unless resolves?(domain)

          result = check_https_status(domain, timeout)
          next unless result

          # Thread-safe storage + logging
          @mutex.synchronize do
            @results << result
            store_loot_result(result)
            log_result(logfile, result) if logfile
          end
        end
      end
    end

    workers.each(&:join)

    print_good("Scan completed — #{@results.length} results saved.")
  end

  def cleanup
    print_status("Scan interrupted — #{@results&.length || 0} partial results saved.")
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

    # HTTPS check
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

    # HTTP check
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
  # Store results in Metasploit loot
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
  def log_result(logfile, result_
