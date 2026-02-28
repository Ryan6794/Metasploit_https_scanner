#
# This module requires Metasploit framework
# Tested with Metasploit 6+
#

require 'msf/core'
require 'net/http'
require 'uri'
require 'openssl'
require 'socket'
require 'fileutils'
require 'thread'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP/HTTPS Subdomain Scanner (Multithreaded)',
      'Description' => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, TLS version, and HTTP response status codes.

        - Multithreaded scanning
        - Stores results as Metasploit loot
        - Optional custom logfile
        - Optional failed request output for speed testing
        - HTTP/HTTPS response status detection
      },
      'Author'      => ['Ryan Lyman'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Base domain to scan', 'example.com']),
        OptInt.new('TIMEOUT', [true, 'Connection timeout in seconds', 5]),
        OptInt.new('THREADS', [true, 'Number of concurrent threads', 10]),
        OptInt.new('RETRY_COUNT', [true, 'Number of retries per request', 1]),
        OptInt.new('HTTP_PORT', [true, 'HTTP port', 80]),
        OptInt.new('HTTPS_PORT', [true, 'HTTPS port', 443]),

        OptPath.new('SUBDOMAIN_FILE', [false, 'Subdomain wordlist',
          File.join(Msf::Config.install_root, 'data', 'subdomains', 'common.txt')
        ]),

        OptString.new('LOGFILE', [false, 'Optional log file (created if missing)']),

        OptBool.new('SHOW_FAILED',
          [false, 'Show domains that return no response (for speed testing)', false]
        )
      ]
    )
  end

  def run
    base_domain = datastore['DOMAIN']
    sub_file    = datastore['SUBDOMAIN_FILE']
    timeout     = datastore['TIMEOUT']
    logfile     = datastore['LOGFILE']
    threads     = datastore['THREADS'] || 10
    show_failed = datastore['SHOW_FAILED']

    retry_count = datastore['RETRY_COUNT'] || 1
    http_port   = datastore['HTTP_PORT'] || 80
    https_port  = datastore['HTTPS_PORT'] || 443

    @mutex = Mutex.new
    @stop_requested = false

    trap('INT') do
      print_warning('Stopping scan... please wait.')
      @stop_requested = true
    end

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

    queue = Queue.new
    subdomains.each do |sub|
      domain = sub.empty? ? base_domain : "#{sub}.#{base_domain}"
      queue << domain
    end

    @total = queue.size
    @processed = 0
    update_progress_bar

    workers = []

    threads.times do
      workers << Thread.new do
        while !queue.empty? && !@stop_requested
          domain = queue.pop(true) rescue nil
          next unless domain
          break if @stop_requested

          unless resolves?(domain)
            if show_failed
              @mutex.synchronize { print_status("NO DNS: #{domain}") }
            end
            increment_progress
            next
          end

          result = check_https_status(domain, timeout, retry_count, http_port, https_port)

          unless result
            if show_failed
              @mutex.synchronize { print_status("NO RESPONSE: #{domain}") }
            end
            increment_progress
            next
          end

          @mutex.synchronize do
            store_loot_result(result)
            log_result(logfile, result) if logfile
          end

          increment_progress
        end
      end
    end

    workers.each(&:join)

    print_line("")
    print_status('Scan completed.')
  end

  def increment_progress
    @mutex.synchronize do
      @processed += 1
      update_progress_bar
    end
  end

  def update_progress_bar
    return if @total.nil? || @total == 0

    percent = (@processed.to_f / @total * 100).round(1)
    bar_length = 30
    filled = (@processed.to_f / @total * bar_length).round
    bar = "[" + "#" * filled + "-" * (bar_length - filled) + "]"

    print("\r#{bar} #{percent}% (#{@processed}/#{@total})")
  end

  def cleanup
    print_warning('Scan interrupted by user.') if @stop_requested
  end

  def resolves?(host)
    Addrinfo.getaddrinfo(host, nil)
    true
  rescue
    false
  end

  def get_tls_version(host, port)
    tcp = nil
    ssl = nil

    begin
      ctx = OpenSSL::SSL::SSLContext.new
      tcp = Socket.tcp(host, port, connect_timeout: 5)

      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = host
      ssl.sync_close = true

      ssl.connect
      ssl.ssl_version
    rescue
      nil
    ensure
      ssl&.close
      tcp&.close
    end
  end

  def check_https_status(domain, timeout, retry_count, http_port, https_port)
    http_url  = "http://#{domain}:#{http_port}"
    https_url = "https://#{domain}:#{https_port}"

    reached_https = false
    reached_http  = false
    https_supported = false
    http_redirects_to_https = false
    tls_version = nil

    http_status = nil
    https_status = nil

    # HTTPS CHECK
    retry_count.times do
      break if reached_https

      begin
        uri = URI.parse(https_url)

        res = Net::HTTP.start(
          uri.host,
          uri.port,
          use_ssl: true,
          verify_mode: OpenSSL::SSL::VERIFY_NONE,
          read_timeout: timeout
        ) { |http| http.get('/') }

        reached_https = true
        https_supported = true
        https_status = res.code
        tls_version = get_tls_version(domain, https_port)

      rescue
        sleep(0.2)
      end
    end

    # HTTP CHECK
    retry_count.times do
      break if reached_http

      begin
        uri = URI.parse(http_url)

        res = Net::HTTP.start(
          uri.host,
          uri.port,
          read_timeout: timeout
        ) { |http| http.get('/') }

        reached_http = true
        http_status = res.code

        if res.is_a?(Net::HTTPRedirection)
          location = res['location']
          http_redirects_to_https = location&.start_with?('https://')
        end

      rescue
        sleep(0.2)
      end
    end

    return nil unless reached_http || reached_https

    @mutex.synchronize do
      print_status("Checking #{domain}")

      if https_supported
        print_good("HTTPS supported (#{https_status})")
      else
        print_error("HTTPS not supported")
      end

      print_status("HTTP status: #{http_status}") if http_status
      print_status("HTTPS status: #{https_status}") if https_status

      if reached_http
        if http_redirects_to_https
          print_good("HTTP redirects to HTTPS")
        else
          print_status("HTTP does not redirect to HTTPS")
        end
      end

      print_good("TLS version: #{tls_version}") if tls_version
    end

    {
      domain: domain,
      https: https_supported,
      http_redirect: http_redirects_to_https,
      tls: tls_version,
      http_status: http_status,
      https_status: https_status
    }
  end

  def store_loot_result(result)
    timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')
    safe_domain = result[:domain].gsub(/[^a-zA-Z0-9\.\-]/, '_')

    loot_data = <<~DATA
      ===== HTTPS Scan Result =====
      Scan Time: #{Time.now}
      Domain: #{result[:domain]}

      Security Details
      ----------------
      HTTPS Supported: #{result[:https]}
      HTTP Status Code: #{result[:http_status] || 'N/A'}
      HTTPS Status Code: #{result[:https_status] || 'N/A'}
      HTTP Redirects to HTTPS: #{result[:http_redirect]}
      TLS Version: #{result[:tls] || 'N/A'}
    DATA

    filename = "https_scan_#{safe_domain}_#{timestamp}.txt"

    store_loot(
      'https.subdomain.scan',
      'text/plain',
      result[:domain],
      loot_data,
      filename,
      "HTTPS Scan #{safe_domain}"
    )
  end

  def log_result(logfile, result)
    timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')

    base = ::File.basename(logfile, '.*')
    ext  = ::File.extname(logfile)

    logfile_with_time = ::File.join(
      ::File.dirname(logfile),
      "#{base}_#{timestamp}#{ext}"
    )

    ::File.open(logfile_with_time, 'a') do |f|
      f.puts(
        "[#{timestamp}] #{result[:domain]} | " \
        "HTTP=#{result[:http_status] || 'N/A'} | " \
        "HTTPS=#{result[:https_status] || 'N/A'} | " \
        "HTTPS_SUPPORTED=#{result[:https]} | " \
        "HTTP->HTTPS=#{result[:http_redirect]} | " \
        "TLS=#{result[:tls] || 'N/A'}"
      )
    end
  end
end