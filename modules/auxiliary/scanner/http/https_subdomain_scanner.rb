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
require 'thread'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP/HTTPS Subdomain Scanner (Multithreaded)',
      'Description' => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, and TLS version.

        - Multithreaded scanning
        - Stores results as Metasploit loot
        - Optional custom logfile
        - Optional failed request output for speed testing
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

    @mutex = Mutex.new
    @stop_requested = false

    # Handle Ctrl+C cleanly
    trap('INT') do
      print_warning('Stopping scan... please wait.')
      @stop_requested = true
    end

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

    # Build queue
    queue = Queue.new
    subdomains.each do |sub|
      domain = sub.empty? ? base_domain : "#{sub}.#{base_domain}"
      queue << domain
    end

    # Progress tracking
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

          result = check_https_status(domain, timeout)

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

    print_line("") # move cursor to new line after bar
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

    @mutex.synchronize do
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
    end

    {
      domain: domain,
      https: https_supported,
      http_redirect: http_redirects_to_https,
      tls: tls_version
    }
  end

  def store_loot_result(result)
    # Clean timestamp (sortable + readable)
    timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')

    # Sanitize domain for filesystem safety
    safe_domain = result[:domain].gsub(/[^a-zA-Z0-9\.\-]/, '_')

    # Pretty formatted output content
    loot_data = <<~DATA
      ===== HTTPS Scan Result =====
      Scan Time: #{Time.now}
      Domain: #{result[:domain]}

      Security Details
      ----------------
      HTTPS Supported: #{result[:https]}
      HTTP Redirects to HTTPS: #{result[:http_redirect]}
      TLS Version: #{result[:tls] || 'N/A'}
    DATA

    # Clean filename format
    filename = "https_scan_#{safe_domain}_#{timestamp}.txt"

    store_loot(
      'https.subdomain.scan',
      'text/plain',
      result[:domain],   # host
      loot_data,
      filename,
      "HTTPS Scan #{safe_domain}"
    )
  end



  #
  # Optional raw logfile (auto timestamped filename + entry time)
  #
  def log_result(logfile, result)
    # Create timestamp
    timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')

    # Add timestamp to logfile name automatically
    base = ::File.basename(logfile, '.*')
    ext  = ::File.extname(logfile)
    logfile_with_time = ::File.join(
      ::File.dirname(logfile),
      "#{base}_#{timestamp}#{ext}"
    )

    ::File.open(logfile_with_time, 'a') do |f|
      f.puts(
        "[#{timestamp}] #{result[:domain]} | " \
        "HTTPS=#{result[:https]} | " \
        "HTTP->HTTPS=#{result[:http_redirect]} | " \
        "TLS=#{result[:tls] || 'N/A'}"
      )
    end
  end
end
