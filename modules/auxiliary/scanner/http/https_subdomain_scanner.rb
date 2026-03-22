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
require 'json'
require 'csv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP/HTTPS Subdomain Scanner (Multithreaded)',
      'Description' => %q{
        Scans subdomains of a base domain for HTTPS support,
        HTTP redirects, TLS version, and HTTP response status codes.

        - Multithreaded scanning
        - Export results to CSV or JSON
        - Stores results in the Metasploit Loot database
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
        OptString.new('USER_AGENT', [true, 'Custom HTTP User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36']),
        OptBool.new('EXPORT_JSON', [false, 'Export results to JSON', false]),
        OptBool.new('EXPORT_CSV', [false, 'Export results to CSV', false]),
        OptPath.new('EXPORT_PATH', [false, 'Directory to store exported scan results', './msf_scans']),
        OptPath.new('SUBDOMAIN_FILE', [false, 'Subdomain wordlist',
          File.join(Msf::Config.install_root, 'data', 'subdomains', 'common.txt')
        ]),
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
    threads     = datastore['THREADS'] || 10
    show_failed = datastore['SHOW_FAILED']

    retry_count = datastore['RETRY_COUNT'] || 1
    http_port   = datastore['HTTP_PORT'] || 80
    https_port  = datastore['HTTPS_PORT'] || 443

    @mutex = Mutex.new
    @stop_requested = false
    @wildcard_ips = detect_wildcard(base_domain)

    @results = []

    trap('INT') do
      print_warning('Stopping scan... please wait.')
      @stop_requested = true
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
            @results << result
          end

          increment_progress
        end
      end
    end

    workers.each(&:join)

    export_results
    print_line("")
    print_status('Scan completed.')
    
  end


  def detect_wildcard(domain)
    random_sub = "#{Rex::Text.rand_text_alpha(12)}.#{domain}"

    begin
      ips = Addrinfo.getaddrinfo(random_sub, nil).map { |a| a.ip_address }.uniq

      if ips.any?
        print_warning("Wildcard DNS detected for #{domain} -> #{ips.join(', ')}")
        return ips
      end
    rescue
      # No wildcard
    end

    print_status("No wildcard DNS detected for #{domain}")
    []
  end

  def increment_progress
    @mutex.synchronize do
      @processed += 1
      update_progress_bar
    end
  end


  def extract_title(body)
    return nil unless body

    match = body.match(/<title[^>]*>(.*?)<\/title>/im)
    return nil unless match

    title = match[1].strip

    # Clean whitespace
    title.gsub(/\s+/, ' ')
  rescue
    nil
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
    ips = Addrinfo.getaddrinfo(host, nil).map { |a| a.ip_address }.uniq

    return false if ips.empty?

    # Filter wildcard DNS matches
    if @wildcard_ips && !@wildcard_ips.empty?
      if (ips & @wildcard_ips).any?
        return false
      end
    end

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



  def get_certificate_info(host, port)
    tcp = nil
    ssl = nil

    begin
      ctx = OpenSSL::SSL::SSLContext.new
      tcp = Socket.tcp(host, port, connect_timeout: 5)

      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = host
      ssl.sync_close = true
      ssl.connect

      cert = ssl.peer_cert

      subject = cert.subject.to_s
      issuer = cert.issuer.to_s
      not_before = cert.not_before
      not_after = cert.not_after

      days_remaining = ((not_after - Time.now) / 86400).to_i

      # Self-signed check
      self_signed = (cert.issuer.to_s == cert.subject.to_s)

      # Extract SANs
      san = []
      ext = cert.extensions.find { |e| e.oid == "subjectAltName" }
      if ext
        san = ext.value.split(",").map { |x| x.strip.gsub("DNS:", "") }
      end

      {
        subject: subject,
        issuer: issuer,
        valid_from: not_before,
        valid_to: not_after,
        days_remaining: days_remaining,
        expired: Time.now > not_after,
        self_signed: self_signed,
        san: san
      }

    rescue
      nil
    ensure
      ssl&.close
      tcp&.close
    end
  end


  def analyze_security_headers(headers)
    checks = {
      "strict-transport-security" => "HSTS",
      "content-security-policy" => "CSP",
      "x-frame-options" => "X-Frame-Options",
      "x-content-type-options" => "X-Content-Type-Options",
      "referrer-policy" => "Referrer-Policy",
      "permissions-policy" => "Permissions-Policy"
    }

    results = {}

    checks.each do |header, name|
      if headers[header]
        results[name] = "present"
      else
        results[name] = "missing"
      end
    end

    results
  end

  def check_https_status(domain, timeout, retry_count, http_port, https_port)
    http_headers = {}
    https_headers = {}
    security_headers = {}
    
    http_url  = "http://#{domain}:#{http_port}"
    https_url = "https://#{domain}:#{https_port}"

    reached_https = false
    reached_http  = false
    https_supported = false
    http_redirects_to_https = false
    tls_version = nil
    cert_info = nil
    http_status = nil
    https_status = nil
    title = nil

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
        ) do |http|
          req = Net::HTTP::Get.new('/')
          req['User-Agent'] = datastore['USER_AGENT']
          http.request(req) do |res|
            res.read_body do |chunk|
              @body ||= ""
              @body << chunk
              break if @body.length > 10_000
            end
          end
        end

        reached_https = true
        https_supported = true
        https_status = res.code
        https_headers = res.to_hash
        title = extract_title(res.body)
        tls_version = get_tls_version(domain, https_port)
        security_headers = analyze_security_headers(https_headers)
        cert_info = get_certificate_info(domain, https_port)

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
        ) do |http|
          req = Net::HTTP::Get.new('/')
          req['User-Agent'] = datastore['USER_AGENT']
          http.request(req)
        end

        reached_http = true
        http_status = res.code
        http_headers = res.to_hash
        title ||= extract_title(res.body)

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

      print_good("Title: #{title}") if title

      print_good("TLS version: #{tls_version}") if tls_version
      if security_headers.any?
        print_status("Security Header Analysis:")

        security_headers.each do |name, status|
          if status == "present"
            print_good("#{name} present")
          else
            print_warning("#{name} missing")
          end
        end
      end

      if cert_info
        print_status("Certificate Info:")
        print_good("Subject: #{cert_info[:subject]}")
        print_good("Issuer: #{cert_info[:issuer]}")
        print_status("Valid From: #{cert_info[:valid_from]}")
        print_status("Valid To: #{cert_info[:valid_to]}")
        print_status("Days Remaining: #{cert_info[:days_remaining]}")

        if cert_info[:expired]
          print_error("Certificate EXPIRED")
        end

        if cert_info[:self_signed]
          print_warning("Self-signed certificate")
        end

        unless cert_info[:san].empty?
          print_status("SANs: #{cert_info[:san].join(', ')}")
        end
      end


    end

    {
      domain: domain,
      title: title,
      https: https_supported,
      http_redirect: http_redirects_to_https,
      tls: tls_version,
      http_status: http_status,
      https_status: https_status,
      security_headers: security_headers,
      certificate: cert_info
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


  def export_results
    @mutex.synchronize do
      return if @results.empty?
    end

    export_path = datastore['EXPORT_PATH']
    FileUtils.mkdir_p(export_path)

    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')

    if datastore['EXPORT_JSON']
      json_file = File.join(export_path, "scan_results_#{timestamp}.json")

      File.open(json_file, 'w') do |f|
        f.write(JSON.pretty_generate(@results))
      end

      print_good("JSON results saved to #{json_file}")
    end

    if datastore['EXPORT_CSV']
      csv_file = File.join(export_path, "scan_results_#{timestamp}.csv")

      CSV.open(csv_file, 'w') do |csv|
        csv << [
          "Domain",
          "Title",
          "HTTPS Supported",
          "HTTP Redirect to HTTPS",
          "TLS Version",
          "HTTP Status",
          "HTTPS Status",
          "HSTS",
          "CSP",
          "X-Frame-Options",
          "X-Content-Type-Options",
          "Referrer-Policy",
          "Permissions-Policy",
          "Cert Issuer",
          "Cert Expiry",
          "Days Remaining",
          "Self Signed"
        ]

        @results.each do |r|
          csv << [
            r[:domain],
            r[:title],
            r[:https],
            r[:http_redirect],
            r[:tls],
            r[:http_status],
            r[:https_status],
            r[:security_headers]["HSTS"],
            r[:security_headers]["CSP"],
            r[:security_headers]["X-Frame-Options"],
            r[:security_headers]["X-Content-Type-Options"],
            r[:security_headers]["Referrer-Policy"],
            r[:security_headers]["Permissions-Policy"],
            r[:certificate]&.dig(:issuer),
            r[:certificate]&.dig(:valid_to),
            r[:certificate]&.dig(:days_remaining),
            r[:certificate]&.dig(:self_signed)
          ]
        end
      end

      print_good("CSV results saved to #{csv_file}")
    end
  end
end