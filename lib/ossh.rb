#!/usr/bin/env ruby
require 'optparse'
require 'em-ssh'
require 'highline/import'
require 'resolv'
require 'bracecomp'

DEFAULT_SSH_CONNECTION_TIMEOUT = 60
DEFAULT_CONCURRENCY = 256
DEFAULT_SSH_PORT = 22

USE_COLOR = STDOUT.tty?
HIGHLINE = HighLine.new($stdin, $stderr)
RESOLVER = Resolv::DNS.new

# each output line is prefixed with host name
# depending on output type host name would have different colors
HOST_COLOR = {
    :stdout => :cyan,
    :stderr => :yellow,
    :error => :red
}

# if we are not using color host name would have following suffixes depending on the output type
HOST_SUFFIX = {
    :stdout => "[1]",
    :stderr => "[2]",
    :error => "[!]"
}

OSSHException = Class.new(Exception)

class OSSHHost
    def initialize(address, port, label, dispatcher, options)
        @address = address
        @port = port || options[:port]
        @label = label
        @dispatcher = dispatcher
        @ssh = nil
        @exit_code = nil
        @timer = nil
        @username = options[:username]
        @password = options[:password]
        @keys = options[:keys]
        @auth_methods = options[:auth_methods]
        @command = options[:command].join("\n")
        @timeout = options[:timeout]
        @connection_timeout = options[:connection_timeout]
        @connection_failed = false
        @buffer = {
            :stdout => "",
            :stderr => ""
        }
    end

    def start_ssh()
        begin
            EM::Ssh.start(@address, @username,
                    :port => @port,
                    :password => @password,
                    :keys => @keys,
                    :timeout => @connection_timeout,
                    :global_known_hosts_file => "/dev/null",
                    :user_known_hosts_file => "/dev/null",
                    :paranoid => false,
                    :use_agent => true,
                    :auth_methods => @auth_methods) do |connection|
                # make default logger silent
                connection.log.level = Logger::FATAL
                # ssh server can be in a really broken state when em-ssh thinks that
                # connection is established but in reality neither callback nor
                # errback are invoked.  em-ssh should do better job regarding this,
                # but while it is not here is workaround. To ensure that we are not
                # interfering with em-ssh timers we use doubled timeout value.
                # IMPORTANT!!! Connection that will fail like this will remain opened
                # until ossh will exit. If you will have a lot of failures like this
                # you can run out of file descriptors.
                @timer = EM::Timer.new(@connection_timeout * 2) do
                    # @connection_failed is set to true because there is chance that callback will be called
                    # but since we already gave up on this sonnections callback should do nothing
                    @connection_failed = true
                    print "#{prefix(:error)} timeout while establishing connection\n"
                    @dispatcher.resume
                end
                yield(connection)
            end
        rescue Exception => e
            EventMachine.defer(
                proc { print "#{prefix(:error)} #{e} (#{e.class})\n" },
                proc { @dispatcher.resume }
            )
        end
    end

    def prefix(out_type)
        if USE_COLOR
            return HIGHLINE.color(@label, HOST_COLOR[out_type])
        else
            return "#{@label} #{HOST_SUFFIX[out_type]}"
        end
    end

    def process_output(out_type, data)
        # stdout is usually flushed by complete lines, but not stderr, which is flushed immediately
        # to have reasonable output we need to buffer output and print it when we are sure we 
        # have complete line (terminating newline is present)
        @buffer[out_type] += data
        if @buffer[out_type].include?("\n")
            # -1 is needed to have last empty line if buffer ends with \n
            out = @buffer[out_type].split("\n", -1)
            @buffer[out_type] = out.pop
            out.map { |x| puts "#{prefix(out_type)} #{x}" }
        end
    end

    def finalize_connection(error = nil)
        # let's check if we have any buffered output that wasn't printed yet
        [:stdout, :stderr].each do |out_type|
            next if @buffer[out_type].empty?
            data = "\n"
            if @buffer[out_type].end_with?("\n")
                data = ""
            end
            process_output(out_type, data)
        end
        # error may be set in case of timeout
        print "#{prefix(:error)} #{error}\n" if error
        # there may be very rare situation when finalize_connection()
        # will be called both from timer and because command is done
        # to protect against this we set @ssh to nil
        return if @ssh.nil?
        @timer.cancel if @timer
        # without explicit connection close socket would stay opened and we may run out of file descriptors
        # Fiber is needed to avoid "can't yield from root fiber" error
        Fiber.new {
            begin
                @ssh.close()
            rescue
            end
        }.resume
        @ssh = nil
        @dispatcher.resume
    end

    def do_run()
        # timeout timer should be defined here because @ssh.open_channel can freeze
        @timer = nil
        if @timeout > 0
            @timer = EM::Timer.new(@timeout) do
                finalize_connection("connection terminated on timeout")
            end
        end
        channel = @ssh.open_channel do |oc|
            # with request_pty stdout and stderr are combined
            # since pty is needed only for interactive programs let's try without it
            #oc.request_pty
            oc.exec(@command) do |ch, success|
                if success
                    channel.on_data do |ch, data|
                        process_output(:stdout, data)
                    end
                    channel.on_extended_data do |ch, type, data|
                        process_output(:stderr, data)
                    end
                    channel.on_request("exit-status") do |ch, data|
                        # IMPORTANT!!! On some platforms exit-status is received BEFORE final output data
                        @exit_code = data.read_long
                    end
                    channel.on_close do |ch|
                        finalize_connection()
                    end
                else
                    finalize_connection("exec() failed")
                end
            end
        end
    end

    def preconnect()
        start_ssh() do |connection|
            connection.errback  { |err| preconnect_cb(nil, err) }
            connection.callback { |ssh| preconnect_cb(ssh, nil) }
        end
    end

    def preconnect_cb(ssh, err)
        # if connection was marked as failed by the timer let's do nothing
        return if @connection_failed
        @timer.cancel
        print "#{prefix(:error)} #{err} (#{err.class})\n" if err
        @ssh = ssh
        @dispatcher.resume
    end

    def connected?
        @ssh != nil
    end

    def run()
        if @ssh
            do_run()
        else
            start_ssh() do |connection|
                connection.errback  { |err| connection_cb(nil, err) }
                connection.callback { |ssh| connection_cb(ssh, nil) }
            end
        end
    end

    def connection_cb(ssh, err)
        # if connection was marked as failed by the timer let's do nothing
        return if @connection_failed
        @timer.cancel
        if ssh
            @ssh = ssh
            do_run()
        else
            print "#{prefix(:error)} #{err} (#{err.class})\n"
            @dispatcher.resume
        end
    end
end

class OSSHDispatcher
    def initialize(hosts, options)
        all_hosts = nil
        @dispatcher = Fiber.new do
            if options[:preconnect]
                hosts_num = all_hosts.size
                all_hosts.each { |h| h.preconnect() }
                hosts_num.times { Fiber.yield }
                all_hosts.select! { |x| x.connected? }
                preconnect_failed = hosts_num - all_hosts.size
                if preconnect_failed > 0 && ! options[:ignore_failures]
                    EM.stop()
                    raise OSSHException.new("Failed to connect to #{preconnect_failed} hosts, exiting")
                end
            end
            running = 0
            all_hosts.each do |h|
                h.run()
                running += 1
                next if running < options[:concurrency]
                Fiber.yield
                running -= 1
            end
            running.times { Fiber.yield }
            EM.stop()
        end
        options[:auth_methods] = ["publickey"]
        options[:auth_methods] << "password" if options[:password]
        max_host_length = hosts.map { |h| h[:label].length }.max
        all_hosts = hosts.sort { |x, y| x[:address] <=> y[:address] }.map do |h|
            OSSHHost.new(h[:address], h[:port], h[:label].ljust(max_host_length), @dispatcher, options)
        end
    end

    def run()
        @dispatcher.resume
    end
end

class OSSH
    def initialize()
        @options = {
            :timeout => 0,
            :connection_timeout => DEFAULT_SSH_CONNECTION_TIMEOUT,
            :username => ENV['USER'],
            :concurrency => DEFAULT_CONCURRENCY,
            :ignore_failures => false,
            :resolve_ip => true,
            :preconnect => false,
            :host_file => [],
            :host_string => [],
            :keys => nil,
            :command => [],
            :port => DEFAULT_SSH_PORT
        }
        begin
            OSSHInventory.new().get_inventory([])
            @options[:inventory] = []
        rescue
        end
    end

    def validate_options()
        errors = []
        errors << "Concurrency can't be < 1" if @options[:concurrency] < 1
        errors << "Port should be in the [1, 65535] range" if @options[:port] < 1 || @options[:port] > 65535
        errors << "No command specified" if @options[:command].join().to_s.empty?
        host_params = [:host_file, :host_string]
        host_params_error_msg = "No host file or host string specified"
        if @options[:inventory]
            host_params << :inventory
            host_params_error_msg = "No host file, host string or inventory filter specified"
        end
        errors << host_params_error_msg if host_params.all? { |x| @options[x].join().empty? }
        errors << "No username specified" if @options[:username].to_s.empty?
        raise OSSHException.new(errors.join("\n")) if errors.size > 0
    end

    def is_ipv4?(a)
        return false if a.size() != 4
        a.all? { |x| x =~ /^\d+$/ && x.to_i.between?(0, 255) }
    end

    def get_label(s)
        a = s.split(".")
        return a[0] if ! is_ipv4?(a)
        return s if ! @options[:resolve_ip]
        name = RESOLVER.getnames(s).map{ |x| x.to_s }.sort.first
        return name.split(".").first if name
        return s
    end

    def get_hosts(h)
        # h is an array of strings
        # each string is a white space delimited list of hosts
        # host can use brace expansion, e.g. host{1,3..5}.com:2222 would expand to:
        # host1.com:2222 host3.com:2222 host4.com:2222 host5.com:2222
        # 2222 is port for connection
        h.map { |s| s.split(/\s+/) }.flatten.map { |s| s.expand }.flatten
            .map { |s| address, port = s.split(":"); {:address => address, :port => port} }
    end

    def run(options = nil)
        @options.merge!(options) if options
        validate_options()

        # hosts array should contain hashes in the form
        # {:label => "some-name", address: => "some-ip"}
        hosts = get_hosts(@options[:host_string]) +
            get_hosts(@options[:host_file].map { |f| File.readlines(f) }.flatten().map {|s| s.sub(/#.*/, '')})
        hosts += OSSHInventory.new().get_inventory(@options[:inventory]) if @options[:inventory]

        raise OSSHException.new("Hosts list is empty!") if hosts.size == 0

        hosts.each do |h|
            h[:label] = get_label(h[:address]) if h[:label].to_s.empty?
        end

        EM.epoll
        EM.run do
            OSSHDispatcher.new(hosts, @options).run()
        end
    end
end

class OSSHCli < OSSH
    def initialize
        super()
        trap("TERM") do
            EM.stop()
            exit 1
        end

        trap("INT") do
            EM.stop()
            exit 2
        end
    end

    def get_cli_options()
        optparse = OptionParser.new do |opts|
            opts.banner = "Usage: #{File.basename($0)} [options]"
            opts.on('-p', '--par PARALLELISM', "How many hosts to run simultaneously (default: #{@options[:concurrency]})") do |concurrency|
                @options[:concurrency] = concurrency.to_i
            end
            opts.on('-C', '--command-file COMMAND_FILE', "File with commands to run") do |command_file|
                @options[:command].push(IO.read(command_file))
            end
            opts.on('-c', '--command COMMAND', "Command to run") do |command|
                @options[:command].push(command)
            end
            opts.on('-A', '--askpass', "Prompt for a password for ssh connects (default: use key based authentication)") do
                @options[:password] = HIGHLINE.ask("password: ") {|q| q.echo = '*'}
            end
            opts.on('-l', '--user USER', "Username for connections (default: $LOGNAME)") do |username|
                @options[:username] = username
            end
            opts.on('-t', '--timeout TIMEOUT', "Timeout for operation, 0 for no timeout (default: #{@options[:timeout]})") do |timeout|
                @options[:timeout] = timeout.to_f
            end
            opts.on('-H', '--host HOST_STRING', "Add the given HOST_STRING to the list of hosts.",
                    "HOST_STRING can contain multiple hosts separated by space, brace expansion can be used.",
                    "E.g. \"host{1,3..5}.com\" would expand to \"host1.com host3.com host4.com host5.com\"",
                    "This option can be used multiple times.") do |host_string|
                @options[:host_string].push(host_string)
            end
            opts.on('-h', '--hosts HOST_FILE', "Read hosts from the given HOST_FILE.", 
                    "Each line in the HOST_FILE should be like HOST_STRING above.",
                    "This option can be used multiple times.") do |host_file|
                @options[:host_file].push(host_file)
            end
            opts.on('-o', '--port PORT', "Port to connect to (default: #{@options[:port]})") do |port|
                @options[:port] = port.to_i
            end
            opts.on("-n", "--noresolve", "Don't resolve ip addresses to names") do
                @options[:resolve_ip] = false
            end
            opts.on("-P", "--preconnect", "Connect to all hosts before running command") do
                @options[:preconnect] = true
            end
            opts.on('-i', '--ignore-failures', "Ignore connection failures in the preconnect mode (default: #{@options[:ignore_failures]})") do
                @options[:ignore_failures] = true
            end
            opts.on('-k', '--key PRIVATE_KEY', "Use this private key.", "This option can be used multiple times") do |key|
                (@options[:keys] ||= []) << key
            end
            if @options[:inventory]
                opts.on("-I", "--inventory FILTER", "Use FILTER expression to select hosts from inventory.",
                        "This option can be used multiple times.") do |inventory|
                    @options[:inventory].push(inventory)
                end
            end
            opts.on('-?', '--help', 'Show help') do
                abort(opts.to_s)
            end
        end

        begin
            optparse.parse!
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            puts $!.to_s
            abort(optparse.to_s)
        end
    end

    def run()
        begin
            get_cli_options()
            super()
        rescue OSSHException => e
            abort(e.message + "\nPlease use -? for help")
        end
    end
end
