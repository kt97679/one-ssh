#!/usr/bin/env ruby
require 'optparse'
require "uri"
require 'em-ssh'
require 'highline/import'
require 'resolv'
require 'bracecomp'

SSH_TIMEOUT = 60
DEFAULT_CONCURRENCY = 256

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

class MultiSSH
    def initialize(hosts, options)
        @options = options
        @host_index = 0
        @hosts_done = 0
        @hosts_failed = 0
        @pool = []
        @auth_methods = ["publickey"]
        max_host_length = hosts.map {|h| h[:label].length}.max
        if options[:password]
            @auth_methods << "password"
        end
        hosts.sort {|x, y| x[:address] <=> y[:address]}.each do |host|
            host[:label] += (" " * (max_host_length - host[:label].length))
            @pool << host
        end
        if options[:preconnect]
            preconnect()
        else
            exec()
        end
    end

    def start_ssh(host)
        EM::Ssh.start(host[:address], @options[:username],
                :password => @options[:password],
                :timeout => SSH_TIMEOUT,
                :global_known_hosts_file => "/dev/null",
                :user_known_hosts_file => "/dev/null",
                :paranoid => false,
                :use_agent => false,
                :auth_methods => @auth_methods) do |connection|
            connection.log.level = Logger::FATAL # make default logger silent
            yield(connection)
        end
    end

    def preconnect()
        @pool.each do |host|
            start_ssh(host) do |connection|
                connection.errback do |err|
                    host[:error] = "#{err} (#{err.class})"
                    host_processed(host)
                end
                connection.callback do |ssh|
                    host[:ssh] = ssh
                    host_processed(host)
                end
            end
        end
    end 

    def host_prefix(host, out_type)
        if USE_COLOR
            return HIGHLINE.color(host, HOST_COLOR[out_type])
        else
            return "#{host} #{HOST_SUFFIX[out_type]}"
        end
    end

    def host_processed(host)
        @hosts_done += 1
        if host[:error] != nil
            print "#{host_prefix(host[:label], :error)} #{host[:error]}\n"
            @hosts_failed += 1
        end
        if @hosts_done == @pool.size()
            if @hosts_failed > 0 && ! @options[:ignore_failures]
                abort("Failed to connect to #{@hosts_failed} hosts, exiting")
            end
            @pool.select! {|x| x[:ssh] }
            exec()
        end
    end

    def exec()
        @hosts_done = 0
        [@pool.size(), @options[:concurrency]].min.times do
            exec_next()
        end
    end

    def process_output(host, out_type, data)
        # stdout is usually flushed by complete lines, but not stderr, which is flushed immediately
        # to have reasonable output we need to buffer output and print it when we are sure we 
        # have complete line (terminating newline is present)
        host[out_type] += data
        if host[out_type].include?("\n")
            out = host[out_type].split("\n")
            if host[out_type].end_with?("\n")
                host[out_type] = ""
            else
                host[out_type] = out.pop
            end
            print out.map {|x| "#{host_prefix(host[:label], out_type)} #{x}" }.join("\n") + "\n"
        end
    end

    def exec_next()
        if @hosts_done == @pool.size()
            EM.stop()
            exit
        end
        host = @pool[@host_index]
        return if host.nil?
        @host_index += 1
        if host[:ssh]
            exec_single(host)
        else
            start_ssh(host) do |connection|
                connection.errback do |err|
                    @hosts_done += 1
                    print "#{host_prefix(host[:label], :error)} #{err} (#{err.class})\n"
                    exec_next()
                end
                connection.callback do |ssh|
                    host[:ssh] = ssh
                    exec_single(host)
                end
            end
        end
    end

    def finalize_connection(ch, host)
        # without explicit connection close socket would stay opened and we may run out of file descriptors
        # Fiber is needed to avoid "can't yield from root fiber" error
        Fiber.new {
            begin
                ch.connection.close()
            rescue
            end
        }.resume
        @hosts_done += 1
        # let's check if we have any buffered output that wasn't printed yet
        [:stdout, :stderr].each do |out_type|
            next if host[out_type].empty?
            data = "\n"
            if host[out_type].end_with?("\n")
                data = ""
            end
            process_output(host, out_type, data)
        end
        print "#{host_prefix(host[:label], :error)} #{host[:error]}\n" if host[:error]
        exec_next()
    end

    def exec_single(host)
        host[:exit_code] = nil
        host[:stdout] = ""
        host[:stderr] = ""
        channel = host[:ssh].open_channel do |oc|
            # with request_pty stdout and stderr are combined
            # since pty is needed only for interactive programs let's try without it
            #oc.request_pty
            oc.exec(@options[:command]) do |ch, success|
                if success
                    if @options[:timeout] > 0
                        host[:timer] = EM::Timer.new(@options[:timeout]) do
                            host[:error] = "terminated on timeout"
                            finalize_connection(ch, host)
                        end
                    end
                    channel.on_data do |ch, data|
                        process_output(host, :stdout, data)
                    end
                    channel.on_extended_data do |ch, type, data|
                        process_output(host, :stderr, data)
                    end
                    channel.on_request("exit-status") do |ch, data|
                        # IMPORTANT!!! On some platforms exit-status is received BEFORE final output data
                        host[:exit_code] = data.read_long
                    end
                    channel.on_close do |ch|
                        host[:timer].cancel if host[:timer]
                        finalize_connection(ch, host)
                    end
                else
                    print "#{host_prefix(host[:label], :error)} exec() failed\n"
                    @hosts_done += 1
                    exec_next()
                end
            end
        end
    end 
end

class OSSH
    def initialize()
        trap("TERM") do
            EM.stop()
            exit 1
        end

        trap("INT") do
            EM.stop()
            exit 2
        end

        @options = {
            :timeout => 0,
            :username => ENV['USER'],
            :concurrency => DEFAULT_CONCURRENCY,
            :ignore_failures => false,
            :resolve_ip => true,
            :preconnect => false
        }
    end

    def validate_options()
        errors = []
        errors << "Concurrency can't be < 1" if @options[:concurrency] < 1
        errors << "No command specified" if @options[:command].to_s.empty?
        host_params = [:host_file, :host_string]
        host_params_error_msg = "No host file or host string specified"
        if defined?(get_inventory)
            host_params << :inventory
            host_params_error_msg = "No host file, host string or inventory filter specified"
        end
        errors << host_params_error_msg if host_params.all? {|x| @options[x].to_s.empty?}
        errors << "No username specified" if @options[:username].to_s.empty?
        if errors.size > 0
            errors << "Please use -? for help"
            abort(errors.join("\n"))
        end
    end

    def is_ipv4?(a)
        return false if a.size() != 4
        a.all? {|x| x =~ /^\d+$/ && x.to_i.between?(0, 255)}
    end

    def get_label(s)
        a = s.split(".")
        return a[0] if ! is_ipv4?(a)
        return s if ! @options[:resolve_ip]
        name = RESOLVER.getnames(s).map{|x| x.to_s}.sort.first
        return name.split(".").first if name
        return s
    end

    def get_hosts(h)
        # h is an array of strings
        # each string is a white space delimited list of hosts
        # host can use brace expansion, e.g. host{1,3..5}.com would expand to:
        # host1.com host3.com host4.com host5.com
        h.map {|s| s.split(/\s+/)}.flatten.map {|s| s.expand}.flatten.map {|s| {:address => s}}
    end

    def run(options = nil)
        @options.merge!(options) if options
        validate_options()

        # hosts array should contain hashes in the form
        # {:label => "some-name", address: => "some-ip"}
        hosts = []
        hosts += get_hosts(@options[:host_string]) if @options[:host_string]
        hosts += get_hosts(@options[:host_file].map {|f| IO.read(f)}) if @options[:host_file]
        hosts += get_inventory(@options[:inventory]) if @options[:inventory]

        abort("Hosts list is empty!") if hosts.size == 0

        hosts.each do |h|
            label = h[:label]
            next if label && label.length > 0
            h[:label] = get_label(h[:address])
        end

        EM.epoll
        EM.run do
            MultiSSH.new(hosts, @options)
        end
    end
end

class OSSHCli < OSSH
    def get_cli_options()
        @optparse = OptionParser.new do |opts|
            opts.banner = "Usage: #{File.basename($0)} [options]"
            opts.on('-p', '--par PARALLELISM', "How many hosts to run simultaneously (default #{@options[:concurrency]})") do |concurrency|
                @options[:concurrency] = concurrency.to_i
            end
            opts.on('-c', '--command COMMAND', "Command to run") do |command|
                @options[:command] = command
            end
            opts.on('-A', '--askpass', "Prompt for a password for ssh connects (by default using key based authentication)") do
                @options[:password] = HIGHLINE.ask("password: ") {|q| q.echo = '*'}
            end
            opts.on('-l', '--user USER', "Username for connections (default $LOGNAME)") do |username|
                @options[:username] = username
            end
            opts.on('-t', '--timeout TIMEOUT', "Timeout for operation, 0 for no timeout (default #{@options[:timeout]})") do |timeout|
                @options[:timeout] = timeout.to_f
            end
            opts.on('-H', '--host HOST_STRING', "Add the given HOST_STRING to the list of hosts (this option can be used multiple times).",
                    "HOST_STRING can contain multiple hosts separated by space, brace expansion can be used.",
                    "E.g. \"host{1,3..5}.com\" would expand to \"host1.com host3.com host4.com host5.com\"") do |host_string|
                if @options[:host_string]
                    @options[:host_string].push(host_string)
                else
                    @options[:host_string] = [host_string]
                end
            end
            opts.on('-h', '--hosts HOST_FILE', "Read hosts from the given HOST_FILE (this option can be used multiple times).", 
                    "Each line in the HOST_FILE can contain multiple hosts separated by space, brace expansion can be used.") do |host_file|
                if @options[:host_file]
                    @options[:host_file].push(host_file)
                else
                    @options[:host_file] = [host_file]
                end
            end
            opts.on("-n", "--noresolve", "Don't resolve ip addresses to names") do
                @options[:resolve_ip] = false
            end
            opts.on("-P", "--preconnect", "Connect to all hosts before running command") do
                @options[:preconnect] = true
            end
            opts.on('-i', '--ignore-failures', "Ignore connection failures in the preconnect mode (default #{@options[:ignore_failures]})") do
                @options[:ignore_failures] = true
            end
            if defined?(get_inventory)
                opts.on("-I", "--inventory FILTER", "Use FILTER expression to select hosts from inventory") do |inventory|
                    @options[:inventory] = inventory
                end
            end
            opts.on('-?', '--help', 'Show help') do
                abort(opts.to_s)
            end
        end

        begin
            @optparse.parse!
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            puts $!.to_s
            abort(@optparse.to_s)
        end
    end

    def run()
        get_cli_options()
        super()
    end
end
