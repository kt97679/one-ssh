# About

This is readme for ossh (One SSH to rule them all) gem.

This gem can be used to run commands via ssh on multiple hosts. It was inspired by the knife utility from
chef configuration management system.  Ossh tool was created by me at Hulu. It was used to run commands
on thousands of machines in parallel.


```
Usage: ossh [options]
    -p, --par PARALLELISM            How many hosts to run simultaneously (default: 256)
    -c, --command COMMAND            Command to run
    -A, --askpass                    Prompt for a password for ssh connects (default: use key based authentication)
    -l, --user USER                  Username for connections (default $LOGNAME)
    -t, --timeout TIMEOUT            Timeout for operation, 0 for no timeout (default: 0)
    -H, --host HOST_STRING           Add the given HOST_STRING to the list of hosts.
                                     HOST_STRING can contain multiple hosts separated by space, brace expansion can be used.
                                     E.g. "host{1,3..5}.com" would expand to "host1.com host3.com host4.com host5.com"
                                     This option can be used multiple times.
    -h, --hosts HOST_FILE            Read hosts from the given HOST_FILE.
                                     Each line in the HOST_FILE should be like HOST_STRING above.
                                     This option can be used multiple times.
    -n, --noresolve                  Don't resolve ip addresses to names
    -P, --preconnect                 Connect to all hosts before running command
    -i, --ignore-failures            Ignore connection failures in the preconnect mode (default: false)
    -?, --help                       Show help
```

# Examples:

## Run command

```
$ ossh -H "db01 db02 web05 web06" -l root -c 'uptime'
db01  15:59:30 up 305 days, 21:04,  1 user,  load average: 0.00, 0.00, 0.00
db02  15:59:30 up 263 days,  4:05,  1 user,  load average: 0.00, 0.00, 0.00
web05 15:59:30 up 107 days, 16:02,  1 user,  load average: 0.08, 0.03, 0.05
web06 15:59:30 up 371 days, 23:25,  1 user,  load average: 0.00, 0.00, 0.00
```

## Stream/monitor logs in the real time

```
$ ossh -H "web05 web06" -c "tail -f -c 0 /var/log/nginx/access.log|grep --line-buffered Wget"
web05 192.168.1.23 - - [22/Jun/2016:12:24:02 -0700] "GET / HTTP/1.1" 200 1532 "-" "Wget/1.15 (linux-gnu)"
web05 192.168.1.49 - - [22/Jun/2016:12:24:07 -0700] "GET / HTTP/1.1" 200 1532 "-" "Wget/1.15 (linux-gnu)"
web06 192.168.1.117 - - [22/Jun/2016:12:24:23 -0700] "GET / HTTP/1.1" 200 1532 "-" "Wget/1.15 (linux-gnu)"
web05 192.168.1.29 - - [22/Jun/2016:12:24:30 -0700] "GET / HTTP/1.1" 200 1532 "-" "Wget/1.15 (linux-gnu)"
```

## Rolling deployment (simulation)

```
$ ossh -p 1 -H "test0{1..3}" -c "sleep 10 && date"
test01 Wed Jun 22 12:38:24 PDT 2016
test02 Wed Jun 22 12:38:34 PDT 2016
test03 Wed Jun 22 12:38:44 PDT 2016
```

# How to use OSSH in your script

```
require 'ossh'
options = {
    :host_string => "db01 db02 web05 web06",
    :command => "hostname -I",
    :ignore_failures => true
}
OSSH.new().run(options)
```

# Customization

On the start ossh tries to load $HOME/.ossh.rb file if it exists. You can use this file to customize
ossh. For example you can put into $HOME/.ossh.rb custom inventory logic as explained below.

# Support for the custom inventory systems

If you have inventory system of your own you can easily use it with ossh. To do this you need to add
get_inventory(inventory_list) method to the OSSH class.  get_inventory(inventory_list) method will be
called with inventory_list being list of parameters supplied via -I or --inventory options to select
machines you need.  You can find sample .ossh.rb in the examples directory. It uses /etc/hosts file to
select machines whoes names match regex provided via -I or --inventory options.

# How to build gem:

```
$ gem build ossh.gemspec
```

# Known issues.

If you run ossh using latest ruby and latest em-ssh and net-ssh gems you may need to add following code
snippet to your ~/.ossh.rb:

```
module EventMachine
  class Ssh
    class Connection < EventMachine::Connection
      def host_keys
        return []
      end
    end
  end
end

```
