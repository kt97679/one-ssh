# About

This is readme for ossh (One SSH to rule them all) tool.

This tool can be used to run commands via ssh on multiple hosts. It was inspired by the knife utility from
chef configuration management system. Ossh tool was created by me at Hulu. It was used to run commands
on thousands of machines in parallel.

```
$ ossh -?
Usage: ossh [-?AinPv] [-c COMMAND] [-H HOST_STRING] [-h HOST_FILE] [-I FILTER] [-k PRIVATE_KEY] [-l USER] [-o PORT] [-p PARALLELISM] [-T TIMEOUT] [-t TIMEOUT] [parameters ...]
 -?, --help        Show help
 -A, --askpass     Prompt for a password for ssh connects
 -c, --command=COMMAND
                   Command to run
 -H, --host=HOST_STRING
                   Add the given HOST_STRING to the list of hosts
 -h, --hosts=HOST_FILE
                   Read hosts from file
 -i, --ignore-failures
                   Ignore connection failures in the preconnect mode
 -I, --inventory=FILTER
                   Use FILTER expression to select hosts from inventory
 -k, --key=PRIVATE_KEY
                   Use this private key
 -l, --user=USER   Username for connections [$LOGNAME]
 -n, --showip      In the output show ips instead of names
 -o, --port=PORT   Port to connect to [22]
 -p, --par=PARALLELISM
                   How many hosts to run simultaneously [512]
 -P, --preconnect  Connect to all hosts before running command
 -T, --connect-timeout=TIMEOUT
                   Connect timeout in seconds [60]
 -t, --timeout=TIMEOUT
                   Run timeout in seconds
 -v, --verbose     Verbose output
$ 
```

HOST\_STRING can specify non standard port e.g. ```host.com:2222```.
HOST\_FILE can use #-style comments.
Brace expansion can be used. E.g. "host{1,3..5}.com" would expand to "host1.com host3.com host4.com host5.com"

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

# Support for the custom inventory systems

If you have inventory system of your own you can easily use it with ossh. To do this you need to have in
the PATH program named ```ossh-inventory``` that being given host specification (argument of -I option)
will return list of strings in the form

```
host-label host-address
```

where host-label can be any string (without whitespaces), host-address can be ip address or dns name.

# How to build binary:

```
$ cd <this repository> && go build -o ossh && strip ossh
```
