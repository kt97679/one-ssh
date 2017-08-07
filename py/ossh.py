#!/usr/bin/env python

import argparse
import os
from braceexpand import braceexpand
import asyncio
import asyncssh
import sys
import importlib.machinery
import types
import getpass
import re
import socket

OSSH_INVENTORY = None

try:
    loader = importlib.machinery.SourceFileLoader('ossh_inventory', os.environ['HOME'] + '/.ossh.py')
    mod = types.ModuleType(loader.name)
    loader.exec_module(mod)
    OSSH_INVENTORY = mod.OSSHInventory
except Exception as e:
    pass

DEFAULT_CONCURRENCY = 256
DEFAULT_SSH_CONNECTION_TIMEOUT = 60

USE_COLOR = sys.stdout.isatty()

COLOR_CODE = {
    'CYAN': '\033[96m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m',
    'RESET_COLOR': '\033[0m'
}

# each output line is prefixed with host name
# depending on output type host name would have different colors
HOST_COLOR = {
    'stdout': 'CYAN',
    'stderr': 'YELLOW',
    'error': 'RED'
}

# if we are not using color host name would have following suffixes depending on the output type
HOST_SUFFIX = {
    'stdout': "[1]",
    'stderr': "[2]",
    'error': "[!]"
}

options = {
    'timeout': 0,
    'connection_timeout': DEFAULT_SSH_CONNECTION_TIMEOUT,
    'username': os.environ.get('LOGNAME'),
    'concurrency': DEFAULT_CONCURRENCY,
    'ignore_failures': False,
    'resolve_ip': True,
    'preconnect': False,
    'host_file': [],
    'host_string': [],
    'inventory': [],
    'keys': None,
    'command': []
}

class OSSHClientSession(asyncssh.SSHClientSession):
    def __init__(self, host):
        self.host = host

    def data_received(self, data, datatype):
        self.host.process_data(data, 'stderr' if datatype == asyncssh.EXTENDED_DATA_STDERR else 'stdout')

    def connection_lost(self, exc):
        if exc:
            print('SSH session error: ' + str(exc), file=sys.stderr)

class OSSHClient(asyncssh.SSHClient):
    def __init__(self, host):
        self.host = host

    def connection_made(self, conn):
        print('Connection made to {} ({}).'.format(conn.get_extra_info('peername')[0], self.host.label))

    def auth_completed(self):
        print('Authentication successful.')

class OSSHHost():
    def __init__(self, addr, label):
        self.addr = addr
        self.label = label
        self.buf = {
            'stdout': '',
            'stderr': ''
        }

    def process_data(self, data, datatype):
        self.buf[datatype] += data
        out = self.buf[datatype].split('\n')
        self.buf[datatype] = out.pop()
        color_code = COLOR_CODE[HOST_COLOR[datatype]]
        for line in out:
            print("{}{}{} {}".format(color_code, self.label, COLOR_CODE['RESET_COLOR'], line))

class OSSH():
    def get_label(self, addr):
        if self.is_ip(addr):
            if self.args.noresolve:
                return addr
            try:
                addr = socket.gethostbyaddr(addr)[0]
            except socket.herror:
                return addr
        return addr.split('.')[0]

    def is_ip(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False

    def get_hosts(self, host_list):
        out = []
        for host_line in host_list:
            for host_string in re.split("\s+", host_line.strip()):
                for host_addr in braceexpand(host_string):
                    host_label = self.get_label(host_addr)
                    out.append(OSSHHost(host_addr, host_label))
        return out

    def run(self, args):
        print(args)
        self.args = args
        self.hosts = []
        if args.hosts_file:
            for h in args.hosts_file:
                with open(h) as hf:
                    self.hosts += self.get_hosts(hf.readlines())
        if args.hosts_string:
            self.hosts += self.get_hosts(args.hosts_string)
        if OSSH_INVENTORY and args.inventory:
            self.hosts += [OSSHHost(h['address'], h['label']) for h in OSSH_INVENTORY().get_inventory(args.inventory)]
        max_label_len = len(max([x.label for x in self.hosts], key=len))
        for h in self.hosts:
            h.label = h.label.ljust(max_label_len)
        self.command = ""
        if args.command_file:
            for command_file in args.command_file:
                with open(command_file) as cf:
                    self.command += (cf.read() + "\n")
        if args.command:
            self.command += "\n".join(args.command)
        self.dispatcher = self._dispatcher()
        self.par = args.par
        
        self.loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.start_dispatcher())
        try:
            self.loop.run_forever()
        finally:
            self.loop.close() 

    async def run_client(self, host):
        client_keys = ()
        if self.args.key:
            client_keys = self.args.key
#        if self.args.password:
#            client_keys = None
        try:
            conn, client = await asyncssh.create_connection(lambda: OSSHClient(host), host.addr, password=self.args.password, username=self.args.user, client_keys=client_keys)
            async with conn:
                chan, session = await conn.create_session(lambda: OSSHClientSession(host), self.command)
                await chan.wait_closed()
        except Exception as e:
            print(e)
        try:
            next(self.dispatcher)
        except StopIteration:
            pass
    
    async def start_dispatcher(self):
        next(self.dispatcher)
    
    def _dispatcher(self):
        running = 0
        for h in self.hosts:
            asyncio.ensure_future(self.run_client(h))
            running += 1
            if running < self.par:
                continue
            yield
            running -= 1
        for h in range(0, running):
            yield
        self.loop.stop()

class OSSHCli(OSSH):
    def parse_cli_args(self):
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-p', '--par', type=int, default=DEFAULT_CONCURRENCY, help="How many hosts to run simultaneously (default: %(default)d)")
        parser.add_argument('-C', '--command-file', type=str, help="File with commands to run", action="append")
        parser.add_argument('-c', '--command', type=str, help="Command to run", action="append")
        parser.add_argument('-A', '--askpass', help="Prompt for a password for ssh connects (default: use key based authentication)", action="store_true")
        parser.add_argument('-l', '--user', type=str, default=os.environ.get('LOGNAME'), help="Username for connections (default: $LOGNAME)")
        parser.add_argument('-t', '--timeout', type=int, default=0, help="Timeout for operation, 0 for no timeout (default: %(default)d)")
        parser.add_argument('-H', '--hosts-string', type=str, action="append", help="Add the given HOSTS_STRING to the list of hosts. "
                        "HOSTS_STRING can contain multiple hosts separated by space, brace expansion can be used. "
                        "E.g. \"host{1,3..5}.com\" would expand to \"host1.com host3.com host4.com host5.com\" "
                        "This option can be used multiple times.")
        parser.add_argument('-h', '--hosts-file', type=str, action="append", help="Read hosts from the given HOSTS_FILE. "
                        "Each line in the HOSTS_FILE should be like HOSTS_STRING above. "
                        "This option can be used multiple times.")
        parser.add_argument("-n", "--noresolve", help="Don't resolve ip addresses to names", action="store_true")
        parser.add_argument("-P", "--preconnect", help="Connect to all hosts before running command", action="store_true")
        parser.add_argument('-i', '--ignore-failures', help="Ignore connection failures in the preconnect mode", action="store_false")
        parser.add_argument('-k', '--key', type=str, action="append", help="Use this private key. This option can be used multiple times")
        if OSSH_INVENTORY and OSSH_INVENTORY.get_inventory:
            parser.add_argument("-I", "--inventory", type=str, action="append", help="Use INVENTORY expression to select hosts. "
                            "This option can be used multiple times.")
        parser.add_argument("-?", "--help", help="Show help", action="help")
        args = parser.parse_args()
        return args

    def run(self):
        args = self.parse_cli_args()
        args.password = None
        if args.askpass:
            args.password = getpass.getpass('Password: ')

        super(OSSHCli, self).run(args)

if __name__ == '__main__':
    OSSHCli().run()
