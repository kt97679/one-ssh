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
    'CYAN': '\033[36m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'GREEN': '\033[32m',
    'RESET_COLOR': '\033[0m'
}

# each output line is prefixed with host name
# depending on output type host name would have different colors
HOST_COLOR = {
    'stdout': 'CYAN',
    'stderr': 'YELLOW',
    'error': 'RED',
    'verbose': 'GREEN'
}

# if we are not using color host name would have following suffixes depending on the output type
HOST_SUFFIX = {
    'stdout': "[1]",
    'stderr': "[2]",
    'error': "[!]",
    'verbose': "[v]"
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

class OSSHException(Exception):
    pass

class OSSHClientSession(asyncssh.SSHClientSession):
    def __init__(self, host):
        self.host = host

    def data_received(self, data, datatype):
        self.host.process_data(data, 'stderr' if datatype == asyncssh.EXTENDED_DATA_STDERR else 'stdout')

    def connection_lost(self, exc):
        self.host.flush()
        if exc:
            host.print('error', 'Error: ' + str(exc))

class OSSHClient(asyncssh.SSHClient):
    def __init__(self, host):
        self.host = host

    def connection_made(self, conn):
        if self.host.args.verbose:
            self.host.print('verbose', 'connection made to {}'.format(conn.get_extra_info('peername')[0]))

    def auth_completed(self):
        if self.host.args.verbose:
            self.host.print('verbose', 'authentication successful')

class OSSHHost():
    def __init__(self, addr, label):
        self.addr = addr
        self.label = label
        self.conn = None
        self.client = None
        self.buf = {
            'stdout': '',
            'stderr': ''
        }

    def flush(self):
        for datatype, data in self.buf.items():
            if not data:
                continue
            out = "\n"
            if data.endswith(out):
                out = ""
            self.process_data(out, datatype)

    def print(self, datatype, data):
        if USE_COLOR:
            color_code = COLOR_CODE[HOST_COLOR[datatype]]
            print("{}{}{} {}".format(color_code, self.label, COLOR_CODE['RESET_COLOR'], data))
        else:
            print("{} {} {}".format(self.label, HOST_SUFFIX[datatype], data))

    def process_data(self, data, datatype):
        self.buf[datatype] += data
        out = self.buf[datatype].split('\n')
        self.buf[datatype] = out.pop()
        for line in out:
            self.print(datatype, line)

    async def connect(self):
        client_keys = ()
        if self.args.key:
            client_keys = self.args.key
#        if self.args.password:
#            client_keys = None
        try:
            self.conn, self.client = await asyncssh.create_connection(lambda: OSSHClient(self), self.addr, password=self.args.password, username=self.args.user, client_keys=client_keys)
        except Exception as e:
            self.print('error', e)

    async def preconnect(self):
        await self.connect()
        try:
            next(self.dispatcher)
        except StopIteration:
            pass

    def stop_run(self):
        self.run_task.cancel()
        self.print('error', 'connection terminated on timeout')

    async def run(self):
        try:
            if not self.conn and not self.client:
                await self.connect()
            if self.conn:
                stop_run_handle = None
                if self.args.timeout:
                    stop_run_handle = self.loop.call_later(self.args.timeout, self.stop_run)
                async with self.conn:
                    chan, session = await self.conn.create_session(lambda: OSSHClientSession(self), self.args.commands)
                    await chan.wait_closed()
                if stop_run_handle:
                    stop_run_handle.cancel()
        except asyncio.CancelledError as ce:
            pass
        except Exception as e:
            self.print('error', e)
        try:
            next(self.dispatcher)
        except StopIteration:
            pass

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
        args.commands = "\n".join(args.commands)
        self.dispatcher = self._dispatcher()
        self.loop = asyncio.get_event_loop()
        for h in self.hosts:
            h.label = h.label.ljust(max_label_len)
            h.args = self.args
            h.dispatcher = self.dispatcher
            h.loop = self.loop
        asyncio.ensure_future(self.start_dispatcher())
        try:
            self.loop.run_forever()
        finally:
            self.loop.close() 

    async def start_dispatcher(self):
        try:
            next(self.dispatcher)
        except StopIteration:
            pass
    
    def _dispatcher(self):
        try:
            if self.args.preconnect:
                for h in self.hosts:
                    h.connect_task = asyncio.ensure_future(h.preconnect())
                for h in self.hosts:
                    yield
                hosts_len = len(self.hosts)
                self.hosts = [h for h in self.hosts if h.conn]
                if not self.args.ignore_failures:
                    failed_connections = hosts_len - len(self.hosts)
                    if failed_connections > 0:
                        raise OSSHException('Failed to connect to {} hosts'.format(failed_connections))
            running = 0
            for h in self.hosts:
                h.run_task = asyncio.ensure_future(h.run())
                running += 1
                if running < self.args.par:
                    continue
                yield
                running -= 1
            for h in range(0, running):
                yield
        except Exception as e:
            print('Error: {}'.format(e))
        finally:
            self.loop.stop()

class OSSHCommandAction(argparse.Action):
    def __call__(self, parser, args, values, option_string=None):
        if not hasattr(args, 'commands'):
            setattr(args, 'commands', [])
        if self.dest == 'command_file':
            with open(values) as f:
                values = f.read()
        commands = getattr(args, 'commands')
        commands.append(values)

class OSSHCli(OSSH):
    def parse_cli_args(self):
        commands = []
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-p', '--par', type=int, default=DEFAULT_CONCURRENCY, help="How many hosts to run simultaneously (default: %(default)d)")
        parser.add_argument('-C', '--command-file', type=str, help="File with commands to run", action=OSSHCommandAction)
        parser.add_argument('-c', '--command', type=str, help="Command to run", action=OSSHCommandAction)
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
        parser.add_argument('-V', '--verbose', help="Enable verbose output for debugging", action="store_true")
        parser.add_argument('-i', '--ignore-failures', help="Ignore connection failures in the preconnect mode", action="store_true")
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
