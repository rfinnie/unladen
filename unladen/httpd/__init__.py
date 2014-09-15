#!/usr/bin/env python

# Unladen
# Copyright (C) 2014 Ryan Finnie
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import BaseHTTPServer
import SocketServer
import urlparse
import urllib
import threading
import httplib
import traceback


class UnladenHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'Unladen/0.0.0.242.1'
    sys_version = ''

    # HTTP/1.1 requires very specific handling.  In general, every response
    # either needs Content-Length or Connection: close.  Exceptions are
    # codes 1xx, 204, and 304.
    protocol_version = 'HTTP/1.1'

    handler_instances = {}

    def dump_req(self):
        print '========================================'
        print 'Thread: %s (%d total)' % (repr(threading.current_thread()), len(threading.enumerate()))
        print 'Command: %s' % self.command
        print 'URL: %s' % repr(self.url)
        print 'Processed path: %s' % self.reqpath
        print 'Query items: %s' % repr(self.query)
        print 'Headers: %s' % repr(self.headers.dict)
        print '========================================'

    def log_request(self, code='-', size='-'):
        """Log an accepted request."""
        referer = '-'
        ua = '-'
        if 'referer' in self.headers:
            referer = self.headers['referer']
        if 'user-agent' in self.headers:
            referer = self.headers['user-agent']

        self.log_message('"%s" %s %s "%s" "%s"', self.requestline, str(code), str(size), str(referer), str(ua))

    def process_xff(self):
        if not 'x-forwarded-for' in self.headers:
            return
        remote_addr = self.client_address[0]
        if not remote_addr in self.server.config['httpd']['xff_trusted_relays']:
            return
        xff_list = self.headers['x-forwarded-for'].split(', ')
        xff_list.reverse()
        for ip in xff_list:
            if not ip:
                continue
            if ip in self.server.config['httpd']['xff_trusted_relays']:
                continue
            self.client_address = (ip, self.client_address[1])
            break

    def process_command(self):
        self.url = urlparse.urlparse(self.path)
        self.reqpath = urllib.unquote(self.url.path).decode('utf-8')
        self.query = urlparse.parse_qs(self.url.query)
        q = urlparse.parse_qs(self.url.query)
        self.query = {}
        for n in q:
            self.query[n.decode('utf-8')] = [y.decode('utf-8') for y in q[n]]

        self.process_xff()

        if self.server.config['debug']:
            self.dump_req()

        for handler_name in self.server.config['httpd']['handlers']:
            if handler_name in self.handler_instances:
                handler_instance = self.handler_instances['handler_name']
            else:
                try:
                    handler_module = __import__('unladen.httpd.handlers.%s' % handler_name, fromlist=['unladen.httpd.handlers'])
                    handler_instance = handler_module.UnladenRequestHandler(self)
                except Exception, err:
                    print traceback.format_exc()
                    self.send_error(httplib.INTERNAL_SERVER_ERROR, err.message)
                self.handler_instances['handler_name'] = handler_instance
            handler_claimed = False
            try:
                handler_claimed = handler_instance.process_request(self.reqpath)
            except Exception, err:
                print traceback.format_exc()
                self.send_error(httplib.INTERNAL_SERVER_ERROR, err.message)
            if handler_claimed:
                return

        self.send_error(httplib.BAD_REQUEST)

    def do_PUT(self):
        self.process_command()

    def do_DELETE(self):
        self.process_command()

    def do_POST(self):
        self.process_command()

    def do_HEAD(self):
        self.process_command()

    def do_GET(self):
        self.process_command()


class UnladenHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    def __init__(self, config, *args):
        if config['httpd']['listen']['ipv6']:
            self.address_family = SocketServer.socket.AF_INET6
        else:
            self.address_family = SocketServer.socket.AF_INET
        self.config = config
        BaseHTTPServer.HTTPServer.__init__(self, *args)


def run(config):
    httpd = UnladenHTTPServer(config, (config['httpd']['listen']['addr'], config['httpd']['listen']['port']), UnladenHTTPHandler)
    httpd.serve_forever()
