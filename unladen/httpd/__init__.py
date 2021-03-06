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

from __future__ import print_function
try:
    import http.server as BaseHTTPServer
except ImportError:
    import BaseHTTPServer
try:
    import socketserver as SocketServer
except ImportError:
    import SocketServer
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
import threading
try:
    import http.client as httplib
except ImportError:
    import httplib
import ssl
import unladen.sql as sql
import unladen.config
import getopt
import logging


class UnladenHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'Unladen/0.0.0.242.1'
    sys_version = ''

    # HTTP/1.1 requires very specific handling.  In general, every response
    # either needs Content-Length or Connection: close.  Exceptions are
    # codes 1xx, 204, and 304.
    protocol_version = 'HTTP/1.1'

    handler_modules = {}
    logger = logging.getLogger(__name__)

    def dump_req(self):
        self.logger.debug('Request:')
        self.logger.debug('    Thread: %s (%d total)' % (repr(threading.current_thread()), len(threading.enumerate())))
        self.logger.debug('    Command: %s' % self.command)
        self.logger.debug('    URL: %s' % repr(self.url))
        self.logger.debug('    Processed path: %s' % self.reqpath)
        self.logger.debug('    Query items: %s' % repr(self.query))
        self.logger.debug('    Headers: %s' % repr({k: v for (k, v) in self.headers.items()}))

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

    def process_ipv6_normalize(self):
        if self.server.address_family == SocketServer.socket.AF_INET:
            return
        if self.client_address[0].startswith('::ffff:'):
            self.client_address = (self.client_address[0][7:], self.client_address[1])

    def process_command(self):
        self.url = urlparse.urlparse(self.path)
        self.reqpath = urlparse.unquote(self.url.path).decode('utf-8')
        self.query = urlparse.parse_qs(self.url.query)
        q = urlparse.parse_qs(self.url.query)
        self.query = {}
        for n in q:
            self.query[n.decode('utf-8')] = [y.decode('utf-8') for y in q[n]]

        self.process_ipv6_normalize()
        self.process_xff()
        self.dump_req()

        self.sql_conn = sql.UnladenSqlConn(self.server.sql_engine)
        for handler_name in self.server.config['httpd']['handlers']:
            if handler_name in self.handler_modules:
                handler_module = self.handler_modules['handler_name']
            else:
                handler_module = __import__('unladen.httpd.handlers.%s' % handler_name, fromlist=['unladen.httpd.handlers'])
                self.handler_modules['handler_name'] = handler_module
            handler_claimed = False
            try:
                handler_instance = handler_module.UnladenRequestHandler(self)
                handler_claimed = handler_instance.process_request(self.reqpath)
            except Exception as e:
                self.logger.exception(e)
                self.send_error(httplib.INTERNAL_SERVER_ERROR, str(e))
                self.sql_conn.close()
                return
            if handler_claimed:
                self.sql_conn.close()
                return
        self.sql_conn.close()

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
        if config['httpd']['listen']['ssl']:
            kwargs = {
                'server_side': True,
                'keyfile': config['httpd']['listen']['ssl_key'],
                'certfile': config['httpd']['listen']['ssl_cert']
            }
            if config['httpd']['listen']['ssl_version']:
                kwargs['ssl_version'] = getattr(ssl, 'PROTOCOL_%s' % config['httpd']['listen']['ssl_version'])
            if config['httpd']['listen']['ssl_ciphers']:
                kwargs['ciphers'] = config['httpd']['listen']['ssl_ciphers']
            self.socket = ssl.wrap_socket(self.socket, **kwargs)
        self.sql_engine = sql.create_engine(config['database']['url'])


def main(args):
    try:
        opts, args = getopt.getopt(args, '', ['config-dir=', 'debug'])
    except getopt.GetoptError as err:
        print(str(err))
        return(1)

    config_dir = ''
    config_cl = {}
    for o, a in opts:
        if o == '--config-dir':
            config_dir = a
        elif o == '--debug':
            config_cl['debug'] = True
        else:
            assert False, "unhandled option"

    config = unladen.config.get_config(config_dir, config_cl)

    if config['debug']:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
        logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    httpd = UnladenHTTPServer(config, (config['httpd']['listen']['addr'], config['httpd']['listen']['port']), UnladenHTTPHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return(0)
