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

import httplib


class UnladenRequestHandler():
    def __init__(self, http):
        self.http = http

    def process_request(self, reqpath):
        """Generic status reply."""
        r_fn = reqpath.strip('/').split('/')
        if not r_fn[0] == 'status':
            return False

        out = 'OK\n'
        self.http.send_response(httplib.OK)
        self.http.send_header('Content-Length', len(out))
        self.http.end_headers()
        self.http.wfile.write(out)
        return True
