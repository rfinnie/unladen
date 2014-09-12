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

import uuid
import httplib


class UnladenRequestHandler():
    def __init__(self, http):
        self.http = http

    def process_request(self, reqpath):
        """Process Version 1.0 TempAuth commands.

        For now this is a stub auth which, if configured, always
        succeeds, give a random token, and sets the Unladen user
        to the specified user.
        """
        r_fn = reqpath.strip('/').split('/')
        if not r_fn[0] == 'v1.0':
            return False
        if not self.http.server.config['auth_tempauth']['storage_url']:
            return False
        if len(r_fn) > 1:
            self.send_error(httplib.BAD_REQUEST)
            return True
        if not 'x-auth-user' in self.http.headers:
            self.send_error(httplib.BAD_REQUEST)
            return True
        self.http.send_response(httplib.NO_CONTENT)
        self.http.send_header('X-Storage-Url', '%s/%s' % (self.http.server.config['auth_tempauth']['storage_url'], self.http.headers['x-auth-user']))
        self.http.send_header('X-Auth-Token', str(uuid.uuid4()))
        self.http.end_headers()
        return True
