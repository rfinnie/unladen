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
import unladen.sql as sql
import os
import time
import unladen.utils.passwords


class UnladenRequestHandler():
    def __init__(self, http):
        self.http = http
        engine = sql.create_engine(self.http.server.config['database']['url'], echo=self.http.server.config['debug'])
        self.conn = engine.connect()

    def process_request(self, reqpath):
        """Process Version 1.0 TempAuth commands."""
        r_fn = reqpath.strip('/').split('/')
        if not r_fn[0] == 'v1.0':
            return False
        if not self.http.server.config['auth_tempauth']['storage_url']:
            return False
        if len(r_fn) > 1:
            self.http.send_error(httplib.BAD_REQUEST)
            return True
        if not 'x-auth-user' in self.http.headers:
            self.http.send_error(httplib.BAD_REQUEST)
            return True
        username = self.http.headers['x-auth-user']
        password = self.http.headers['x-auth-key']
        res = self.conn.execute(sql.select([
            sql.tempauth_users.c.account,
            sql.tempauth_users.c.password
        ]).where(
            sql.tempauth_users.c.username == username
        )).fetchone()
        if not res:
            self.http.send_error(httplib.UNAUTHORIZED)
            return True
        (account_name, password_crypt) = res
        if not unladen.utils.passwords.check_password(password_crypt, password):
            self.http.send_error(httplib.UNAUTHORIZED)
            return True
        token = str(uuid.uuid4())
        expires = int(time.time() + 86400)
        # Since this is a local provider, we cheat a bit and just add
        # the token directly to tokens_cache.
        self.conn.execute(sql.tokens_cache.insert().values(
            id=token,
            account=account_name,
            expires=expires,
            source='auth_tempauth'
        ))
        self.http.send_response(httplib.NO_CONTENT)
        storage_url = self.http.server.config['auth_tempauth']['storage_url']
        self.http.send_header('X-Storage-Url', '%s/%s' % (storage_url, account_name))
        self.http.send_header('X-Unladen-Base-Url', storage_url)
        self.http.send_header('X-Auth-Token', token)
        self.http.end_headers()
        return True
