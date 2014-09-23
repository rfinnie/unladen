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

import sqlite3
import uuid
import os
import Crypto.Cipher.AES
import json
import hashlib
import time
import mimetypes
import traceback
import httplib
import random
import urlparse


class UnladenRequestHandler():
    authenticated_account = None

    def __init__(self, http):
        self.http = http
        self.data_dir = self.http.server.config['data_dir']
        self.conn = sqlite3.connect(os.path.join(self.data_dir, 'catalog.sqlite'))

    def send_error(self, code, message=None):
        """Return a (possibly formatted) error.

        This replicates the functionality of
        BaseHTTPRequestHandler.log_error(), but will format a response
        as JSON if format=json is requested.  It also utilizes
        Content-Length instead of Connection: close to improve
        performance of clients which send multiple requests per
        connection, as error responses are a common part of the
        REST-driven Swift API.

        Keyword arguments:
        code -- Numeric HTTP code.
        message -- Optional message text.
        """
        use_json = False
        if 'format' in self.http.query:
            if 'json' in self.http.query['format']:
                use_json = True

        try:
            short, long = self.http.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        self.http.log_error('code %d, message %s', code, message)
        self.http.send_response(code, message)
        if use_json:
            content = json.dumps({'code': code, 'message': message, 'explain': explain}).encode('utf-8')
            self.http.send_header('Content-Type', 'application/json; charset=utf-8')
        else:
            content = ('Error %(code)d (%(message)s)\n\n%(explain)s\n' %
                       {'code': code, 'message': message, 'explain': explain})
            self.http.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.http.send_header('Content-Length', len(content))
        self.http.end_headers()
        if self.http.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.http.wfile.write(content)

    def output_file_list(self, data):
        """Output a (possibly formatted) file list.

        Outputs a JSON dump of the data if requested, otherwise
        constructs a basic text file list.

        Keyword arguments:
        data -- List of dicts containing file data.  "name" is expected
                to be in each dict, at the very least.
        """
        use_json = False
        if 'format' in self.http.query:
            if 'json' in self.http.query['format']:
                use_json = True
        self.http.send_response(httplib.OK)
        if use_json:
            out = json.dumps(data).encode('utf-8')
            self.http.send_header('Content-Type', 'application/json; charset=utf-8')
            self.http.send_header('Content-Length', len(out))
            self.http.end_headers()
            self.http.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            out = ''
            for row in data:
                out += ('%s\n' % row['name']).encode('utf-8')
            self.http.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.http.send_header('Content-Length', len(out))
            self.http.end_headers()
            self.http.wfile.write(out)

    def choose_store(self):
        """Choose a random size-weighted store."""
        weight_map = {}
        for store in self.http.server.config['stores']:
            weight_map[store] = self.http.server.config['stores'][store]['size']
        return self.random_weighted(weight_map)

    def random_weighted(self, m):
        """Return a weighted random key."""
        total = sum([v for v in m.itervalues()])
        weighted = []
        tp = 0
        for (k, v) in m.iteritems():
            tp = tp + (float(v) / total)
            weighted.append((k, tp))
        r = random.random()
        for (k, v) in weighted:
            if r < v:
                return k

    def do_head_account(self, account_name):
        """Handle account-level HEAD operations."""
        c = self.conn.cursor()
        c.execute('SELECT COUNT(*), COUNT(DISTINCT container), SUM(bytes) FROM objects WHERE account = ?', (account_name,))
        (objects, containers, bytes) = c.fetchone()
        self.http.send_response(httplib.NO_CONTENT)
        self.http.send_header('X-Account-Container-Count', containers)
        self.http.send_header('X-Account-Bytes-Used', bytes)
        self.http.send_header('X-Account-Object-Count', objects)
        self.http.end_headers()

    def do_head_container(self, account_name, container_name):
        """Handle container-level HEAD operations."""
        c = self.conn.cursor()
        c.execute('SELECT COUNT(*), SUM(bytes) FROM objects WHERE account = ? AND container = ?', (account_name, container_name))
        (objects, bytes) = c.fetchone()
        if objects == 0:
            self.send_error(httplib.NOT_FOUND)
            return
        self.http.send_response(httplib.NO_CONTENT)
        self.http.send_header('X-Container-Bytes-Used', bytes)
        self.http.send_header('X-Container-Object-Count', objects)
        self.http.end_headers()

    def do_head_file_container(self):
        """Handle file container-level HEAD operations."""
        c = self.conn.cursor()
        c.execute('SELECT COUNT(*), SUM(bytes_disk) FROM files WHERE uploader = ?', (self.authenticated_account,))
        (files, bytes) = c.fetchone()
        if not bytes:
            bytes = 0
        total_config_bytes = 0
        for store in self.http.server.config['stores']:
            total_config_bytes = total_config_bytes + self.http.server.config['stores'][store]['size']
        self.http.send_response(httplib.NO_CONTENT)
        self.http.send_header('X-Container-Bytes-Used', bytes)
        self.http.send_header('X-Container-Object-Count', files)
        self.http.send_header('X-Unladen-Node-Capacity', total_config_bytes)
        self.http.end_headers()

    def do_head_object(self, account_name, container_name, object_name):
        """Handle object-level HEAD operations."""
        # Use the GET handler -- it will know when to stop if it's
        # actually a HEAD.
        self.do_get_object(account_name, container_name, object_name)

    def do_head_file(self, fn_uuid):
        """Handle file-level HEAD operations."""
        # Use the GET handler -- it will know when to stop if it's
        # actually a HEAD.
        self.do_get_file(fn_uuid)

    def do_get_account(self, account_name):
        """Handle account-level GET operations."""
        if 'marker' in self.http.query:
            self.output_file_list([])
            return
        c = self.conn.cursor()
        c.execute('SELECT container, COUNT(*), SUM(bytes) FROM objects WHERE account = ? GROUP BY container', (account_name,))
        out = []
        for (container_name, count, bytes) in c.fetchall():
            out.append({'name': container_name, 'count': count, 'bytes': bytes})
        self.output_file_list(out)

    def do_get_container(self, account_name, container_name):
        """Handle container-level GET operations."""
        if 'marker' in self.http.query:
            self.output_file_list([])
            return
        c = self.conn.cursor()
        c.execute('SELECT name, bytes, last_modified, expires, meta FROM objects WHERE account = ? AND container = ?', (account_name, container_name))
        out = []
        for (name, bytes, last_modified, expires, meta) in c.fetchall():
            if expires and expires <= time.time():
                continue
            if meta:
                meta = json.loads(meta)
            else:
                meta = {}
            content_type = 'application/octet-stream'
            if 'content_type' in meta:
                content_type = meta['content_type']
            out.append({'name': name, 'hash': meta['hash'], 'bytes': bytes, 'last_modified': last_modified, 'content_type': content_type})
        if len(out) == 0:
            self.send_error(httplib.NOT_FOUND)
            return
        self.output_file_list(out)

    def do_get_file_container(self):
        """Handle file container-level GET operations."""
        if 'marker' in self.http.query:
            self.output_file_list([])
            return
        c = self.conn.cursor()
        c.execute('SELECT uuid, bytes_disk, created, meta FROM files WHERE uploader = ?', (self.authenticated_account,))
        out = []
        for (uuid, bytes, last_modified, meta) in c.fetchall():
            if meta:
                meta = json.loads(meta)
            else:
                meta = {}
            content_type = 'application/octet-stream'
            out.append({'name': uuid, 'hash': meta['hash'], 'bytes': bytes, 'last_modified': last_modified, 'content_type': content_type})
        self.output_file_list(out)

    def do_get_object(self, account_name, container_name, object_name):
        """Handle object-level GET operations."""
        c = self.conn.cursor()
        c.execute('SELECT uuid, bytes, meta, last_modified, expires, user_meta FROM objects WHERE account = ? AND container = ? AND name = ?', (account_name, container_name, object_name))
        res = c.fetchone()
        if not res:
            self.send_error(httplib.NOT_FOUND)
            return
        (fn_uuid, length, meta, last_modified, expires, user_meta) = res
        if expires and expires <= time.time():
            self.send_error(httplib.NOT_FOUND)
            return
        if meta:
            meta = json.loads(meta)
        else:
            meta = {}
        if user_meta:
            user_meta = json.loads(user_meta)
        else:
            user_meta = {}
        aes_key = meta['aes_key'].decode('hex')
        self.http.send_response(httplib.OK)
        if 'content_type' in meta:
            self.http.send_header('Content-Type', meta['content_type'].encode('utf-8'))
        else:
            self.http.send_header('Content-Type', 'application/octet-stream')
        if 'content_encoding' in meta:
            self.http.send_header('Content-Encoding', meta['content_encoding'].encode('utf-8'))
        if 'content_disposition' in meta:
            self.http.send_header('Content-Disposition', meta['content_disposition'].encode('utf-8'))
        self.http.send_header('Content-Length', length)
        self.http.send_header('Last-Modified', self.http.date_time_string(last_modified))
        self.http.send_header('X-Timestamp', last_modified)
        if expires:
            self.http.send_header('X-Delete-At', expires)
        self.http.send_header('ETag', meta['hash'])
        for header in user_meta:
            self.http.send_header(('X-Object-Meta-%s' % header).encode('utf-8'), user_meta[header].encode('utf-8'))
        self.http.end_headers()
        if self.http.command == 'HEAD':
            return
        block_size = Crypto.Cipher.AES.block_size
        cipher = None
        peer = None
        if len(meta['disk_peers']) > 0:
            peer = random.choice(meta['disk_peers'])
        if peer:
            c.execute('SELECT storage_url, token FROM cluster_peers WHERE peer = ?', (peer,))
            res = c.fetchone()
            (peer_storage_url, peer_token) = res
            peer_url = urlparse.urlparse(peer_storage_url)
            if peer_url.scheme == 'https':
                h = httplib.HTTPSConnection(peer_url.netloc, timeout=5)
            else:
                h = httplib.HTTPConnection(peer_url.netloc, timeout=5)
            h.putrequest('GET', '%s/%s/%s' % (peer_url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea', fn_uuid))
            h.putheader('X-Auth-Token', peer_token)
            h.endheaders()
            r = h.getresponse()
        else:
            contentdir = os.path.join(self.http.server.config['staging_files_dir'], fn_uuid[0:2], fn_uuid[2:4])
            r = open(os.path.join(contentdir, fn_uuid), 'rb')
        if not cipher:
            iv = r.read(block_size)
            cipher = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_CFB, iv)
        bytesread = 0
        blk = r.read(1024)
        bytesread = bytesread + len(blk)
        while blk:
            buf = cipher.decrypt(blk)
            self.http.wfile.write(buf)
            blk = r.read(1024)
            bytesread = bytesread + len(blk)

    def do_get_file(self, fn_uuid):
        """Handle file-level GET operations."""
        if not fn_uuid:
            self.send_error(httplib.BAD_REQUEST)
            return
        c = self.conn.cursor()
        c.execute('SELECT bytes_disk, store, created, meta FROM files WHERE uuid = ?', (fn_uuid,))
        res = c.fetchone()
        if not res:
            self.send_error(httplib.NOT_FOUND)
            return
        (length, store, last_modified, meta) = res
        meta = json.loads(meta)
        store_dir = self.http.server.config['stores'][store]['directory']
        self.http.send_response(httplib.OK)
        self.http.send_header('Content-Type', 'application/octet-stream')
        self.http.send_header('Content-Length', length)
        self.http.send_header('Last-Modified', self.http.date_time_string(last_modified))
        self.http.send_header('X-Timestamp', last_modified)
        self.http.send_header('ETag', meta['hash'])
        self.http.end_headers()
        if self.http.command == 'HEAD':
            return
        with open(os.path.join(store_dir, fn_uuid[0:2], fn_uuid[2:4], fn_uuid), 'rb') as r:
            blk = r.read(1024)
            while blk:
                self.http.wfile.write(blk)
                blk = r.read(1024)

    def do_put_account(self, account_name):
        """Handle account-level PUT operations.

        This operation intentionally returns BAD_REQUEST as PUT
        (creation) of an account is not supported by the Swift API.
        """
        self.send_error(httplib.BAD_REQUEST)

    def do_put_container(self, account_name, container_name):
        """Handle container-level PUT operations."""
        self.http.send_response(httplib.CREATED)
        self.http.send_header('Content-Length', 0)
        self.http.end_headers()

    def do_put_file_container(self):
        """Handle file container-level PUT operations."""
        self.http.send_response(httplib.CREATED)
        self.http.send_header('Content-Length', 0)
        self.http.end_headers()

    def do_put_object(self, account_name, container_name, object_name):
        """Handle object-level PUT operations."""
        if not 'content-length' in self.http.headers:
            self.send_error(httplib.LENGTH_REQUIRED)
            return
        length = int(self.http.headers['content-length'])
        last_modified = time.time()
        if 'x-unladen-uuid' in self.http.headers:
            try:
                fn_uuid = str(uuid.UUID(self.http.headers['x-unladen-uuid']))
            except ValueError:
                self.send_error(httplib.BAD_REQUEST)
                return
        else:
            fn_uuid = str(uuid.uuid4())
        if 'x-unladen-aes-key' in self.http.headers:
            try:
                aes_key = self.http.headers['x-unladen-aes-key'].decode('hex')
            except TypeError:
                self.send_error(httplib.BAD_REQUEST)
                return
            if not len(aes_key) == 32:
                self.send_error(httplib.BAD_REQUEST)
                return
        else:
            aes_key = os.urandom(32)
        meta = {}
        meta_file = {}
        meta['aes_key'] = aes_key.encode('hex')
        if 'x-detect-content-type' in self.http.headers and self.http.headers['x-detect-content-type'] == 'true':
            (content_type_guess, content_encoding_guess) = mimetypes.guess_type(object_name)
            if content_type_guess:
                meta['content_type'] = content_type_guess
            if content_encoding_guess:
                meta['content_encoding'] = content_encoding_guess
        else:
            if 'content-type' in self.http.headers:
                meta['content_type'] = self.http.headers['content-type']
            if 'content-encoding' in self.http.headers:
                meta['content_encoding'] = self.http.headers['content-encoding']
        if 'content-disposition' in self.http.headers:
            meta['content_disposition'] = self.http.headers['content-disposition']
        expires = None
        if 'x-delete-at' in self.http.headers:
            expires = int(self.http.headers['x-delete-at'])
        elif 'x-delete-after' in self.http.headers:
            expires = last_modified + int(self.http.headers['x-delete-after'])
        user_meta = {}
        for header in self.http.headers:
            if header.lower().startswith('x-object-meta-'):
                user_meta[header[14:]] = self.http.headers[header]
        contentdir = os.path.join(self.http.server.config['staging_files_dir'], fn_uuid[0:2], fn_uuid[2:4])
        if not os.path.isdir(contentdir):
            os.makedirs(contentdir)
        block_size = Crypto.Cipher.AES.block_size
        iv = os.urandom(block_size)
        cipher = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_CFB, iv)
        m = hashlib.md5()
        m_file = hashlib.md5()
        bytes_disk = 0
        with open(os.path.join(contentdir, fn_uuid), 'wb') as w:
            m_file.update(iv)
            w.write(iv)
            bytes_disk = bytes_disk + len(iv)
            bytesread = 0
            toread = 1024
            if (bytesread + toread) > length:
                toread = length - bytesread
            blk = self.http.rfile.read(toread)
            bytesread = bytesread + len(blk)
            while blk:
                m.update(blk)
                blk_encrypted = cipher.encrypt(blk)
                m_file.update(blk_encrypted)
                w.write(blk_encrypted)
                bytes_disk = bytes_disk + len(blk_encrypted)
                toread = 1024
                if (bytesread + toread) > length:
                    toread = length - bytesread
                blk = self.http.rfile.read(toread)
                bytesread = bytesread + len(blk)
        md5_hash = m.hexdigest()
        md5_hash_file = m_file.hexdigest()
        if 'etag' in self.http.headers:
            if not self.http.headers['etag'].lower() == md5_hash:
                self.send_error(httplib.CONFLICT)
                return
        meta['hash'] = md5_hash
        meta_file['hash'] = md5_hash_file
        meta['disk_peers'] = []
        c = self.conn.cursor()
        c.execute('SELECT uuid FROM objects WHERE account = ? AND container = ? AND name = ?', (account_name, container_name, object_name))
        res = c.fetchone()
        if res:
            (old_fn_uuid,) = res
            c.execute('DELETE FROM objects WHERE uuid = ?', (old_fn_uuid,))
            self.conn.commit()
        c.execute('INSERT INTO objects (uuid, account, container, name, bytes, last_modified, expires, meta, user_meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (fn_uuid, account_name, container_name, object_name, length, last_modified, expires, json.dumps(meta), json.dumps(user_meta)))
        self.conn.commit()
        self.http.send_response(httplib.CREATED)
        if 'content_type' in meta:
            self.http.send_header('Content-Type', meta['content_type'].encode('utf-8'))
        else:
            self.http.send_header('Content-Type', 'application/octet-stream')
        if 'content_encoding' in meta:
            self.http.send_header('Content-Encoding', meta['content_encoding'].encode('utf-8'))
        if 'content_disposition' in meta:
            self.http.send_header('Content-Disposition', meta['content_disposition'].encode('utf-8'))
        self.http.send_header('Content-Length', 0)
        self.http.send_header('ETag', md5_hash)
        self.http.end_headers()

    def do_put_file(self, fn_uuid):
        """Handle file-level PUT operations."""
        if not fn_uuid:
            self.send_error(httplib.BAD_REQUEST)
            return
        if not 'content-length' in self.http.headers:
            self.send_error(httplib.LENGTH_REQUIRED)
            return
        length = int(self.http.headers['content-length'])
        try:
            uuid.UUID(fn_uuid)
        except ValueError:
            self.send_error(httplib.BAD_REQUEST)
            return
        c = self.conn.cursor()
        c.execute('SELECT store FROM files WHERE uuid = ?', (fn_uuid,))
        res = c.fetchone()
        if res:
            self.send_error(httplib.CONFLICT)
            return
        now = time.time()
        meta_file = {}
        store = self.choose_store()
        store_dir = self.http.server.config['stores'][store]['directory']
        contentdir = os.path.join(store_dir, fn_uuid[0:2], fn_uuid[2:4])
        if not os.path.isdir(contentdir):
            os.makedirs(contentdir)
        m_file = hashlib.md5()
        bytes_disk = 0
        with open(os.path.join(contentdir, fn_uuid), 'wb') as w:
            bytesread = 0
            toread = 1024
            if (bytesread + toread) > length:
                toread = length - bytesread
            blk = self.http.rfile.read(toread)
            bytesread = bytesread + len(blk)
            while blk:
                m_file.update(blk)
                w.write(blk)
                bytes_disk = bytes_disk + len(blk)
                toread = 1024
                if (bytesread + toread) > length:
                    toread = length - bytesread
                blk = self.http.rfile.read(toread)
                bytesread = bytesread + len(blk)
        md5_hash_file = m_file.hexdigest()
        if 'etag' in self.http.headers:
            if not self.http.headers['etag'].lower() == md5_hash_file:
                self.send_error(httplib.CONFLICT)
                return
        meta_file['hash'] = md5_hash_file
        c.execute('INSERT INTO files (uuid, bytes_disk, store, uploader, created, meta) VALUES (?, ?, ?, ?, ?, ?)', (fn_uuid, bytes_disk, store, self.authenticated_account, now, json.dumps(meta_file)))
        self.conn.commit()
        self.http.send_response(httplib.CREATED)
        self.http.send_header('Content-Length', 0)
        self.http.send_header('ETag', md5_hash_file)
        self.http.end_headers()

    def do_post_account(self, account_name):
        """Handle account-level POST operations."""
        self.http.send_response(httplib.CREATED)
        self.http.send_header('Content-Length', 0)
        self.http.end_headers()

    def do_post_container(self, account_name, container_name):
        """Handle container-level POST operations."""
        self.http.send_response(httplib.CREATED)
        self.http.send_header('Content-Length', 0)
        self.http.end_headers()

    def do_post_object(self, account_name, container_name, object_name):
        """Handle object-level POST operations."""
        c = self.conn.cursor()
        c.execute('SELECT uuid, expires FROM objects WHERE account = ? AND container = ? AND name = ?', (account_name, container_name, object_name))
        res = c.fetchone()
        if not res:
            self.send_error(httplib.NOT_FOUND)
            return
        (fn_uuid, expires) = res
        if expires and expires <= time.time():
            self.send_error(httplib.NOT_FOUND)
            return
        user_meta = {}
        for header in self.http.headers:
            if header.lower().startswith('x-object-meta-'):
                user_meta[header[14:]] = self.http.headers[header]
        last_modified = time.time()
        c.execute('UPDATE objects SET user_meta = ?, last_modified = ? WHERE uuid = ?', (json.dumps(user_meta), last_modified, fn_uuid))
        self.conn.commit()
        self.http.send_response(httplib.NO_CONTENT)
        self.http.end_headers()

    def do_delete_account(self, account_name):
        """Handle account-level DELETE operations.

        This operation intentionally returns BAD_REQUEST as deletion
        of an account is not supported by the Swift API.
        """
        self.send_error(httplib.BAD_REQUEST)

    def do_delete_container(self, account_name, container_name):
        """Handle container-level DELETE operations."""
        c = self.conn.cursor()
        c.execute('SELECT COUNT(*) FROM objects WHERE account = ? AND container = ?', (account_name, container_name))
        (objects,) = c.fetchone()
        if objects > 0:
            self.send_error(httplib.CONFLICT)
            return
        self.http.send_response(httplib.NO_CONTENT)
        self.http.end_headers()

    def do_delete_object(self, account_name, container_name, object_name):
        """Handle object-level DELETE operations."""
        c = self.conn.cursor()
        c.execute('SELECT uuid FROM objects WHERE account = ? AND container = ? AND name = ?', (account_name, container_name, object_name))
        res = c.fetchone()
        if not res:
            self.send_error(httplib.NOT_FOUND)
            return
        (fn_uuid,) = res
        c.execute('DELETE FROM objects WHERE uuid = ?', (fn_uuid,))
        self.conn.commit()
        self.http.send_response(httplib.NO_CONTENT)
        self.http.end_headers()

    def do_delete_file(self, fn_uuid):
        """Handle file-level DELETE operations."""
        c = self.conn.cursor()
        c.execute('SELECT store FROM files WHERE uuid = ?', (fn_uuid,))
        res = c.fetchone()
        if not res:
            self.send_error(httplib.NOT_FOUND)
            return
        (store,) = res
        store_dir = self.http.server.config['stores'][store]['directory']
        c.execute('DELETE FROM files WHERE uuid = ?', (fn_uuid,))
        os.remove(os.path.join(store_dir, fn_uuid[0:2], fn_uuid[2:4], fn_uuid))
        self.conn.commit()
        self.http.send_response(httplib.NO_CONTENT)
        self.http.end_headers()

    def authenticate_token(self, user_token):
        c = self.conn.cursor()
        c.execute('SELECT account FROM tokens_cache WHERE id = ? AND expires > ?', (user_token, time.time()))
        res = c.fetchone()
        if not res:
            return False
        (token_account,) = res
        return token_account

    def process_request(self, reqpath):
        """Process Version 1 Swift commands."""
        r_fn = reqpath.strip('/').split('/')
        if not r_fn[0] == 'v1':
            return False

        if len(r_fn) == 1:
            self.send_error(httplib.BAD_REQUEST)
            return True
        if 'format' in self.http.query:
            if not 'json' in self.http.query['format']:
                self.send_error(httplib.NOT_IMPLEMENTED)
                return True
        mode = self.http.command.lower()
        if len(r_fn) == 2:
            level = 'account'
            args = [r_fn[1]]
        elif len(r_fn) == 3:
            if r_fn[2] == '808f1b75-a011-4ea7-82a5-e6aad1092fea':
                level = 'file_container'
                args = []
            else:
                level = 'container'
                args = [r_fn[1], r_fn[2]]
        else:
            if r_fn[2] == '808f1b75-a011-4ea7-82a5-e6aad1092fea':
                level = 'file'
                args = [r_fn[3]]
            else:
                level = 'object'
                args = [r_fn[1], r_fn[2], '/'.join(r_fn[3:])]
        try:
            call_func = getattr(self, 'do_%s_%s' % (mode, level))
        except AttributeError:
            self.send_error(httplib.NOT_IMPLEMENTED)
            return True
        if 'x-auth-token' in self.http.headers:
            ret = self.authenticate_token(self.http.headers['x-auth-token'])
            if ret:
                self.authenticated_account = ret
            else:
                self.send_error(httplib.UNAUTHORIZED)
                return True
        try:
            call_func(*args)
            return True
        except Exception, err:
            print traceback.format_exc()
            self.send_error(httplib.INTERNAL_SERVER_ERROR, err.message)
            return True
