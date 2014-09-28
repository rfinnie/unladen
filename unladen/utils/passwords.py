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
import os
import hashlib
import base64

# hashlib.pbkdf2_hmac is available in Python 2.7.8 and later, and is
# possibly faster if compiled against OpenSSL.
try:
    from hashlib import pbkdf2_hmac
except ImportError:
    import hmac
    import binascii
    import struct

    # Based on Django's pure Python implementation, but functionally
    # compatible with Python 2.7.8's version.
    def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=0):
        """Implements PBKDF2 as defined in RFC 2898, section 5.2"""
        assert iterations > 0
        if not isinstance(hash_name, str):
            raise TypeError(hash_name)
        hlen = hashlib.new(hash_name).digest_size
        if not dklen:
            dklen = hlen
        if dklen > (2 ** 32 - 1) * hlen:
            raise OverflowError('dklen too big')
        l = -(-dklen // hlen)
        r = dklen - (l - 1) * hlen

        hex_format_string = "%%0%ix" % (hlen * 2)

        inner, outer = hashlib.new(hash_name), hashlib.new(hash_name)
        if len(password) > inner.block_size:
            password = hashlib.new(hash_name, password).digest()
        password += b'\x00' * (inner.block_size - len(password))
        inner.update(password.translate(hmac.trans_36))
        outer.update(password.translate(hmac.trans_5C))

        def F(i):
            u = salt + struct.pack(b'>I', i)
            result = 0
            for j in xrange(int(iterations)):
                dig1, dig2 = inner.copy(), outer.copy()
                dig1.update(u)
                dig2.update(dig1.digest())
                u = dig2.digest()
                result ^= int(binascii.hexlify(u), 16)
            return binascii.unhexlify((hex_format_string % result).encode('ascii'))

        T = [F(x) for x in range(1, l)]
        return b''.join(T) + F(l)[:r]


def hash_password(password, salt=None, hash_name='sha256', iterations=10000):
    block_size = hashlib.new(hash_name).block_size
    if not salt:
        salt = os.urandom(block_size)
    hash_pass = pbkdf2_hmac(hash_name, password, salt, iterations, block_size)
    return '$PBKDF2$%s$%d$%s$%s' % (hash_name, iterations, base64.b64encode(salt), base64.b64encode(hash_pass))


def check_password(hash, password):
    assert hash[0:8] == '$PBKDF2$'
    (hash_name, iterations, salt, hash_pass) = hash[8:].split('$')
    iterations = int(iterations)
    hash_name = str(hash_name)
    salt = base64.b64decode(salt)
    return hash == hash_password(password, salt, hash_name, iterations)


if __name__ == '__main__':
    import getpass
    pw = getpass.getpass()
    pw2 = getpass.getpass('Retype password: ')
    assert pw == pw2
    hash = hash_password(pw)
    print('Password hash: %s' % hash)
    if check_password(hash, pw):
        print('Verification succeeded')
    else:
        print('Verification FAILED')
