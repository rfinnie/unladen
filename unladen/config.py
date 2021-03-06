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

import json
import os
import copy
import platform

if __file__.startswith('/usr/lib'):
    DEFAULT_CONFIG_DIR = '/etc/unladen'
    DEFAULT_DATA_DIR = '/var/lib/unladen'
elif __file__.startswith('/usr/local/lib'):
    DEFAULT_CONFIG_DIR = '/usr/local/etc'
    DEFAULT_DATA_DIR = '/usr/local/lib/unladen'
else:
    DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.unladen', 'etc')
    DEFAULT_DATA_DIR = os.path.join(os.path.expanduser('~'), '.unladen', 'var')

DEFAULT_CONFIG = {
    'data_dir': DEFAULT_DATA_DIR,
    'staging_files_dir': None,
    'debug': False,
    'node_id': platform.node(),
    'stores': {},
    'peers': {},
    'database': {
        'url': None
    },
    'httpd': {
        'handlers': ['auth_tempauth', 'swift_v1', 'status'],
        'listen': {
            'ipv6': False,
            'addr': '',
            'port': 52777,
            'ssl': False,
            'ssl_key': None,
            'ssl_cert': None,
            'ssl_version': None,
            'ssl_ciphers': None
        },
        'xff_trusted_relays': []
    },
    'auth_tempauth': {
        'storage_url': None
    }
}


def dict_merge(s, m):
    """Recursively merge one dict into another."""
    if not isinstance(m, dict):
        return m
    out = copy.deepcopy(s)
    for k, v in m.items():
        if k in out and isinstance(out[k], dict):
            out[k] = dict_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def get_config(config_dir='', config_cl={}):
    """Build a merged configuration."""
    # Use the built-in default config
    config = DEFAULT_CONFIG

    # If config.json is found, merge that
    if not config_dir:
        config_dir = DEFAULT_CONFIG_DIR
    json_file = os.path.join(config_dir, 'config.json')
    if os.path.isfile(json_file):
        res = open(json_file, 'rb').read()
        if type(res) == bytes:
            res = res.decode('utf-8')
        config = dict_merge(config, json.loads(res))

    # Merge anything from the command line
    config = dict_merge(config, config_cl)

    # Handle empty node ID
    if not config['node_id']:
        config['node_id'] = 'default'

    # Build default storage_url if not specified
    if not config['auth_tempauth']['storage_url']:
        addr = config['httpd']['listen']['addr']
        if not addr:
            if config['httpd']['listen']['ipv6']:
                addr = '::1'
            else:
                addr = '127.0.0.1'
        if config['httpd']['listen']['ipv6']:
            addr = '[%s]' % addr
        config['auth_tempauth']['storage_url'] = 'http://%s:%d/v1' % (addr, config['httpd']['listen']['port'])

    if not config['staging_files_dir']:
        config['staging_files_dir'] = os.path.join(config['data_dir'], 'staging_files')

    for peer in config['peers']:
        if not 'auth' in config['peers'][peer]:
            raise Exception('"auth" not specified for peer "%s"' % peer)
        if not 'confidence' in config['peers'][peer]:
            config['peers'][peer]['confidence'] = 100

    # Check stores configuration for completeness
    for store in config['stores']:
        if not 'directory' in config['stores'][store]:
            raise Exception('"directory" not specified for store "%s"' % store)
        if not 'size' in config['stores'][store]:
            config['stores'][store]['size'] = 10000000000

    if not config['database']['url']:
        config['database']['url'] = 'sqlite:///%s' % os.path.join(config['data_dir'], 'catalog.sqlite')

    return config
