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

import sqlalchemy

create_engine = sqlalchemy.create_engine
distinct = sqlalchemy.distinct
select = sqlalchemy.sql.select
count = sqlalchemy.func.count
sum = sqlalchemy.func.sum

metadata = sqlalchemy.MetaData()

tempauth_users = sqlalchemy.Table(
    'tempauth_users',
    metadata,
    sqlalchemy.Column('account', sqlalchemy.String, primary_key=True),
    sqlalchemy.Column('username', sqlalchemy.String),
    sqlalchemy.Column('password', sqlalchemy.String)
)


tokens_cache = sqlalchemy.Table(
    'tokens_cache',
    metadata,
    sqlalchemy.Column('id', sqlalchemy.String, primary_key=True),
    sqlalchemy.Column('account', sqlalchemy.String),
    sqlalchemy.Column('expires', sqlalchemy.Integer),
    sqlalchemy.Column('source', sqlalchemy.String)
)

objects = sqlalchemy.Table(
    'objects',
    metadata,
    sqlalchemy.Column('uuid', sqlalchemy.String, primary_key=True),
    sqlalchemy.Column('account', sqlalchemy.String),
    sqlalchemy.Column('container', sqlalchemy.String),
    sqlalchemy.Column('name', sqlalchemy.String),
    sqlalchemy.Column('bytes', sqlalchemy.Integer),
    sqlalchemy.Column('last_modified', sqlalchemy.Integer),
    sqlalchemy.Column('expires', sqlalchemy.Integer),
    sqlalchemy.Column('deleted', sqlalchemy.Boolean),
    sqlalchemy.Column('meta', sqlalchemy.String),
    sqlalchemy.Column('user_meta', sqlalchemy.String)
)

files = sqlalchemy.Table(
    'files',
    metadata,
    sqlalchemy.Column('uuid', sqlalchemy.String, primary_key=True),
    sqlalchemy.Column('bytes_disk', sqlalchemy.Integer),
    sqlalchemy.Column('store', sqlalchemy.String),
    sqlalchemy.Column('uploader', sqlalchemy.String),
    sqlalchemy.Column('created', sqlalchemy.Integer),
    sqlalchemy.Column('meta', sqlalchemy.String)
)

cluster_peers = sqlalchemy.Table(
    'cluster_peers',
    metadata,
    sqlalchemy.Column('peer', sqlalchemy.String, primary_key=True),
    sqlalchemy.Column('peer_updated', sqlalchemy.Integer),
    sqlalchemy.Column('storage_url', sqlalchemy.String),
    sqlalchemy.Column('token', sqlalchemy.String),
    sqlalchemy.Column('token_expires', sqlalchemy.Integer),
    sqlalchemy.Column('total_size', sqlalchemy.Integer),
    sqlalchemy.Column('used_size', sqlalchemy.Integer)
)
