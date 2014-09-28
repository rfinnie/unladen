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
import unladen.config
import getopt
import unladen.sql as sql
import os
import shutil
import random
import time
try:
    import http.client as httplib
except ImportError:
    import httplib
import json
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
import hashlib
import threading


class UnladenMaint():
    cluster_peers_cache = {}
    sema = threading.Semaphore(10)

    def __init__(self, config):
        self.config = config
        engine = sql.create_engine(self.config['database']['url'], echo=self.config['debug'])
        self.conn = engine.connect()

    def random_weighted(self, m):
        """Return a weighted random key."""
        total = sum([v for v in m.values()])
        weighted = []
        tp = 0
        for (k, v) in m.items():
            tp = tp + (float(v) / float(total))
            weighted.append((k, tp))
        r = random.random()
        for (k, v) in weighted:
            if r < v:
                return k

    def choose_peers(self, existing_peers, peer_weights, target):
        confidence = 0.0
        out = []
        for peer in existing_peers:
            if peer in self.config['peers']:
                out.append(peer)
                confidence = confidence + (self.config['peers'][peer]['confidence'] / 100.0)
        if confidence >= target:
            return out
        peer_candidates = {}
        for peer in self.config['peers']:
            if peer in out:
                continue
            peer_candidates[peer] = peer_weights[peer]
        if len(peer_candidates) == 0:
            return out
        while confidence < target:
            peer = self.random_weighted(peer_candidates)
            out.append(peer)
            confidence = confidence + (self.config['peers'][peer]['confidence'] / 100.0)
            del(peer_candidates[peer])
            if len(peer_candidates) == 0:
                return out
        return out

    def clean_tokens_cache(self):
        time_target = time.time() - 3600
        self.conn.execute(sql.tokens_cache.delete().where(
            sql.tokens_cache.c.expires < time_target
        ))
        print('Deleted expired tokens')

    def peers_maint(self):
        self.cluster_peers_cache = {}
        sql_peers = {}
        todelete = []
        for (peer, peer_updated, storage_url, token, token_expires, total_size, used_size) in self.conn.execute(sql.select([
            sql.cluster_peers.c.peer,
            sql.cluster_peers.c.peer_updated,
            sql.cluster_peers.c.storage_url,
            sql.cluster_peers.c.token,
            sql.cluster_peers.c.token_expires,
            sql.cluster_peers.c.total_size,
            sql.cluster_peers.c.used_size
        ])):
            if peer not in self.config['peers']:
                todelete.append(peer)
                continue
            sql_peers[peer] = (peer_updated, storage_url, token, token_expires, total_size, used_size)
        for peer in todelete:
            self.conn.execute(sql.cluster_peers.delete().where(
                sql.cluster_peers.c.peer == peer
            ))
        for peer in self.config['peers']:
            if peer in sql_peers:
                (peer_updated, storage_url, token, token_expires, total_size, used_size) = sql_peers[peer]
            else:
                (peer_updated, storage_url, token, token_expires, total_size, used_size) = (0, None, None, 0, 0, 0)
            now = int(time.time())
            if time.time() > ((token_expires - peer_updated) / 2):
                url = urlparse.urlparse(self.config['peers'][peer]['auth']['url'])
                if url.scheme == 'https':
                    h = httplib.HTTPSConnection(url.netloc, timeout=5)
                else:
                    h = httplib.HTTPConnection(url.netloc, timeout=5)
                h.putrequest('GET', url.path)
                h.putheader('X-Auth-User', self.config['peers'][peer]['auth']['username'])
                h.putheader('X-Auth-Key', self.config['peers'][peer]['auth']['password'])
                h.endheaders()
                res = h.getresponse()
                print(res.getheaders())
                token = res.getheader('x-auth-token')
                token_expires = now + 86400
                storage_url = res.getheader('x-storage-url')
            url = urlparse.urlparse(storage_url)
            if url.scheme == 'https':
                h = httplib.HTTPSConnection(url.netloc, timeout=5)
            else:
                h = httplib.HTTPConnection(url.netloc, timeout=5)
            h.putrequest('HEAD', '%s/%s' % (url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea'))
            h.putheader('X-Auth-Token', token)
            h.endheaders()
            res = h.getresponse()
            print(res.getheaders())
            total_size = int(res.getheader('x-unladen-node-capacity'))
            used_size = int(res.getheader('x-container-bytes-used'))
            if peer in sql_peers:
                self.conn.execute(sql.cluster_peers.update().where(
                    sql.cluster_peers.c.peer == peer
                ).values(
                    peer_updated=now,
                    storage_url=storage_url,
                    token=token,
                    token_expires=token_expires,
                    total_size=total_size,
                    used_size=used_size
                ))
            else:
                self.conn.execute(sql.cluster_peers.insert().values(
                    peer=peer,
                    peer_updated=now,
                    storage_url=storage_url,
                    token=token,
                    token_expires=token_expires,
                    total_size=total_size,
                    used_size=used_size
                ))
            self.cluster_peers_cache[peer] = (peer_updated, storage_url, token, token_expires, total_size, used_size)

    def object_replication(self):
        peer_weights = {}
        for peer in self.cluster_peers_cache:
            (peer_updated, storage_url, token, token_expires, total_size, used_size) = self.cluster_peers_cache[peer]
            peer_weights[peer] = total_size
        toadd = []
        todel = []
        for (fn_uuid, meta) in self.conn.execute(sql.select([
            sql.objects.c.uuid,
            sql.objects.c.meta
        ]).where(
            sql.objects.c.deleted == False
        )):
            meta = json.loads(meta)
            existing_peers = []
            for peer in meta['disk_peers']:
                if peer in self.config['peers']:
                    existing_peers.append(peer)
            new_peers = self.choose_peers(existing_peers, peer_weights, 3.0)
            for peer in new_peers:
                if not peer in existing_peers:
                    toadd.append((fn_uuid, peer, existing_peers, meta['disk_bytes'], meta['disk_hash']))
            for peer in existing_peers:
                if not peer in new_peers:
                    todel.append((fn_uuid, peer))

        staging_delete = []
        if len(toadd) > 0:
            print('Starting threads...')
            for (fn_uuid, peer, existing_peers, bytes_disk, md5_hash) in toadd:
                self.sema.acquire(blocking=True)
                t = threading.Thread(target=self.replication_add_thread, args=(fn_uuid, peer, existing_peers, bytes_disk, md5_hash))
                t.start()
            print('Waiting for threads to finish...')
            while threading.active_count() > 1:
                time.sleep(0.5)
            print('All threads done.')
            for (fn_uuid, peer, existing_peers, bytes_disk, md5_hash) in toadd:
                (meta,) = self.conn.execute(sql.select([
                    sql.objects.c.meta
                ]).where(
                    sql.objects.c.uuid == fn_uuid
                )).fetchone()
                meta = json.loads(meta)
                meta['disk_peers'].append(peer)
                self.conn.execute(sql.objects.update().where(
                    sql.objects.c.uuid == fn_uuid
                ).values(
                    meta=json.dumps(meta)
                ))
                if not fn_uuid in staging_delete:
                    staging_delete.append(fn_uuid)

        if len(todel) > 0:
            print('Starting threads...')
            for (fn_uuid, peer) in todel:
                if not peer in self.config['peers']:
                    continue
                self.sema.acquire(blocking=True)
                t = threading.Thread(target=self.replication_del_thread, args=(fn_uuid, peer))
                t.start()
            print('Waiting for threads to finish...')
            while threading.active_count() > 1:
                time.sleep(0.5)
            print('All threads done.')
            for (fn_uuid, peer) in todel:
                (meta,) = self.conn.execute(sql.select([
                    sql.objects.c.meta
                ]).where(
                    sql.objects.c.uuid == fn_uuid
                )).fetchone()
                meta = json.loads(meta)
                meta['disk_peers'].remove(peer)
                self.conn.execute(sql.objects.update().where(
                    sql.objects.c.uuid == fn_uuid
                ).values(
                    meta=json.dumps(meta)
                ))

        for fn_uuid in staging_delete:
            contentdir = os.path.join(self.config['staging_files_dir'], fn_uuid[0:2], fn_uuid[2:4])
            if os.path.isfile(os.path.join(contentdir, fn_uuid)):
                os.remove(os.path.join(contentdir, fn_uuid))

    def replication_del_thread(self, fn_uuid, peer):
        if True:
            print('%s DEL %s %s' % (repr(threading.current_thread()), fn_uuid, peer))
            peer_storage_url = self.cluster_peers_cache[peer][1]
            peer_token = self.cluster_peers_cache[peer][2]
            peer_url = urlparse.urlparse(peer_storage_url)
            if peer_url.scheme == 'https':
                h = httplib.HTTPSConnection(peer_url.netloc, timeout=5)
            else:
                h = httplib.HTTPConnection(peer_url.netloc, timeout=5)
            h.putrequest('DELETE', '%s/%s/%s' % (peer_url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea', fn_uuid))
            h.putheader('X-Auth-Token', peer_token)
            h.endheaders()
            res = h.getresponse()
            self.sema.release()

    def replication_add_thread(self, fn_uuid, peer, existing_peers, bytes_disk, md5_hash):
        contentdir = os.path.join(self.config['staging_files_dir'], fn_uuid[0:2], fn_uuid[2:4])
        if not os.path.isfile(os.path.join(contentdir, fn_uuid)):
            peer_candidates = [x for x in existing_peers]
            while len(peer_candidates) > 0:
                remote_peer = random.choice(peer_candidates)
                peer_candidates.remove(remote_peer)
                print('%s PULL %s %s' % (repr(threading.current_thread()), fn_uuid, remote_peer))
                peer_storage_url = self.cluster_peers_cache[remote_peer][1]
                peer_token = self.cluster_peers_cache[remote_peer][2]
                peer_url = urlparse.urlparse(peer_storage_url)
                if peer_url.scheme == 'https':
                    h = httplib.HTTPSConnection(peer_url.netloc, timeout=5)
                else:
                    h = httplib.HTTPConnection(peer_url.netloc, timeout=5)
                h.putrequest('GET', '%s/%s/%s' % (peer_url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea', fn_uuid))
                h.putheader('X-Auth-Token', peer_token)
                h.endheaders()
                r = h.getresponse()
                bytesread = 0
                m = hashlib.md5()
                with open(os.path.join(contentdir, '%s.new' % fn_uuid), 'wb') as w:
                    blk = r.read(1024)
                    while blk:
                        m.update(blk)
                        bytesread = bytesread + len(blk)
                        w.write(blk)
                        blk = r.read(1024)
                md5_hash_test = m.hexdigest()
                if (bytesread == bytes_disk) and (md5_hash == md5_hash_test):
                    shutil.move(os.path.join(contentdir, '%s.new' % fn_uuid), os.path.join(contentdir, fn_uuid))
                    break
                else:
                    os.remove(os.path.join(contentdir, '%s.new' % fn_uuid))
        if not os.path.isfile(os.path.join(contentdir, fn_uuid)):
            raise Exception('Could not retrieve remote file')
        print('%s ADD %s %s %s' % (repr(threading.current_thread()), fn_uuid, peer, md5_hash))
        peer_storage_url = self.cluster_peers_cache[peer][1]
        peer_token = self.cluster_peers_cache[peer][2]
        peer_url = urlparse.urlparse(peer_storage_url)
        if peer_url.scheme == 'https':
            h = httplib.HTTPSConnection(peer_url.netloc, timeout=5)
        else:
            h = httplib.HTTPConnection(peer_url.netloc, timeout=5)
        h.putrequest('PUT', '%s/%s/%s' % (peer_url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea', fn_uuid))
        h.putheader('Content-Length', bytes_disk)
        h.putheader('X-Auth-Token', peer_token)
        h.putheader('ETag', md5_hash)
        h.endheaders()
        with open(os.path.join(contentdir, fn_uuid), 'rb') as r:
            blk = r.read(1024)
            while blk:
                h.send(blk)
                blk = r.read(1024)
        res = h.getresponse()
        self.sema.release()

    def delete_expired_objects(self):
        now = time.time()
        self.conn.execute(sql.objects.update().where(
            sql.objects.c.expires <= now
        ).values(
            deleted=True
        ))
        print('Marked expired objects as deleted')

    def purge_deleted_objects(self):
        to_purge = []
        for (fn_uuid, meta) in self.conn.execute(sql.select([
            sql.objects.c.uuid,
            sql.objects.c.meta
        ]).where(
            sql.objects.c.deleted == True
        )):
            meta = json.loads(meta)
            to_purge.append((fn_uuid, meta))
        if len(to_purge) > 0:
            print('Starting threads...')
            for (fn_uuid, meta) in to_purge:
                for peer in meta['disk_peers']:
                    if not peer in self.config['peers']:
                        continue
                    self.sema.acquire(blocking=True)
                    t = threading.Thread(target=self.purge_thread, args=(fn_uuid, peer))
                    t.start()
            print('Waiting for threads to finish...')
            while threading.active_count() > 1:
                time.sleep(0.5)
            print('All threads done.')
            for (fn_uuid, meta) in to_purge:
                self.conn.execute(sql.objects.delete().where(
                    sql.objects.c.uuid == fn_uuid
                ))
                contentdir = os.path.join(self.config['staging_files_dir'], fn_uuid[0:2], fn_uuid[2:4])
                if os.path.isfile(os.path.join(contentdir, fn_uuid)):
                    os.remove(os.path.join(contentdir, fn_uuid))
        print('Purged %d objects' % len(to_purge))

    def purge_thread(self, fn_uuid, peer):
        if True:
            if True:
                print('%s PURGE %s %s' % (repr(threading.current_thread()), fn_uuid, peer))
                peer_storage_url = self.cluster_peers_cache[peer][1]
                peer_token = self.cluster_peers_cache[peer][2]
                peer_url = urlparse.urlparse(peer_storage_url)
                if peer_url.scheme == 'https':
                    h = httplib.HTTPSConnection(peer_url.netloc, timeout=5)
                else:
                    h = httplib.HTTPConnection(peer_url.netloc, timeout=5)
                h.putrequest('DELETE', '%s/%s/%s' % (peer_url.path, '808f1b75-a011-4ea7-82a5-e6aad1092fea', fn_uuid))
                h.putheader('X-Auth-Token', peer_token)
                h.endheaders()
                res = h.getresponse()
                self.sema.release()

    def check_store_balance(self):
        store_stats = {}
        total_bytes = 0
        total_objects = 0
        for (store, objects, bytes) in self.conn.execute(sql.select([
            sql.files.c.store,
            sql.count('*'),
            sql.sum(sql.files.c.bytes_disk)
        ]).group_by(sql.files.c.store)):
            total_bytes = total_bytes + bytes
            total_objects = total_objects + objects
            store_stats[store] = (objects, bytes)
        if total_objects == 0:
            return
        total_config_bytes = 0
        for store in self.config['stores']:
            total_config_bytes = total_config_bytes + self.config['stores'][store]['size']
        rebalance_stores = False
        total_transfer_out = 0
        total_transfer_in = 0
        transfer_d = {}
        for store in sorted(self.config['stores']):
            if store in store_stats:
                (objects, bytes) = store_stats[store]
            else:
                (objects, bytes) = (0, 0)
            objects_pct = float(objects) / float(total_objects)
            bytes_pct = float(bytes) / float(total_bytes)
            config_pct = float(self.config['stores'][store]['size']) / float(total_config_bytes)
            config_pct_delta = bytes_pct - config_pct
            print('%s: %d objects (%0.02f%%), %d bytes (%0.02f%%, %0.02f%% from config)' % (store, objects, objects_pct * 100.0, bytes, bytes_pct * 100.0, config_pct_delta * 100.0))
            should_have = int(float(total_bytes) * config_pct)
            print('    Should have %d bytes' % should_have)
            transfer = bytes - should_have
            transfer_d[store] = transfer
            if transfer > 0:
                print('    Transfer %d bytes out' % abs(transfer))
                total_transfer_out = total_transfer_out + abs(transfer)
            else:
                print('    Transfer %d bytes in' % abs(transfer))
                total_transfer_in = total_transfer_in + abs(transfer)
            if abs(config_pct_delta) > 0.01:
                rebalance_stores = True
        if rebalance_stores:
            print('Time to rebalance the stores')
        else:
            print('Stores are sufficiently balanced')
            return
        transfer_orders = []
        for store_from in transfer_d:
            if transfer_d[store_from] < 0:
                continue
            stores_transfer_to = {}
            for store_to in transfer_d:
                if transfer_d[store_to] > 0:
                    continue
                x = int(float(abs(transfer_d[store_to])) / float(total_transfer_in) * float(transfer_d[store_from]))
                print('Transfer %d bytes from %s to %s' % (x, store_from, store_to))
                if x > 0:
                    stores_transfer_to[store_to] = x
            bytes_left = x
            res = self.conn.execute(sql.select([
                sql.files.c.uuid,
                sql.files.c.bytes_disk
            ]).where(
                sql.files.c.store == store_from
            ).order_by(
                sql.desc(sql.files.c.bytes_disk)
            ))
            for (fn_uuid, bytes) in res:
                store_to = None
                bytes_left = 0
                for store_to_candidate in stores_transfer_to:
                    if float(bytes) / float(stores_transfer_to[store_to_candidate]) < 1.05:
                        store_to = store_to_candidate
                        bytes_left = stores_transfer_to[store_to_candidate]
                        break
                if not store_to:
                    continue
                print('Move %s (%d) from %s to %s' % (fn_uuid, bytes, store_from, store_to))
                transfer_orders.append((fn_uuid, store_from, store_to))
                bytes_left = bytes_left - bytes
                if bytes_left <= 0:
                    del(stores_transfer_to[store_to])
                else:
                    stores_transfer_to[store_to] = bytes_left
                if len(stores_transfer_to) == 0:
                    res.close()
                    break
        print('')
        print('')
        random.shuffle(transfer_orders)
        for (fn_uuid, store_from, store_to) in transfer_orders:
            print('%s %s %s' % (fn_uuid, store_from, store_to))
            store_dir_from = self.config['stores'][store_from]['directory']
            contentdir_from = os.path.join(store_dir_from, fn_uuid[0:2], fn_uuid[2:4])
            store_dir_to = self.config['stores'][store_to]['directory']
            contentdir_to = os.path.join(store_dir_to, fn_uuid[0:2], fn_uuid[2:4])
            if not os.path.isdir(contentdir_to):
                os.makedirs(contentdir_to)
            shutil.copy(os.path.join(contentdir_from, fn_uuid), os.path.join(contentdir_to, fn_uuid))
            self.conn.execute(sql.files.update().where(
                sql.files.c.uuid == fn_uuid
            ).values(
                store=store_to
            ))
            os.remove(os.path.join(contentdir_from, fn_uuid))


def main(args):
    try:
        opts, args = getopt.getopt(args, '', ['config-dir=', 'debug'])
    except getopt.GetoptError as err:
        print(str(err))
        return(0)

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

    last_clean_tokens_cache = 0
    last_peers_maint = 0
    last_delete_expired_objects = 0
    last_purge_deleted_objects = 0
    last_check_store_balance = 0
    last_object_replication = 0

    maint = UnladenMaint(config)
    while True:
        if time.time() > (last_clean_tokens_cache + 60):
            maint.clean_tokens_cache()
            last_clean_tokens_cache = time.time()
        if time.time() > (last_peers_maint + 60):
            maint.peers_maint()
            last_peers_maint = time.time()
        if time.time() > (last_delete_expired_objects + 60):
            maint.delete_expired_objects()
            last_delete_expired_objects = time.time()
        if time.time() > (last_purge_deleted_objects + 10):
            maint.purge_deleted_objects()
            last_purge_deleted_objects = time.time()
        if time.time() > (last_check_store_balance + 60):
            maint.check_store_balance()
            last_check_store_balance = time.time()
        if time.time() > (last_object_replication + 3):
            maint.object_replication()
            last_object_replication = time.time()
        time.sleep(1)
