"""Reference external-process CoNe anchor. Local stand, not deployment approval.

State must be outside the signer's rollback domain. Restoring the anchor's own
database snapshot violates the monotonicity contract; retire affected keys.
"""
import argparse
from contextlib import closing
import hashlib
import http.server
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat
import sys
from urllib.parse import quote

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.local_stand.tls import TLSHTTPServer, server_context

HEX32 = re.compile(r'[0-9a-f]{64}\Z')


def private_path(path, directory=False):
    st = os.lstat(path)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('anchor state/key path must be private and owned by the service user')
    if not directory and st.st_nlink != 1:
        raise ValueError('hardlinked anchor state/key is forbidden')


class Store:
    def __init__(self, path):
        self.path = pathlib.Path(path).absolute()
        private_path(self.path.parent, directory=True)
        private_path(self.path)
        with closing(self.connect()) as db:
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('unknown anchor schema')
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise ValueError('damaged anchor database')
            if db.execute('SELECT count(*) FROM identity').fetchone()[0] != 1:
                raise ValueError('missing anchor identity')

    def connect(self):
        # mode=rw refuses to recreate a missing DB. Parent is owner-only.
        private_path(self.path)
        db = sqlite3.connect('file:' + quote(str(self.path), safe='/') + '?mode=rw',
                             uri=True, timeout=2, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA fullfsync=ON')
        if db.execute('PRAGMA journal_mode').fetchone()[0] != 'wal':
            db.close()
            raise ValueError('anchor requires WAL mode')
        return db

    def reserve(self, key_id, index):
        db = self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('INSERT INTO counters(key_id,last_index) VALUES (?,?) '
                                'ON CONFLICT(key_id) DO UPDATE SET last_index=excluded.last_index '
                                'WHERE excluded.last_index > counters.last_index', (key_id,index))
            accepted = cursor.rowcount == 1
            db.execute('COMMIT')
            # HTTP success is sent only after COMMIT returned with FULL sync.
            return accepted
        except Exception:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()


def initialize(path):
    path = pathlib.Path(path).absolute()
    private_path(path.parent, directory=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(str(path), isolation_level=None)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA fullfsync=ON')
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE identity(id TEXT PRIMARY KEY NOT NULL)')
        db.execute('INSERT INTO identity VALUES (?)', (secrets.token_hex(32),))
        db.execute('CREATE TABLE counters(key_id TEXT PRIMARY KEY NOT NULL, '
                   'last_index INTEGER NOT NULL CHECK(last_index BETWEEN 0 AND 15))')
        db.execute('PRAGMA user_version=1')
        db.execute('COMMIT')
    finally:
        db.close()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def unique_object(pairs):
    result = {}
    for k,v in pairs:
        if k in result:
            raise ValueError('duplicate JSON property')
        result[k] = v
    return result


def handler(store, permissions):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        server_version = 'N2QAnchor'
        sys_version = ''

        def log_message(self, *args):
            pass  # No request bodies, credentials or key identifiers in logs.

        def reply(self, status):
            self.send_response(status)
            self.send_header('Content-Length','0')
            self.send_header('Cache-Control','no-store')
            self.send_header('Connection','close')
            self.end_headers()
            self.close_connection = True

        def peer_permissions(self):
            cert = self.connection.getpeercert(binary_form=True)
            return permissions.get(hashlib.sha256(cert).hexdigest(), set()) if cert else set()

        def do_GET(self):
            if not self.peer_permissions():
                self.reply(403)
            else:
                self.reply(204 if self.path == '/health' else 404)

        def do_POST(self):
            allowed = self.peer_permissions()
            if not allowed:
                self.reply(403)
                return
            if self.path != '/v1/reserve':
                self.reply(404)
                return
            lengths = self.headers.get_all('Content-Length', [])
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()
                    or self.headers.get('Transfer-Encoding') is not None
                    or self.headers.get('Content-Type') != 'application/json'):
                self.reply(400)
                return
            size = int(lengths[0])
            if not 1 <= size <= 256:
                self.reply(413)
                return
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError('short request')
                request = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
                if not isinstance(request,dict) or set(request) != {'key_id','index'}:
                    raise ValueError('unexpected properties')
                key_id, index = request['key_id'], request['index']
                if not isinstance(key_id,str) or HEX32.fullmatch(key_id) is None:
                    raise ValueError('bad key identifier')
                if type(index) is not int or not 0 <= index < 16:
                    raise ValueError('bad index')
            except (ValueError, UnicodeError, OSError):
                self.reply(400)
                return
            if key_id not in allowed:
                self.reply(403)
                return
            try:
                self.reply(204 if store.reserve(key_id,index) else 409)
            except (sqlite3.Error, OSError, ValueError):
                self.reply(503)  # Uncertain commit is a failure; signer burns index.
    return Handler


def load_config(path):
    private_path(path)
    config = json.loads(pathlib.Path(path).read_text(), object_pairs_hook=unique_object)
    permissions = config['permissions']
    if not permissions or len(permissions) > 256:
        raise ValueError('invalid permission set')
    for fingerprint, keys in permissions.items():
        if not isinstance(keys,list) or HEX32.fullmatch(fingerprint) is None or not keys or len(keys) > 256:
            raise ValueError('invalid peer permission')
        if any(not isinstance(key,str) or HEX32.fullmatch(key) is None for key in keys):
            raise ValueError('invalid key identifier')
    private_path(config['key'])
    return config, {k:set(v) for k,v in permissions.items()}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command',required=True)
    sub.add_parser('init').add_argument('--db',required=True)
    sub.add_parser('serve').add_argument('--config',required=True)
    args = parser.parse_args()
    if args.command == 'init':
        initialize(args.db)
    else:
        config, permissions = load_config(args.config)
        # Stand intentionally binds loopback. External hosting is a separate step.
        server = TLSHTTPServer(('127.0.0.1',int(config.get('port',9444))),
                               handler(Store(config['database']),permissions),
                               server_context(config['cert'],config['key'],config['ca']))
        server.serve_forever()


if __name__ == '__main__':
    main()
