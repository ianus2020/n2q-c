"""Versioned local HTTPS release host and atomic publication of public assets."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.local_stand.tls import TLSHTTPServer, server_context
from tools.anchor.server import private_path, unique_object

FILES = ('index.html','app.js','app.css','crypto-worker.js','pkg/build-manifest.json',
         'pkg/n2q_c_wasm.js','pkg/n2q_c_wasm_bg.wasm')
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_PUBLIC_BYTES = 64 * 1024 * 1024
MAX_RELEASES = 16
CSP = "default-src 'none'; script-src 'self' blob: 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
HEADERS = {'Content-Security-Policy':CSP,'X-Content-Type-Options':'nosniff',
           'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
           'Cross-Origin-Opener-Policy':'same-origin',
           'Cross-Origin-Embedder-Policy':'require-corp',
           'Cross-Origin-Resource-Policy':'same-origin',
           'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
           'Cache-Control':'no-store'}


def read_public(root,name):
    # A fixed allowlist, no symlinks and a pre-read size limit.
    path = Path(root)/name
    if name.startswith('pkg/') and not stat.S_ISDIR(os.lstat(Path(root)/'pkg').st_mode):
        raise ValueError('symlinked/non-directory pkg')
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4194304:
        raise ValueError('invalid public asset')
    with path.open('rb') as source:
        data = source.read(4194305)
    if len(data) != info.st_size or len(data)>4194304:
        raise ValueError('asset changed or exceeds limit')
    return data


def sync_directory(path):
    fd = os.open(path,os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def publish(source,destination):
    source,destination = Path(source).absolute(),Path(destination).absolute()
    if not stat.S_ISDIR(os.lstat(source).st_mode):
        raise ValueError('source must be a real directory')
    data = {name:read_public(source,name) for name in FILES}
    manifest = json.loads(data['pkg/build-manifest.json'],object_pairs_hook=unique_object)
    if manifest.get('version') != 1 or set(manifest) != {'version','js','wasm'}:
        raise ValueError('unknown build manifest')
    for key,name in [('js','pkg/n2q_c_wasm.js'),('wasm','pkg/n2q_c_wasm_bg.wasm')]:
        entry = manifest[key]
        if (not isinstance(entry,dict) or set(entry) != {'bytes','sha256'} or type(entry['bytes']) is not int
                or not 0 < entry['bytes'] <= 4194304 or entry['bytes'] != len(data[name])
                or hashlib.sha256(data[name]).hexdigest() != entry['sha256']):
            raise ValueError('mixed or damaged JS/WASM package')
    record = dict(version=1,files={name:dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                                  for name,body in data.items()})
    encoded = json.dumps(record,sort_keys=True,separators=(',',':')).encode()
    release = hashlib.sha256(encoded).hexdigest()
    destination.mkdir(mode=0o700,exist_ok=True)
    private_path(destination,directory=True)
    releases = destination/'releases'
    releases.mkdir(mode=0o700,exist_ok=True)
    private_path(releases,directory=True)
    final = releases/release
    if final.exists():
        if final.is_symlink() or read_public(final,'release.json') != encoded:
            raise ValueError('existing release is not the expected immutable build')
        if any(read_public(final,name) != body for name,body in data.items()):
            raise ValueError('existing release was modified')
    else:
        existing = [p for p in releases.iterdir() if HEX.fullmatch(p.name)]
        used = sum(p.stat().st_size for p in releases.rglob('*') if p.is_file())
        if len(existing) >= MAX_RELEASES or used + sum(map(len,data.values())) + len(encoded) > MAX_PUBLIC_BYTES:
            raise ValueError('local public-release quota exhausted; review old releases explicitly')
        staging = Path(tempfile.mkdtemp(prefix='.release-',dir=releases))
        try:
            (staging/'pkg').mkdir(mode=0o700)
            for name,body in dict(data,**{'release.json':encoded}).items():
                with (staging/name).open('xb') as output:
                    os.fchmod(output.fileno(),0o600)
                    output.write(body);output.flush();os.fsync(output.fileno())
            sync_directory(staging/'pkg');sync_directory(staging)
            os.rename(staging,final)
            sync_directory(releases)
        finally:
            if staging.exists(): shutil.rmtree(staging)
    fd,temp = tempfile.mkstemp(prefix='.current-',dir=destination)
    try:
        with os.fdopen(fd,'wb') as output:
            output.write(json.dumps(dict(release=release)).encode());output.flush();os.fsync(output.fileno())
        os.replace(temp,destination/'current.json');sync_directory(destination)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    return release


def handler(directory):
    directory = Path(directory).absolute()
    private_path(directory,directory=True)
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'N2QLocalTLS'
        sys_version = ''
        def log_message(self,*args): pass
        def respond(self,status,body=b'',content_type='text/plain',location=None):
            self.send_response(status)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Content-Type',content_type)
            for name,value in HEADERS.items():self.send_header(name,value)
            if location:self.send_header('Location',location)
            self.end_headers()
            if self.command != 'HEAD':self.wfile.write(body)
            self.close_connection = True
        def do_HEAD(self):self.do_GET()
        def do_GET(self):
            try:
                parsed = urlsplit(self.path)
                if parsed.scheme or parsed.netloc:raise ValueError('invalid target')
                path = unquote(parsed.path,errors='strict')
                if path == '/':
                    private_path(directory/'current.json')
                    pointer = json.loads((directory/'current.json').read_text(),object_pairs_hook=unique_object)
                    release = pointer['release']
                    if HEX.fullmatch(release) is None:raise ValueError('bad release')
                    self.respond(302,location='/releases/'+release+'/index.html')
                    return
                parts = path.split('/',3)
                if len(parts) != 4 or parts[1] != 'releases' or HEX.fullmatch(parts[2]) is None:
                    self.respond(404);return
                name = parts[3]
                if name not in (*FILES,'release.json'):
                    self.respond(404);return
                release_dir = directory/'releases'/parts[2]
                if release_dir.is_symlink():raise ValueError('symlink release')
                body = read_public(release_dir,name)
                mime = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8',
                        '.css':'text/css; charset=utf-8','.wasm':'application/wasm','.json':'application/json'}
                self.respond(200,body,mime[Path(name).suffix])
            except (OSError,ValueError,KeyError,TypeError):
                self.respond(404)
    return Handler


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command',required=True)
    pub = sub.add_parser('publish');pub.add_argument('--source',required=True);pub.add_argument('--destination',required=True)
    serve = sub.add_parser('serve');serve.add_argument('--directory',required=True)
    serve.add_argument('--cert',required=True);serve.add_argument('--key',required=True);serve.add_argument('--port',type=int,default=9443)
    args = parser.parse_args()
    if args.command == 'publish': print(publish(args.source,args.destination))
    else:
        private_path(args.key)
        TLSHTTPServer(('127.0.0.1',args.port),handler(args.directory),server_context(args.cert,args.key)).serve_forever()


if __name__ == '__main__':main()
