import hashlib
import json
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.local_stand.web import FILES,HEADERS,publish,handler
from tools.local_stand.pki import create
from tools.local_stand.tls import TLSHTTPServer,server_context


class LocalWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.pki=create(cls.root/'pki')
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.work=Path(tempfile.mkdtemp(dir=self.root))
        self.source=self.work/'source';(self.source/'pkg').mkdir(parents=True)
        for name in FILES:
            (self.source/name).write_bytes(('public fixture '+name).encode())
        self.write_manifest()
        self.dest=self.work/'published'
        self.release=publish(self.source,self.dest)
        self.server=TLSHTTPServer(('127.0.0.1',0),handler(self.dest),
                                  server_context(str(self.pki/'server.pem'),str(self.pki/'server.key')))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base='https://localhost:%s'%self.server.server_address[1]
        self.context=ssl.create_default_context(cafile=str(self.pki/'ca.pem'))
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5);shutil.rmtree(self.work)
    def write_manifest(self):
        m={'version':1}
        for key,name in [('js','pkg/n2q_c_wasm.js'),('wasm','pkg/n2q_c_wasm_bg.wasm')]:
            body=(self.source/name).read_bytes();m[key]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        (self.source/'pkg/build-manifest.json').write_text(json.dumps(m))
    def get(self,path):return urllib.request.urlopen(self.base+path,context=self.context,timeout=3)
    def test_https_headers_mime_and_allowlist(self):
        with self.get('/') as response:
            self.assertTrue(response.url.endswith('/'+self.release+'/index.html'))
            for key,value in HEADERS.items():self.assertEqual(response.getheader(key),value)
        prefix='/releases/'+self.release+'/'
        with self.get(prefix+'pkg/n2q_c_wasm_bg.wasm') as response:
            self.assertEqual(response.getheader('Content-Type'),'application/wasm')
        for name in ['../../pki/server.key','%2e%2e/%2e%2e/pki/server.key','pkg/../app.js','pkg/','secret.key','']:
            with self.assertRaises(urllib.error.HTTPError) as error:self.get(prefix+name)
            self.assertEqual(error.exception.code,404)
        with self.assertRaises((ssl.SSLError,urllib.error.URLError)):
            urllib.request.urlopen(self.base,timeout=3)
    def test_versioned_publication_preserves_old_pages_and_rejects_tampering(self):
        old=(self.source/'app.js').read_bytes()
        (self.source/'app.js').write_bytes(b'new public fixture')
        new=publish(self.source,self.dest)
        self.assertNotEqual(new,self.release)
        with self.get('/releases/'+self.release+'/app.js') as response:self.assertEqual(response.read(),old)
        with self.get('/') as response:self.assertIn(new,response.url)
        pointer=(self.dest/'current.json').read_bytes()
        (self.source/'pkg/n2q_c_wasm_bg.wasm').write_bytes(b'broken')
        with self.assertRaises(ValueError):publish(self.source,self.dest)
        self.assertEqual((self.dest/'current.json').read_bytes(),pointer)
        self.assertFalse(list((self.dest/'releases').glob('.release-*')))
    def test_symlinked_artifacts_are_rejected(self):
        path=self.source/'app.js';path.unlink();path.symlink_to(self.pki/'server.key')
        with self.assertRaises(ValueError):publish(self.source,self.dest)
    def test_manifest_type_and_release_quota_preserve_current(self):
        pointer=(self.dest/'current.json').read_bytes()
        manifest=json.loads((self.source/'pkg/build-manifest.json').read_text())
        manifest['version']=True
        (self.source/'pkg/build-manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):publish(self.source,self.dest)
        self.write_manifest();(self.source/'app.js').write_bytes(b'new release')
        with mock.patch('tools.local_stand.web.MAX_PUBLIC_BYTES',1):
            with self.assertRaises(ValueError):publish(self.source,self.dest)
        self.assertEqual((self.dest/'current.json').read_bytes(),pointer)


if __name__=='__main__':unittest.main()
