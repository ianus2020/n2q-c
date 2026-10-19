"""Local mTLS/SQLite integration, including the actual C signer callback."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.anchor.server import initialize, Store, handler
from tools.local_stand.pki import create, fingerprint
from tools.local_stand.tls import TLSHTTPServer, server_context


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


class AnchorService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.pki = create(cls.root/'pki')
        cls.client = cls.root/'client'
        subprocess.run(['cc','-O1','-g','-pthread','-fsanitize=address,undefined',
                        str(ROOT/'tests/anchor_http_client.c'),str(ROOT/'impl/c/n2q_cone_anchor_http.c'),
                        '-lcurl','-o',str(cls.client)],check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(dir=self.root))
        self.db = self.directory/'anchor.sqlite'
        initialize(self.db)
        signer = self.directory/'signer'
        signer.mkdir(mode=0o700)
        self.journal = signer/'journal'
        self.key_id = subprocess.check_output([str(self.client),'create',str(self.journal)],text=True).strip()
        self.http_id = hashlib.sha256(self.id().encode()).hexdigest()
        self.processes = []
        self.port = self.start()

    def start(self):
        port = free_port()
        cfg = dict(database=str(self.db),port=port,cert=str(self.pki/'server.pem'),
                   key=str(self.pki/'server.key'),ca=str(self.pki/'ca.pem'),
                   permissions={fingerprint(self.pki/'client.pem'):[self.key_id,self.http_id]})
        path = self.directory/('config-%s.json'%port)
        path.write_text(json.dumps(cfg));path.chmod(0o600)
        process = subprocess.Popen([sys.executable,str(ROOT/'tools/anchor/server.py'),'serve','--config',str(path)],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        self.processes.append(process)
        self.addCleanup(self.stop_process,process)
        deadline = time.monotonic()+10
        last = 'no response'
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(process.stderr.read().decode())
            try:
                last = self.request(None,port=port,path='/health',timeout=0.5)
                if last == 204:
                    return port
            except (OSError,ssl.SSLError,http.client.HTTPException) as error:
                last = type(error).__name__+': '+str(error)
            time.sleep(0.02)
        self.fail('anchor startup timeout: '+str(last))

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate();process.wait(timeout=5)
        process.stderr.close()

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate();process.wait(timeout=5)
            process.stderr.close()
        shutil.rmtree(self.directory)

    def context(self,identity='client'):
        context = ssl.create_default_context(cafile=str(self.pki/'ca.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        if identity:
            context.load_cert_chain(str(self.pki/(identity+'.pem')),str(self.pki/(identity+'.key')))
        return context

    def request(self,body,port=None,path='/v1/reserve',identity='client',raw=False,timeout=5):
        conn = http.client.HTTPSConnection('localhost',port or self.port,context=self.context(identity),timeout=timeout)
        try:
            if body is None:
                conn.request('GET',path)
            else:
                conn.request('POST',path,body if raw else json.dumps(body),{'Content-Type':'application/json'})
            response = conn.getresponse()
            self.assertEqual(response.read(),b'')
            self.assertEqual(response.getheader('Cache-Control'),'no-store')
            return response.status
        finally:
            conn.close()

    def reserve(self,index,**kwargs):
        return self.request(dict(key_id=self.http_id,index=index),**kwargs)

    def sign(self,port=None,ca=None):
        return subprocess.run([str(self.client),'https://localhost:%s/v1/reserve'%(port or self.port),
                               str(ca or self.pki/'ca.pem'),str(self.pki/'client.pem'),
                               str(self.pki/'client.key'),str(self.journal),'PUBLIC_TEST_SEED'],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)

    def test_persistence_concurrency_across_processes(self):
        second = self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(lambda i:self.reserve(0,port=second if i%2 else self.port),range(16)))
        self.assertEqual(codes.count(204),1)
        self.assertEqual(codes.count(409),15)
        self.assertEqual(self.reserve(1),204)
        for p in self.processes:
            p.kill();p.wait(timeout=5)
        self.port = self.start()
        self.assertEqual(self.reserve(0),409)
        self.assertEqual(self.reserve(1),409)
        self.assertEqual(self.reserve(2),204)

    def test_validation_and_tenant_binding(self):
        self.assertEqual(self.reserve(0,identity='unlisted'),403)
        self.assertEqual(self.request(dict(key_id='0'*64,index=0)),403)
        for index in [-1,16,True,'0',0.0,None]:
            self.assertEqual(self.reserve(index),400)
        self.assertEqual(self.request('{"key_id":"%s","index":0,"index":1}'%self.http_id,raw=True),400)
        self.assertEqual(self.request(' '*257,raw=True),413)
        self.assertEqual(self.reserve(0),204)
        with self.assertRaises((OSError,ssl.SSLError,http.client.HTTPException)):
            self.reserve(1,identity=None)
        with socket.create_connection(('127.0.0.1',self.port),timeout=3) as sock:
            with self.assertRaises(ssl.SSLError):
                self.context().wrap_socket(sock,server_hostname='wrong.example')

    def test_missing_state_and_reinitialization_fail_closed(self):
        with self.assertRaises(FileExistsError):
            initialize(self.db)
        for p in self.processes:
            p.terminate();p.wait(timeout=5)
        self.db.rename(self.db.with_suffix('.lost'))
        with self.assertRaises((OSError,ValueError)):
            Store(self.db)
        self.assertFalse(self.db.exists())

    def test_store_rejects_public_permissions_and_links(self):
        self.db.chmod(0o644)
        with self.assertRaises(ValueError): Store(self.db)
        self.db.chmod(0o600)
        link = self.directory/'alias.sqlite'
        link.symlink_to(self.db)
        with self.assertRaises(ValueError): Store(link)
        link.unlink();os.link(self.db,link)
        with self.assertRaises(ValueError): Store(self.db)
        link.unlink()

    def test_committed_request_with_lost_response_burns_index(self):
        faulty = handler(Store(self.db),{fingerprint(self.pki/'client.pem'):{self.key_id}})
        normal_reply = faulty.reply
        def drop_success(request,status):
            if status == 204:
                request.close_connection = True
                request.connection.close()
            else:
                normal_reply(request,status)
        faulty.reply = drop_success
        server = TLSHTTPServer(('127.0.0.1',0),faulty,
                               server_context(str(self.pki/'server.pem'),str(self.pki/'server.key'),str(self.pki/'ca.pem')))
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            result = self.sign(port=server.server_address[1])
            self.assertEqual(result.returncode,3,result.stdout+result.stderr)
            self.assertIn('signature_bytes=0',result.stdout)
            self.assertEqual(self.journal.stat().st_size,37+8)
            with sqlite3.connect(str(self.db)) as db:
                self.assertEqual(db.execute('SELECT last_index FROM counters WHERE key_id=?',(self.key_id,)).fetchone(),(0,))
            self.assertIn('verified_index=1',self.sign().stdout)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

    def test_c_signer_rejects_snapshot_and_unavailable_anchor(self):
        result = self.sign()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('verified_index=0',result.stdout)
        snapshot = self.journal.read_bytes()
        self.assertEqual(self.sign().returncode,0)
        self.journal.write_bytes(snapshot)
        result = self.sign()
        self.assertEqual(result.returncode,3,result.stdout+result.stderr)
        self.assertIn('signature_bytes=0',result.stdout)
        # Rejected duplicate burns local index; the next distinct index works.
        self.assertIn('verified_index=2',self.sign().stdout)
        length = self.journal.stat().st_size
        self.assertEqual(self.sign(port=free_port()).returncode,3)
        self.assertEqual(self.journal.stat().st_size,length+8)
        self.assertEqual(self.sign(ca=self.pki/'client.pem').returncode,3)


if __name__ == '__main__':
    unittest.main()
