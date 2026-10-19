import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'impl/python'))
import n2qc as q
from tools.migration import n2q_migrate as m


def sha(data):return hashlib.sha256(data).hexdigest()
def legacy(bits,profile,key,chunks):
    output=b'N2QF'+bytes([1,(1 if bits==128 else 2)|(0x20 if profile==q.FAST else 0)])
    for i,chunk in enumerate(chunks):
        ct=q.seal(bits,profile,key,i.to_bytes(16,'little'),b'',chunk)
        output+=len(ct).to_bytes(4,'little')+ct
    return output


class OfflineMigration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.old=self.root/'old.key';self.new=self.root/'new.key'
        self.old.write_bytes(bytes(range(16)));self.new.write_bytes(bytes(range(32)))
        self.old.chmod(0o600);self.new.chmod(0o600)
        self.source=self.root/'source.n2qf';self.destination=self.root/'result'
        self.plain=b'firstsecond'
        self.original=legacy(128,q.SECURE,self.old.read_bytes(),[b'first',b'second'])
        self.source.write_bytes(self.original)
    def tearDown(self):self.tmp.cleanup()
    def migrate(self,**changes):
        args=dict(source=self.source,destination=self.destination,old_key_path=self.old,new_key_path=self.new,
                  trusted_container_hash=sha(self.original),trusted_plaintext_hash=sha(self.plain),
                  trusted_plaintext_bytes=len(self.plain),allow_v1=True)
        args.update(changes);return m.migrate(**args)
    def assert_clean(self):
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(self.root.glob('.n2q-migrate-*')))
    def test_both_widths_profiles_and_empty_v1(self):
        for bits in (128,256):
            self.old.write_bytes(bytes(range(bits//8)))
            for profile in (q.SECURE,q.FAST):
                self.new.write_bytes(bytes(range(16 if profile==q.FAST else 32)))
                for chunks in ([b'first',b'second'],[]):
                    original=legacy(bits,profile,self.old.read_bytes(),chunks);plain=b''.join(chunks)
                    self.source.write_bytes(original)
                    report=self.migrate(trusted_container_hash=sha(original),trusted_plaintext_hash=sha(plain),trusted_plaintext_bytes=len(plain))
                    encrypted=(self.destination/'data.n2qf').read_bytes()
                    self.assertEqual(b''.join(q._decrypt_chunks(len(self.new.read_bytes())*8,self.new.read_bytes(),io.BytesIO(encrypted))),plain)
                    self.assertEqual(report['output_container_sha256'],sha(encrypted))
                    self.assertEqual((self.destination/'data.n2qf').stat().st_mode&0o777,0o600)
                    self.assertNotIn('key_hex',json.dumps(report))
                    self.assertEqual(self.source.read_bytes(),original)
                    shutil.rmtree(self.destination)
    def test_v2_rekey_and_readback(self):
        original=b''.join(q._encrypt_chunks(128,q.FAST,self.old.read_bytes(),[self.plain]))
        self.source.write_bytes(original)
        report=self.migrate(trusted_container_hash=sha(original),allow_v1=False)
        self.assertEqual(report['input_version'],2)
        self.assertEqual(report['output_profile'],'Secure')
    def test_trusted_evidence_is_required_and_no_overwrite(self):
        for changed in [dict(allow_v1=False),dict(trusted_container_hash='0'*64),dict(trusted_plaintext_hash='0'*64),
                        dict(trusted_plaintext_bytes=0),dict(trusted_plaintext_bytes=12)]:
            with self.assertRaises(ValueError):self.migrate(**changed)
            self.assert_clean()
        self.destination.mkdir();(self.destination/'keep').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):self.migrate()
        self.assertEqual((self.destination/'keep').read_bytes(),b'keep')
    def test_record_truncation_splicing_and_malformed_sizes(self):
        first_end=6+4+16+5
        other=legacy(128,q.SECURE,self.old.read_bytes(),[b'other',b'second'])
        variants=[self.original[:first_end],self.original[:-1],self.original+b'garbage',
                  self.original[:first_end]+other[first_end:]]
        # A real cross-file splice with valid per-record tags and changed PT.
        variants.append(other[:first_end]+self.original[first_end:])
        for length in [0,15,65553,0xffffffff]:variants.append(self.original[:6]+length.to_bytes(4,'little')+self.original[10:])
        for original in variants:
            if original==self.original:continue
            self.source.write_bytes(original)
            with self.assertRaises(ValueError):self.migrate(trusted_container_hash=sha(original))
            self.assert_clean()
        # The normal reader still rejects legacy; only this explicit tool recovers.
        with self.assertRaises(ValueError):list(q._decrypt_chunks(128,self.old.read_bytes(),io.BytesIO(self.original)))
    def test_private_keys_links_and_budget(self):
        self.new.chmod(0o644)
        with self.assertRaises(ValueError):self.migrate()
        self.new.chmod(0o600)
        alias=self.root/'alias';alias.symlink_to(self.old)
        with self.assertRaises(OSError):self.migrate(old_key_path=alias)
        alias.unlink();os.link(self.old,alias)
        with self.assertRaises(ValueError):self.migrate()
        alias.unlink()
        with self.assertRaises(ValueError):self.migrate(max_source_bytes=10,trusted_plaintext_bytes=5)
        self.assert_clean()
    def test_publish_error_and_concurrent_destination_preserve_data(self):
        with mock.patch.object(m,'rename_new_directory',side_effect=OSError('simulated publish error')):
            with self.assertRaises(OSError):self.migrate()
        self.assert_clean()
        original=m.rename_new_directory
        inode=[]
        def raced(source,destination):
            destination.mkdir(mode=0o700)
            inode.append(destination.stat().st_ino)
            original(source,destination)
        with mock.patch.object(m,'rename_new_directory',side_effect=raced):
            with self.assertRaises(OSError):self.migrate()
        self.assertEqual(self.destination.stat().st_ino,inode[0])
        self.assertEqual(list(self.destination.iterdir()),[])
        self.assertFalse(list(self.root.glob('.n2q-migrate-*')))
    def test_inventory_never_claims_trust(self):
        report=m.inventory(self.root)
        self.assertEqual(len(report['files']),1)
        self.assertEqual(report['files'][0]['observed_sha256'],sha(self.original))
        self.assertEqual(report['files'][0]['status'],'untrusted observation')
        self.assertNotIn(self.new.read_bytes().hex(),json.dumps(report))
    def test_legacy_large_record_is_explicitly_bounded_and_split(self):
        plain=b'a'*65537
        original=legacy(128,q.FAST,self.old.read_bytes(),[plain]);self.source.write_bytes(original)
        evidence=dict(trusted_container_hash=sha(original),trusted_plaintext_hash=sha(plain),trusted_plaintext_bytes=len(plain))
        with self.assertRaises(ValueError):self.migrate(**evidence)
        self.assert_clean()
        self.migrate(legacy_record_limit=131072,**evidence)
        with (self.destination/'data.n2qf').open('rb') as source:
            chunks=list(q._decrypt_chunks(256,self.new.read_bytes(),source))
        self.assertEqual([len(c) for c in chunks],[65536,1]);self.assertEqual(b''.join(chunks),plain)
    def test_secret_metadata_is_rejected_and_inventory_redacts_keys(self):
        bundle=dict(format='n2q-offline-key-v1',algorithm='argon2id-v19',key_bits=256,
                    key_hex=self.new.read_bytes().hex(),salt_hex='00'*16,
                    costs=dict(memory_kib=65536,passes=3,lanes=1,password='must not be copied'))
        path=self.root/'bundle.json';path.write_text(json.dumps(bundle));path.chmod(0o600)
        with self.assertRaises(ValueError):m.key_file(path)
        report=m.inventory(self.root)
        self.assertNotIn(bundle['key_hex'],json.dumps(report))
        self.assertNotIn('must not be copied',json.dumps(report))


@unittest.skipUnless(os.environ.get('N2Q_MIGRATION_KEYS_BINARY'),'offline Rust CLI not configured')
class PasswordKeyCLI(unittest.TestCase):
    def test_new_restore_legacy_and_no_clobber(self):
        binary=os.environ['N2Q_MIGRATION_KEYS_BINARY']
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);password=root/'password';salt=root/'salt';first=root/'first.json';again=root/'restored.json'
            password.write_bytes(b'correct horse\n');password.chmod(0o600)
            def run(*args,success=True):
                p=subprocess.run([binary,*map(str,args)],capture_output=True,text=True,timeout=30)
                self.assertEqual(p.returncode==0,success,p.stderr)
                return p
            run('new',password,256,first)
            data=json.loads(first.read_text());salt.write_bytes(bytes.fromhex(data['salt_hex']));salt.chmod(0o600)
            c=data['costs'];run('restore',password,salt,c['memory_kib'],c['passes'],c['lanes'],256,again)
            self.assertEqual(json.loads(again.read_text())['key_hex'],data['key_hex'])
            self.assertEqual(first.stat().st_mode&0o777,0o600)
            before=first.read_bytes();run('new',password,256,first,success=False)
            self.assertEqual(first.read_bytes(),before)
            old=root/'legacy.json'
            run('legacy',password,salt,4,2,128,old,'--acknowledge-insecure-recovery')
            self.assertEqual(len(m.key_file(old)[0]),16)
            with self.assertRaises(ValueError):m.key_file(old,for_output=True)
            run('legacy',password,salt,0,2,128,root/'bad.json','--acknowledge-insecure-recovery',success=False)


if __name__=='__main__':unittest.main()
