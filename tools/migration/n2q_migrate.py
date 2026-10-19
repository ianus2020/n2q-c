"""Offline, explicit, synthetic-tested recovery/rekey tool; no application fallback.

Whole-file and plaintext hashes/length MUST come from independent trusted evidence.
Inventory hashes of a suspect file are observations, not trusted evidence.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'impl/python'))
sys.path.insert(0,str(ROOT))
import n2qc as q
from tools.anchor.server import private_path,unique_object

HEX=re.compile(r'[0-9a-f]{64}\Z')
DEFAULT_LIMIT=1 << 30


def open_regular(path,private=False):
    fd=os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):raise ValueError('regular input file required')
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('key must be an owner-only, non-hardlinked file')
        return os.fdopen(fd,'rb')
    except Exception:
        os.close(fd);raise


def key_file(path,for_output=False):
    private_path(Path(path).absolute().parent,directory=True)
    with open_regular(path,private=True) as stream:data=stream.read(4097)
    if len(data) in (16,32):return data,dict(algorithm='raw-key-file',key_bits=len(data)*8)
    if len(data)>4096:raise ValueError('key file too large')
    bundle=json.loads(data,object_pairs_hook=unique_object)
    if (not isinstance(bundle,dict) or set(bundle) != {'format','algorithm','key_bits','key_hex','salt_hex','costs'}
            or bundle['format'] != 'n2q-offline-key-v1' or type(bundle['key_bits']) is not int
            or bundle['key_bits'] not in (128,256)
            or bundle['algorithm'] not in ('argon2id-v19','legacy-n2q-pw-v1')):
        raise ValueError('unsupported private key bundle')
    if for_output and bundle['algorithm'] != 'argon2id-v19':
        raise ValueError('legacy password derivation is recovery-only')
    text=bundle['key_hex']
    if not isinstance(text,str) or re.fullmatch('[0-9a-f]{%d}'%(bundle['key_bits']//4),text) is None:
        raise ValueError('invalid private key encoding')
    return bytes.fromhex(text),{k:v for k,v in bundle.items() if k!='key_hex'}


class HashedReader:
    def __init__(self,source,limit):self.source=source;self.limit=limit;self.total=0;self.hash=hashlib.sha256()
    def read(self,count):
        if not 0 <= count <= (16 << 20)+32:raise ValueError('unbounded read forbidden')
        data=self.source.read(count);self.total+=len(data)
        if self.total>self.limit:raise ValueError('source exceeds offline resource budget')
        self.hash.update(data);return data


def legacy_chunks(source,bits,key,record_limit):
    header=source.read(6)
    suites=(1,0x21) if bits==128 else (2,0x22)
    if len(header)!=6 or header[:5]!=b'N2QF\1' or header[5] not in suites:
        raise ValueError('invalid legacy header')
    profile=q.FAST if header[5]&0x20 else q.SECURE
    index=0
    while True:
        length=source.read(4)
        if not length:break
        if len(length)!=4:raise ValueError('short legacy length')
        size=int.from_bytes(length,'little');tag=bits//8
        if not tag<size<=record_limit+tag:raise ValueError('legacy record exceeds bound')
        sealed=source.read(size)
        if len(sealed)!=size:raise ValueError('short legacy record')
        plaintext=q.open(bits,profile,key,index.to_bytes(16,'little'),b'',sealed)
        if plaintext is None:raise ValueError('legacy record authentication failed')
        for offset in range(0,len(plaintext),65536):yield plaintext[offset:offset+65536]
        index+=1
        if index >= 1 << 64:raise ValueError('legacy counter exhausted')


def rename_new_directory(source,destination):
    """Atomic no-replace publication. No racy exists-check fallback."""
    libc=ctypes.CDLL(None,use_errno=True)
    old,new=os.fsencode(source),os.fsencode(destination)
    if b'\0' in old or b'\0' in new:raise ValueError('NUL in publication path')
    if sys.platform=='darwin' and hasattr(libc,'renamex_np'):
        fn=libc.renamex_np;fn.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint];fn.restype=ctypes.c_int
        result=fn(old,new,4) # Darwin SDK RENAME_EXCL
    elif sys.platform.startswith('linux') and hasattr(libc,'renameat2'):
        fn=libc.renameat2;fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];fn.restype=ctypes.c_int
        result=fn(-100,old,-100,new,1) # AT_FDCWD / RENAME_NOREPLACE
    else:raise OSError(errno.ENOTSUP,'atomic no-replace directory publication unavailable')
    if result:raise OSError(ctypes.get_errno(),'migration destination was not published')


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY | os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def migrate(source,destination,old_key_path,new_key_path,trusted_container_hash,trusted_plaintext_hash,
            trusted_plaintext_bytes,allow_v1=False,max_source_bytes=DEFAULT_LIMIT,legacy_record_limit=65536):
    if (HEX.fullmatch(trusted_container_hash) is None or HEX.fullmatch(trusted_plaintext_hash) is None
            or type(trusted_plaintext_bytes) is not int or not 0<=trusted_plaintext_bytes<=max_source_bytes
            or not 1<=max_source_bytes<=1<<40 or not 1<=legacy_record_limit<=16<<20):
        raise ValueError('invalid trusted evidence or resource budget')
    destination=Path(destination).absolute();private_path(destination.parent,directory=True)
    if os.path.lexists(destination):raise FileExistsError('migration never replaces an existing destination')
    old_key,old_algorithm=key_file(old_key_path)
    new_key,new_algorithm=key_file(new_key_path,for_output=True)
    staging=None
    try:
        with open_regular(source) as raw:
            if os.fstat(raw.fileno()).st_size>max_source_bytes:raise ValueError('source exceeds budget')
            header=raw.read(6);raw.seek(0)
            if len(header)!=6 or header[:4]!=b'N2QF' or header[5] not in (1,0x21,2,0x22):
                raise ValueError('unsupported source container')
            version=header[4];bits=128 if header[5]&15==1 else 256
            if len(old_key)*8!=bits:raise ValueError('source key width does not match container')
            reader=HashedReader(raw,max_source_bytes)
            if version==1 and allow_v1:chunks=legacy_chunks(reader,bits,old_key,legacy_record_limit)
            elif version==2:chunks=q._decrypt_chunks(bits,old_key,reader)
            else:raise ValueError('v1 needs explicit recovery acknowledgement; unknown versions rejected')
            plaintext_hash=hashlib.sha256();plaintext_bytes=0
            def verified_chunks():
                nonlocal plaintext_bytes
                for chunk in chunks:
                    plaintext_bytes+=len(chunk)
                    if plaintext_bytes>trusted_plaintext_bytes:raise ValueError('plaintext length exceeds trusted evidence')
                    plaintext_hash.update(chunk);yield chunk
                if (reader.hash.hexdigest()!=trusted_container_hash or plaintext_hash.hexdigest()!=trusted_plaintext_hash
                        or plaintext_bytes!=trusted_plaintext_bytes):
                    raise ValueError('trusted whole-file/plaintext evidence does not match')
            staging=Path(tempfile.mkdtemp(prefix='.n2q-migrate-',dir=destination.parent))
            encrypted=staging/'data.n2qf';output_hash=hashlib.sha256()
            with encrypted.open('xb') as output:
                os.fchmod(output.fileno(),0o600)
                for block in q._encrypt_chunks(len(new_key)*8,q.SECURE,new_key,verified_chunks()):
                    output.write(block);output_hash.update(block)
                output.flush();os.fsync(output.fileno())
        # Verify the actual staged v2 file under the new key before publication.
        digest=hashlib.sha256();count=0
        with encrypted.open('rb') as check:
            check_reader=HashedReader(check,encrypted.stat().st_size+1)
            for chunk in q._decrypt_chunks(len(new_key)*8,new_key,check_reader):digest.update(chunk);count+=len(chunk)
        if digest.hexdigest()!=trusted_plaintext_hash or count!=trusted_plaintext_bytes:
            raise ValueError('new v2 read-back verification failed')
        if check_reader.hash.hexdigest()!=output_hash.hexdigest():raise ValueError('new ciphertext changed during verification')
        report=dict(schema=1,input_version=version,output_version=2,source_key_bits=bits,
                    output_key_bits=len(new_key)*8,output_profile='Secure',source_key_algorithm=old_algorithm['algorithm'],
                    output_key_algorithm=new_algorithm['algorithm'],output_kdf=new_algorithm,trusted_container_sha256=trusted_container_hash,
                    trusted_plaintext_sha256=trusted_plaintext_hash,plaintext_bytes=plaintext_bytes,
                    output_container_sha256=output_hash.hexdigest(),
                    evidence_note='Caller supplied independent trusted hashes/length; not established by this tool.')
        with (staging/'migration.json').open('x') as output:
            os.fchmod(output.fileno(),0o600);json.dump(report,output,sort_keys=True,indent=2)
            output.flush();os.fsync(output.fileno())
        sync_dir(staging);rename_new_directory(staging,destination);staging=None;sync_dir(destination.parent)
        return report
    finally:
        if staging is not None and staging.exists():shutil.rmtree(staging)


def inventory(directory,max_bytes=DEFAULT_LIMIT):
    result=[]
    for path in sorted(Path(directory).rglob('*')):
        if not stat.S_ISREG(path.lstat().st_mode):continue
        with open_regular(path) as source:
            header=source.read(6)
            if header[:4]!=b'N2QF':
                if header.startswith(b'{') and path.stat().st_size<=4096:
                    try:
                        bundle=json.loads(header+source.read(4091),object_pairs_hook=unique_object)
                        if (isinstance(bundle,dict) and bundle.get('format')=='n2q-offline-key-v1'
                                and bundle.get('algorithm') in ('argon2id-v19','legacy-n2q-pw-v1')):
                            result.append(dict(path=str(path),kind='private-key-metadata',algorithm=bundle['algorithm'],
                                               key_bits=bundle.get('key_bits') if bundle.get('key_bits') in (128,256) else None,
                                               status='metadata only; secret key omitted'))
                    except (ValueError,UnicodeError):pass
                continue
            info=dict(path=str(path),bytes=path.stat().st_size,version=header[4] if len(header)>4 else None)
            if len(header)==6:
                info['suite_hex']='%02x'%header[5]
                info['key_bits']=128 if header[5] in (1,0x21) else 256 if header[5] in (2,0x22) else None
                info['profile']='Fast' if header[5] in (0x21,0x22) else 'Secure' if header[5] in (1,2) else 'unknown'
            if info['bytes']>max_bytes:info['status']='over-budget'
            else:
                digest=hashlib.sha256(header);total=len(header);over=False
                while True:
                    block=source.read(65536)
                    if not block:break
                    total+=len(block)
                    if total>max_bytes:over=True;break
                    digest.update(block)
                if over:info['status']='over-budget'
                else:info.update(observed_sha256=digest.hexdigest(),status='untrusted observation')
            result.append(info)
    return dict(schema=1,files=result,warning='Observed hashes do not establish authenticity or completeness.')


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    scan=sub.add_parser('inventory');scan.add_argument('directory',type=Path)
    run=sub.add_parser('migrate')
    for name in ['source','destination','old-key-file','new-key-file','trusted-container-sha256','trusted-plaintext-sha256']:
        run.add_argument('--'+name,required=True)
    run.add_argument('--trusted-plaintext-bytes',type=int,required=True)
    run.add_argument('--allow-v1-recovery',action='store_true')
    run.add_argument('--max-source-bytes',type=int,default=DEFAULT_LIMIT)
    run.add_argument('--legacy-record-limit',type=int,default=65536)
    args=parser.parse_args()
    if args.command=='inventory':print(json.dumps(inventory(args.directory),indent=2))
    else:
        report=migrate(args.source,args.destination,args.old_key_file,args.new_key_file,
                       args.trusted_container_sha256,args.trusted_plaintext_sha256,args.trusted_plaintext_bytes,
                       args.allow_v1_recovery,args.max_source_bytes,args.legacy_record_limit)
        print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError) as error:
        print('Offline migration failed: '+str(error),file=sys.stderr);sys.exit(1)
