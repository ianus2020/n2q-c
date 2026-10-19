"""Run after building native CLIs; see scripts/check.sh and docs/security-fixes.md."""
import io, os, shlex, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'impl/python'))
import n2qc as q
commands={name:shlex.split(os.environ['N2Q_'+name.upper()]) for name in ('c','rust','go','php','swift') if os.environ.get('N2Q_'+name.upper())}
assert commands, 'set N2Q_C, N2Q_RUST, N2Q_GO, N2Q_PHP and/or N2Q_SWIFT'
# Keep paths inside the checkout so container-based CLIs can mount the same path.
with tempfile.TemporaryDirectory(prefix='.interop-',dir=ROOT) as d:
    d=Path(d); key=d/'key';key.write_bytes(bytes(range(16)));source=d/'source';out=d/'out'
    def run(name,op,src,dst,ok=True):
        if name=='python':
            try:
                if op=='encrypt':q.encrypt_file(128,q.SECURE,key.read_bytes(),src,dst)
                else:q.decrypt_file(128,key.read_bytes(),src,dst)
                success=True
            except (ValueError,OSError):success=False
        else:
            p=subprocess.run(commands[name]+[op,str(key),str(src),str(dst)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            success=p.returncode==0
            if success!=ok:raise AssertionError((name,op,p.stderr.decode(errors='replace')))
        assert success==ok,(name,op)
    names=['python']+list(commands)
    for payload in (b'',bytes(range(256))*256+b'!'):
        source.write_bytes(payload)
        for writer in names:
            enc=d/('enc-'+writer);run(writer,'encrypt',source,enc)
            for reader in names:
                run(reader,'decrypt',enc,out);assert out.read_bytes()==payload,(writer,reader)
            # All ports reject framing attacks and preserve existing output.
            buf=enc.read_bytes();bad=d/'bad'
            attacks=[buf[:-1],buf[:22],buf+b'x',b'N2QF\1'+buf[5:],buf[:23]+b'\xff'*4+buf[27:]]
            if payload:
                boundary=22+5+16+65536
                attacks.append(buf[:boundary])
            for attack in attacks:
                bad.write_bytes(attack)
                # Readers exercised once per payload; writers independently round-trip above.
                if writer!='python':continue
                for reader in names:
                    out.write_bytes(b'keep');run(reader,'decrypt',bad,out,False);assert out.read_bytes()==b'keep',reader
    # Input/output IO failures and in-place replacement exercise the staged path.
    for name in names:
        out.write_bytes(b'keep')
        run(name,'encrypt',d/'missing-input',out,False)
        assert out.read_bytes()==b'keep',name
        run(name,'encrypt',source,d,False) # destination is an existing directory
        same=d/'same';same.write_bytes(b'in-place payload')
        run(name,'encrypt',same,same)
        assert same.stat().st_mode & 0o077 == 0,(name,'output permissions')
        run(name,'decrypt',same,same)
        assert same.read_bytes()==b'in-place payload',name
    if 'c' in commands or 'go' in commands:
        key.write_bytes(bytes(range(32)))
        for profile in (q.SECURE,q.FAST):
            q.encrypt_file(256,profile,key.read_bytes(),source,d/'256')
            for reader in ('c','go'):
                if reader in commands:
                    run(reader,'decrypt',d/'256',out);assert out.read_bytes()==source.read_bytes()
    assert not list(d.glob('*.n2q-*')) and not list(d.glob('.n2q-*'))
print('File interop + malformed input + atomic output PASS:', ', '.join(names))
