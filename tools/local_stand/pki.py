"""Generate ephemeral local-test PKI. Never install its CA in the OS trust store."""
import hashlib
import os
import pathlib
import ssl
import subprocess


def fingerprint(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pathlib.Path(path).read_text())).hexdigest()


def create(directory):
    directory = pathlib.Path(directory).absolute()
    directory.mkdir(mode=0o700)  # exclusive: never overwrite an existing PKI
    def run(*args):
        try:
            subprocess.run(['openssl',*args],cwd=str(directory),check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            raise RuntimeError('local TEST PKI command failed: '+error.stderr.decode(errors='replace')) from error
    def key(name):
        run('ecparam','-name','prime256v1','-genkey','-noout','-out',name+'.key')
        os.chmod(directory/(name+'.key'),0o600)
    key('ca')
    # OpenSSL 1.1.1 appends -addext to ambient x509_extensions, producing
    # duplicate CA/SKI extensions with common openssl.cnf defaults. Use one
    # complete configuration instead, including for CSRs, so the host cannot
    # silently inject constraints or extensions into these test identities.
    (directory/'ca.cnf').write_text('''[req]
distinguished_name=dn
prompt=no
x509_extensions=ca
[dn]
CN=N2Q LOCAL TEST CA
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
''')
    run('req','-new','-x509','-sha256','-days','2','-key','ca.key',
        '-config','ca.cnf','-extensions','ca','-out','ca.pem')
    run('verify','-x509_strict','-CAfile','ca.pem','ca.pem')
    for number,name in enumerate(['server','client','unlisted'],2):
        key(name)
        run('req','-new','-sha256','-key',name+'.key','-config','ca.cnf',
            '-subj','/CN=N2Q LOCAL '+name,'-out',name+'.csr')
        ext = ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
               'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        if name == 'server':
            ext += 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
        else:
            ext += 'extendedKeyUsage=clientAuth\n'
        (directory/(name+'.ext')).write_text(ext)
        run('x509','-req','-sha256','-days','2','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key',
            '-set_serial',str(number),'-extfile',name+'.ext','-out',name+'.pem')
        run('verify','-x509_strict','-purpose','sslserver' if name == 'server' else 'sslclient',
            '-CAfile','ca.pem',name+'.pem')
    return directory
