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
        subprocess.run(['openssl',*args],cwd=str(directory),check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def key(name):
        run('ecparam','-name','prime256v1','-genkey','-noout','-out',name+'.key')
        os.chmod(directory/(name+'.key'),0o600)
    key('ca')
    run('req','-new','-x509','-sha256','-days','2','-key','ca.key','-subj','/CN=N2Q LOCAL TEST CA',
        '-out','ca.pem','-addext','basicConstraints=critical,CA:TRUE',
        '-addext','keyUsage=critical,keyCertSign,cRLSign')
    for number,name in enumerate(['server','client','unlisted'],2):
        key(name)
        run('req','-new','-sha256','-key',name+'.key','-subj','/CN=N2Q LOCAL '+name,'-out',name+'.csr')
        ext = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
        if name == 'server':
            ext += 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
        else:
            ext += 'extendedKeyUsage=clientAuth\n'
        (directory/(name+'.ext')).write_text(ext)
        run('x509','-req','-sha256','-days','2','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key',
            '-set_serial',str(number),'-extfile',name+'.ext','-out',name+'.pem')
    return directory
