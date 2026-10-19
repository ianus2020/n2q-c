"""Start a loopback stand with ephemeral TEST PKI and a PUBLIC signing fixture."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.local_stand.pki import create, fingerprint
from tools.local_stand.web import publish
from tools.anchor.server import initialize, private_path


def prepare(state,web_port,anchor_port):
    state.mkdir(mode=0o700)  # Never silently reset an existing identity or database.
    pki = create(state/'pki')
    for folder in ['anchor','signer','bin']:(state/folder).mkdir(mode=0o700)
    client = state/'bin/public-test-client'
    subprocess.run(['cc','-O2','-pthread',str(ROOT/'tests/anchor_http_client.c'),
                    str(ROOT/'impl/c/n2q_cone_anchor_http.c'),'-lcurl','-o',str(client)],check=True)
    journal = state/'signer/public-test-journal'
    key_id = subprocess.check_output([str(client),'create',str(journal)],text=True).strip()
    database = state/'anchor/state.sqlite';initialize(database)
    config = dict(database=str(database),port=anchor_port,cert=str(pki/'server.pem'),key=str(pki/'server.key'),
                  ca=str(pki/'ca.pem'),permissions={fingerprint(pki/'client.pem'):[key_id]})
    anchor_config = state/'anchor/config.json';anchor_config.write_text(json.dumps(config,indent=2));anchor_config.chmod(0o600)
    release = publish(ROOT/'impl/n2q-c-wasm/web',state/'web')
    info = dict(version=1,web_port=web_port,anchor_port=anchor_port,release=release,
                public_test_seed=True,anchor_config=str(anchor_config),state=str(state))
    (state/'stand.json').write_text(json.dumps(info,indent=2));(state/'stand.json').chmod(0o600)
    return info


def start(info,check=False):
    state = Path(info['state']);pki = state/'pki'
    commands = [[sys.executable,str(ROOT/'tools/anchor/server.py'),'serve','--config',info['anchor_config']],
                [sys.executable,str(ROOT/'tools/local_stand/web.py'),'serve','--directory',str(state/'web'),
                 '--cert',str(pki/'server.pem'),'--key',str(pki/'server.key'),'--port',str(info['web_port'])]]
    processes = []
    context = ssl.create_default_context(cafile=str(pki/'ca.pem'))
    url = 'https://localhost:%s/'%info['web_port']
    try:
        for command in commands:processes.append(subprocess.Popen(command))
        for _ in range(100):
            if any(p.poll() is not None for p in processes):raise RuntimeError('stand service stopped')
            try:
                with urllib.request.urlopen(url,context=context,timeout=2) as response:
                    if response.status == 200:break
            except (OSError,urllib.error.URLError):time.sleep(0.05)
        else:raise RuntimeError('stand startup timed out')
        print('LOCAL TEST STAND (PUBLIC FIXTURE SEED; synthetic data only)',flush=True)
        print('Web: '+url,flush=True)
        print('CA for explicit test trust: '+str(pki/'ca.pem'),flush=True)
        print('Release: '+info['release'],flush=True)
        if check:
            subprocess.run([str(state/'bin/public-test-client'),
                            'https://localhost:%s/v1/reserve'%info['anchor_port'],str(pki/'ca.pem'),
                            str(pki/'client.pem'),str(pki/'client.key'),str(state/'signer/public-test-journal'),
                            'PUBLIC_TEST_SEED'],check=True)
            print('HTTPS + mTLS C signer check PASS',flush=True)
        else:
            while all(p.poll() is None for p in processes):time.sleep(0.25)
            raise RuntimeError('stand service stopped')
    finally:
        for p in processes:
            if p.poll() is None:p.terminate()
        for p in processes:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--web-port',type=int,default=9443)
    parser.add_argument('--anchor-port',type=int,default=9444)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if not 1 <= args.web_port <= 65535 or not 1 <= args.anchor_port <= 65535:
        parser.error('ports must be in 1..65535')
    if args.web_port == args.anchor_port:parser.error('ports must be different')
    state = args.state.absolute()
    if args.resume:
        private_path(state,directory=True);private_path(state/'stand.json')
    info = json.loads((state/'stand.json').read_text()) if args.resume else prepare(state,args.web_port,args.anchor_port)
    if info['state'] != str(state):raise ValueError('stand location does not match its record')
    lock = os.open(state/'stand.lock',os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:start(info,args.check)
        except KeyboardInterrupt:pass
    finally:os.close(lock)
