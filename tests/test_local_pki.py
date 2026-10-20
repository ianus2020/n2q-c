"""Generated test trust must be independent of ambient openssl.cnf extensions."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.local_stand.pki import create


class LocalPKI(unittest.TestCase):
    def test_ambient_ca_extensions_cannot_override_test_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ambient = root/'ambient.cnf'
            ambient.write_text('''[req]
distinguished_name=dn
x509_extensions=ambient
[dn]
CN=Ambient CA
[ambient]
basicConstraints=critical,CA:TRUE
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:.invalid.example
''')
            with mock.patch.dict(os.environ, {'OPENSSL_CONF':str(ambient)}):
                pki = create(root/'pki')
                certificate = subprocess.check_output(
                    ['openssl','x509','-in',str(pki/'ca.pem'),'-noout','-text'], text=True)
            self.assertEqual(certificate.count('X509v3 Basic Constraints:'), 1)
            self.assertEqual(certificate.count('X509v3 Subject Key Identifier:'), 1)
            self.assertNotIn('X509v3 Name Constraints:', certificate)
            self.assertEqual((pki/'ca.key').stat().st_mode & 0o077, 0)
            for name, purpose in [('server','sslserver'),('client','sslclient'),('unlisted','sslclient')]:
                subprocess.run(['openssl','verify','-x509_strict','-purpose',purpose,
                                '-CAfile',str(pki/'ca.pem'),str(pki/(name+'.pem'))],
                               check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
