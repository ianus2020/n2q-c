"""The public CI evidence must preserve failures and exclude ambient secrets."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location("n2q_evidence",Path(__file__).resolve().parents[1]/"scripts/verification-record.py")
evidence=importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
class EvidenceTests(unittest.TestCase):
    def test_failures_and_no_environment_dump(self):
        with mock.patch.object(Path,"read_bytes",return_value=b"fixture"), \
             mock.patch.object(Path,"exists",return_value=False), \
             mock.patch.object(subprocess,"run",return_value=subprocess.CompletedProcess([],0,"fixture tool")), \
             mock.patch.object(evidence.platform,"platform",return_value="fixture platform"), \
             mock.patch.dict(os.environ,{"TEST_SECRET_NEVER_RECORD":"private-test-marker","N2Q_VERIFICATION_STATUS":"failure","N2Q_SOURCE_COMMIT":"public-source-id"}):
            data=evidence.record("native")
        self.assertEqual(data["ci_status"],"failure")
        self.assertEqual(data["source_commit"],"public-source-id")
        self.assertNotIn("private-test-marker",json.dumps(data))
        self.assertNotIn("rust-fuzz",data["tools"])
        self.assertIn("impl/conformance/vectors.txt",data["input_sha256"])
        self.assertIn("tools/local_stand/pki.py",data["input_sha256"])
        self.assertIn("python-ssl",data["tools"])
        self.assertIn("openssl",data["tools"])
        self.assertTrue(all(len(v)==64 for v in data["input_sha256"].values()))
    def test_unavailable_version_tool_is_recorded(self):
        with mock.patch.object(subprocess,"run",side_effect=FileNotFoundError()):
            self.assertEqual(evidence.version(["missing-tool","--version"]),{"available":False})
