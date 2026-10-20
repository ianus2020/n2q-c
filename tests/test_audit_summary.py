"""Incomplete or inconsistent dependency evidence must never report success."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CARGO = ('native', 'wasm', 'fuzz', 'bench', 'cryptanalysis')


class AuditSummary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.cargo = {
            'database': {'advisory-count': 1, 'last-commit': '0' * 40,
                         'last-updated': '2026-10-20T00:00:00Z'},
            'vulnerabilities': {'found': False, 'count': 0, 'list': []},
            'warnings': {},
        }
        self.npm = {'auditReportVersion': 2, 'vulnerabilities': {}, 'metadata': {
            'vulnerabilities': dict(info=0, low=0, moderate=0, high=0, critical=0, total=0)}}
        for name in CARGO:
            self.write(name + '.json', self.cargo)
        self.write('npm.json', self.npm)
        self.write('gitleaks.json', [])

    def write(self, name, report):
        (self.directory / name).write_text(json.dumps(report), encoding='utf-8')

    def run_summary(self):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/audit-summary.py'),
                               str(self.directory)], capture_output=True, text=True, timeout=10)

    def assert_rejected(self, filename):
        result = self.run_summary()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(filename, result.stdout + result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        return result

    def test_complete_clean_reports_pass(self):
        result = self.run_summary()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in CARGO:
            self.assertIn(name + '.json', result.stdout)
        self.assertIn('npm totals:', result.stdout)
        self.assertIn('gitleaks history findings: 0', result.stdout)

    def test_each_required_report_is_mandatory(self):
        for name in [*(name + '.json' for name in CARGO), 'npm.json', 'gitleaks.json']:
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                path.unlink()
                try:
                    self.assert_rejected(name)
                finally:
                    path.write_bytes(original)

    def test_malformed_duplicate_and_invalid_utf8_json_are_rejected(self):
        for raw in [b'{', b'{"vulnerabilities":{},"vulnerabilities":{}}', b'\xff', b'{"value":NaN}']:
            with self.subTest(raw=repr(raw)):
                (self.directory / 'native.json').write_bytes(raw)
                self.assert_rejected('native.json')

    def test_cargo_boolean_count_and_inconsistent_counts_are_rejected(self):
        for vulnerability in [
            {'found': False, 'count': False, 'list': []},
            {'found': True, 'count': 0, 'list': []},
            {'found': False, 'count': 1, 'list': []},
        ]:
            with self.subTest(vulnerability=vulnerability):
                report = copy.deepcopy(self.cargo)
                report['vulnerabilities'] = vulnerability
                self.write('native.json', report)
                self.assert_rejected('native.json')

    def test_empty_objects_and_wrong_top_level_shapes_are_rejected(self):
        for name, invalid in [('native.json', {}), ('wasm.json', []),
                              ('npm.json', {}), ('gitleaks.json', {})]:
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                self.write(name, invalid)
                try:
                    self.assert_rejected(name)
                finally:
                    path.write_bytes(original)

    def test_npm_error_and_inconsistent_totals_are_rejected(self):
        reports = []
        report = copy.deepcopy(self.npm)
        report['error'] = {'code': 'FIXTURE_UNAVAILABLE'}
        reports.append(report)
        report = copy.deepcopy(self.npm)
        report['metadata']['vulnerabilities']['total'] = 1
        reports.append(report)
        report = copy.deepcopy(self.npm)
        report['vulnerabilities']['fixture-package'] = {'severity': 'high', 'fixAvailable': False}
        reports.append(report)
        for report in reports:
            with self.subTest(report=report):
                self.write('npm.json', report)
                self.assert_rejected('npm.json')

    def test_findings_fail_and_secret_fields_are_not_printed(self):
        cases = []
        report = copy.deepcopy(self.cargo)
        report['vulnerabilities'] = {'found': True, 'count': 1, 'list': [{
            'advisory': {'id': 'FIXTURE-ADVISORY', 'title': 'synthetic advisory'},
            'package': {'name': 'fixture-package', 'version': '1.0.0'}}]}
        cases.append(('native.json', report, 'FIXTURE-ADVISORY'))
        report = copy.deepcopy(self.npm)
        report['vulnerabilities']['fixture-package'] = {'severity': 'high', 'fixAvailable': False}
        report['metadata']['vulnerabilities'].update(high=1, total=1)
        cases.append(('npm.json', report, 'fixture-package'))
        cases.append(('gitleaks.json', [{'RuleID': 'fixture-rule', 'File': 'fixture.txt',
            'StartLine': 1, 'Commit': '0' * 40, 'Secret': 'PRIVATE_MARKER_NEVER_PRINT'}],
            'gitleaks history findings: 1'))
        for name, report, expected in cases:
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                self.write(name, report)
                try:
                    result = self.run_summary()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stdout)
                    self.assertNotIn('PRIVATE_MARKER_NEVER_PRINT', result.stdout + result.stderr)
                finally:
                    path.write_bytes(original)

    def test_reports_are_checked_after_an_error(self):
        (self.directory / 'bench.json').unlink()
        self.write('npm.json', {})
        result = self.assert_rejected('bench.json')
        self.assertIn('npm.json', result.stdout + result.stderr)
        self.assertIn('wasm.json', result.stdout)

    def test_full_driver_rejects_invalid_reports_even_if_tools_exit_zero(self):
        sandbox = self.directory / 'driver'
        (sandbox / 'scripts').mkdir(parents=True)
        for name in ['dependency-audit.sh', 'audit-summary.py']:
            shutil.copyfile(ROOT / 'scripts' / name, sandbox / 'scripts' / name)
        binary = sandbox / 'bin'
        binary.mkdir()
        (binary / 'python3').symlink_to(sys.executable)
        stub = '''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
fixtures=Path(os.environ['N2Q_PUBLIC_AUDIT_FIXTURES'])
name=Path(sys.argv[0]).name
if name=='gitleaks':
    Path(sys.argv[sys.argv.index('--report-path')+1]).write_bytes((fixtures/'gitleaks.json').read_bytes())
else:
    print((fixtures/('native.json' if name=='cargo' else 'npm.json')).read_text())
'''
        for name in ['cargo', 'gitleaks', 'npm']:
            path = binary / name
            path.write_text(stub)
            path.chmod(0o700)
        environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.defpath,
                           N2Q_PUBLIC_AUDIT_FIXTURES=str(self.directory))
        for invalid in (False, True):
            with self.subTest(invalid=invalid):
                if invalid:
                    (self.directory / 'native.json').write_text('{')
                result = subprocess.run(['/bin/sh', str(sandbox / 'scripts/dependency-audit.sh'),
                                         str(sandbox / ('invalid' if invalid else 'clean'))],
                                        capture_output=True, text=True, env=environment, timeout=15)
                self.assertEqual(result.returncode, 1 if invalid else 0, result.stdout + result.stderr)
                if invalid:
                    self.assertIn('Dependency audit failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
