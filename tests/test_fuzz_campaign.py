"""Exercise report integrity, deadlines and process cleanup with controlled children."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORTER = Path(os.environ.get('N2Q_TEST_REPORTER', ROOT/'scripts/fuzz-campaign.py'))
FAKE = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
mode = os.environ['N2Q_TEST_MODE']
if mode in ('checkpoint', 'orphan', 'stubborn'):
    child = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
    Path('children.json').write_text(json.dumps([os.getpid(), child.pid]))
    if mode != 'orphan': signal.signal(signal.SIGTERM, signal.SIG_IGN)
targets = ['c/fireline','c/n2qf','c/siv','c/modes_roundtrip','c/convergent','rust/frames','rust/n2qf']
for index, name in enumerate(targets):
    print('N2Q_FUZZ_TARGET '+name, flush=True)
    if (mode == 'checkpoint' and index == 1) or mode == 'stubborn': time.sleep(60)
    print('#1 DONE cov: 1', flush=True)
    print('Done 1 runs in 0 second(s)', flush=True)
    for variant in range(8 if name == 'c/modes_roundtrip' else 2 if name == 'c/convergent' else 0):
        print('N2Q_FUZZ_VARIANT %d 1'%variant, flush=True)
    if mode == 'incomplete': break
if mode == 'diagnostic' or (mode == 'series-fail' and os.environ['N2Q_FUZZ_SEED'] == '2'):
    print('fixture.c:1: runtime error: signed integer overflow', flush=True)
if mode == 'source-change': Path('impl/c/input.c').write_text('changed\n')
'''


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='n2q-campaign-controls-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('scripts', 'impl/c', 'bin'):
            (self.root/name).mkdir(parents=True)
        (self.root/'impl/c/input.c').write_text('/* synthetic fixture */\n')
        fake = self.root/'scripts/fuzz-smoke.sh'
        fake.write_text('#!'+sys.executable+'\n'+FAKE)
        fake.chmod(0o700)
        for tool in ('clang', 'rustc', 'cargo'):
            path = self.root/'bin'/tool
            path.write_text('#!/bin/sh\nprintf "controlled version\\n"\n')
            path.chmod(0o700)
        for args in (['init','-q'], ['add','.'], ['-c','user.name=Fixture',
                     '-c','user.email=fixture@invalid.local','commit','-qm','Synthetic fixture']):
            subprocess.run(['git',*args], cwd=self.root, check=True, capture_output=True)
        self.env = dict(os.environ, PATH=str(self.root/'bin')+os.pathsep+os.environ['PATH'])
        self.env.pop('N2Q_SOURCE_COMMIT', None)
        self.processes = []
        self.addCleanup(self.cleanup_children)

    def cleanup_children(self):
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        path = self.root/'children.json'
        if path.exists():
            pid = json.loads(path.read_text())[0]
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError: pass

    def launch(self, mode='pass', extra=(), series=False):
        path = ROOT/'scripts/fuzz-series.py' if series else REPORTER
        launcher = ('import importlib.util,sys; from pathlib import Path; '
                    's=importlib.util.spec_from_file_location("fixture_runner",sys.argv[1]); '
                    'm=importlib.util.module_from_spec(s);s.loader.exec_module(m); '
                    'setattr(m.campaign if hasattr(m,"campaign") else m,"ROOT",Path(sys.argv[2])); '
                    'sys.argv=[sys.argv[1],*sys.argv[3:]];sys.exit(m.main())')
        env = dict(self.env, N2Q_TEST_MODE=mode)
        proc = subprocess.Popen([sys.executable,'-c',launcher,str(path),str(self.root),
                                 '--output',str(self.root/'output'),*extra], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        return proc

    def wait_json(self, name, predicate=lambda value: True):
        deadline = time.monotonic()+10
        path = self.root/name
        while time.monotonic()<deadline:
            try:
                value = json.loads(path.read_text())
                if predicate(value): return value
            except FileNotFoundError: pass
            time.sleep(0.02)
        self.fail('Checkpoint was not written: '+name)

    def assert_children_stopped(self):
        pids = json.loads((self.root/'children.json').read_text())
        deadline = time.monotonic()+3
        alive = pids
        while time.monotonic()<deadline:
            alive = []
            for pid in pids:
                result = subprocess.run(['ps','-o','stat=','-p',str(pid)], capture_output=True,text=True)
                if result.returncode==0 and result.stdout.strip() and not result.stdout.lstrip().startswith('Z'):
                    alive.append(pid)
            if not alive: return
            time.sleep(0.02)
        self.fail('Fixture descendants are still running: '+str(alive))

    def test_checkpoint_and_sigterm_cleanup(self):
        proc = self.launch('checkpoint')
        self.wait_json('children.json')
        # Old versions write only their initial status, without parsed targets.
        if not os.environ.get('N2Q_TEST_REPORTER'):
            running = self.wait_json('output/summary.json',lambda r: len(r.get('targets',[]))==2)
            self.assertEqual(running['status'],'running')
            self.assertEqual(running['targets'][0]['runs'],1)
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=12),130)
        report = json.loads((self.root/'output/summary.json').read_text())
        self.assertEqual(report['status'],'interrupted')
        self.assertEqual(report['received_signal'],signal.SIGTERM)
        self.assert_children_stopped()

    def test_deadline_kills_stubborn_process_group(self):
        proc = self.launch('stubborn', ('--wall-seconds','1'))
        self.assertEqual(proc.wait(timeout=15),124)
        report = json.loads((self.root/'output/summary.json').read_text())
        self.assertEqual(report['status'],'timed_out')
        self.assertTrue(report['deadline_exceeded'])
        self.assert_children_stopped()

    def test_exited_wrapper_with_open_descendant_is_not_passed(self):
        proc = self.launch('orphan', ('--wall-seconds','1'))
        self.assertEqual(proc.wait(timeout=15),124)
        report = json.loads((self.root/'output/summary.json').read_text())
        self.assertEqual(report['returncode'],0)
        self.assertEqual(report['status'],'timed_out')
        self.assert_children_stopped()

    def test_complete_and_private_evidence(self):
        self.assertEqual(self.launch().wait(timeout=10),0)
        path=self.root/'output/summary.json'
        report=json.loads(path.read_text())
        self.assertEqual(report['status'],'passed')
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertEqual(len(report['targets']),7)

    def test_fail_closed_for_diagnostic_missing_target_or_source_change(self):
        for mode in ('diagnostic','incomplete','source-change'):
            with self.subTest(mode=mode):
                proc = self.launch(mode)
                self.assertEqual(proc.wait(timeout=10),1)
                report=json.loads((self.root/'output/summary.json').read_text())
                self.assertEqual(report['status'],'failed')
                # Next case gets a new immutable evidence directory.
                (self.root/'output').rename(self.root/('result-'+mode))

    def test_series_stops_at_failed_seed(self):
        proc=self.launch('series-fail', ('--seeds','1','2','3'), series=True)
        self.assertEqual(proc.wait(timeout=15),1)
        report=json.loads((self.root/'output/series.json').read_text())
        self.assertEqual(report['status'],'failed')
        self.assertEqual([r['seed'] for r in report['campaigns']],[1,2])
        self.assertEqual([r['status'] for r in report['campaigns']],['passed','failed'])
        self.assertFalse((self.root/'output/seed-3').exists())

    def test_series_completes_every_planned_seed(self):
        proc=self.launch('pass', ('--seeds','1','2'), series=True)
        self.assertEqual(proc.wait(timeout=15),0)
        report=json.loads((self.root/'output/series.json').read_text())
        self.assertEqual(report['status'],'passed')
        self.assertEqual([r['seed'] for r in report['campaigns']],[1,2])
        self.assertEqual([r['status'] for r in report['campaigns']],['passed','passed'])

    def test_series_reports_interruption(self):
        proc=self.launch('checkpoint', ('--seeds','1','2'), series=True)
        self.wait_json('children.json')
        self.wait_json('output/seed-1/summary.json',lambda r: len(r.get('targets',[]))==2)
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=12),130)
        report=json.loads((self.root/'output/series.json').read_text())
        self.assertEqual(report['status'],'interrupted')
        self.assertEqual(len(report['campaigns']),1)
        self.assert_children_stopped()


if __name__ == '__main__':
    unittest.main()
