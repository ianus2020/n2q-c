#!/usr/bin/env python3
"""Run a bounded synthetic campaign and retain actual counts, logs and inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {'c/fireline', 'c/n2qf', 'c/siv', 'c/modes_roundtrip', 'c/convergent',
           'rust/frames', 'rust/n2qf'}


def parse_log(log):
    targets, current = [], None
    diagnostics = False
    for line in log.splitlines():
        if line.startswith('N2Q_FUZZ_TARGET '):
            name = line.split(maxsplit=1)[1]
            if name not in TARGETS or any(t['name'] == name for t in targets):
                raise ValueError('unknown or duplicate fuzz target marker')
            current = {'name':name, 'runs':None, 'seconds':None, 'coverage_edges':None, 'peak_rss_mb':None,
                       'completed_crypto_cases':{}}
            targets.append(current)
        if any(marker in line for marker in ('ERROR: AddressSanitizer', 'runtime error:',
                                             'SUMMARY: UndefinedBehaviorSanitizer', 'ERROR: libFuzzer')):
            diagnostics = True
        if current is None:
            continue
        match = re.search(r'Done (\d+) runs in (\d+) second', line)
        if match:
            if current['runs'] is not None:
                raise ValueError('duplicate final run count')
            current.update(runs=int(match[1]), seconds=int(match[2]))
        match = re.search(r'#\d+\s+DONE\s+cov:\s*(\d+)', line)
        if match:
            current['coverage_edges'] = int(match[1])
        match = re.search(r'stat::peak_rss_mb:\s*(\d+)', line)
        if match:
            current['peak_rss_mb'] = int(match[1])
        match = re.fullmatch(r'N2Q_FUZZ_VARIANT (\d+) (\d+)', line)
        if match:
            variant = match[1]
            if variant in current['completed_crypto_cases']:
                raise ValueError('duplicate crypto case counter')
            current['completed_crypto_cases'][variant] = int(match[2])
    complete = {t['name'] for t in targets} == TARGETS and all(t['runs'] is not None and t['runs'] > 0 for t in targets)
    for target in targets:
        count = 8 if target['name'] == 'c/modes_roundtrip' else 2 if target['name'] == 'c/convergent' else 0
        if count:
            complete = complete and set(target['completed_crypto_cases']) == {str(i) for i in range(count)} and all(
                value > 0 for value in target['completed_crypto_cases'].values())
    return {'targets':targets, 'complete':complete, 'sanitizer_or_fuzzer_diagnostic':diagnostics}


def version(command):
    try:
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
        return {'exit_code':run.returncode, 'text':run.stdout.strip()[:400]}
    except (OSError, subprocess.TimeoutExpired):
        return {'available':False}


def inputs():
    paths = subprocess.check_output(['git','ls-files','-z','impl/c','impl/python','impl/n2q-c-ref','fuzz',
                                     'scripts','tests/sanitizer_probe.c','.gitignore',
                                     '.github/workflows/security.yml'], cwd=ROOT).decode().split('\0')
    result = []
    for name in sorted(filter(None, paths)):
        path = ROOT/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('fuzz source input must be a regular file: '+name)
        result.append({'path':name, 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    return result


def archive_corpus(output, name):
    corpus = ROOT/'fuzz/corpus'
    files = []
    for path in sorted(corpus.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink in synthetic fuzz corpus')
        if path.is_file():
            files.append(path)
    if not files:
        return {'files':0, 'bytes':0, 'archive':None}
    with tarfile.open(output/name, 'w:gz') as archive:
        for path in files:
            archive.add(path, arcname=str(path.relative_to(corpus)), recursive=False)
    return {'files':len(files), 'bytes':sum(path.stat().st_size for path in files),
            'archive':name, 'sha256':hashlib.sha256((output/name).read_bytes()).hexdigest()}


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('budget must be positive')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=positive, default=1000000)
    parser.add_argument('--seconds', type=positive, default=180)
    parser.add_argument('--seed', type=positive, default=20261019)
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True)  # Refuse an existing evidence directory.
    toolchain = os.environ.get('N2Q_FUZZ_TOOLCHAIN', 'nightly-2026-10-18')
    source = os.environ.get('N2Q_SOURCE_COMMIT') or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if re.fullmatch('[0-9a-f]{40}', source) is None:
        raise ValueError('source commit must be a full Git SHA')
    report = {'schema':1, 'source_commit':source, 'checkout_commit':subprocess.check_output(
              ['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(), 'platform':platform.platform(),
              'budget':{'runs_per_target':args.runs, 'seconds_per_target':args.seconds,
                        'seed':args.seed, 'max_input_bytes':4096, 'rss_limit_mb':512, 'input_timeout_seconds':5},
              'tools':{'clang':version(['clang','--version']), 'rust':version(['rustc','+'+toolchain,'--version']),
                       'cargo-fuzz':version(['cargo','+1.96.1','fuzz','--version'])},
              'inputs':inputs(), 'status':'running',
              'initial_corpus':archive_corpus(args.output, 'initial-corpus.tar.gz'),
              'limitations':['Bounded implementation fuzzing, not cryptographic security proof.',
                             'Coverage edges depend on compiler/instrumentation and are not path coverage.',
                             'A time limit can stop a target before its requested run count.']}
    report_path = args.output/'summary.json'
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    env = os.environ.copy()
    env.update(N2Q_FUZZ_RUNS=str(args.runs), N2Q_FUZZ_SECONDS=str(args.seconds), N2Q_FUZZ_SEED=str(args.seed))
    started = time.monotonic()
    interrupted = False
    with (args.output/'campaign.log').open('w') as log:
        proc = subprocess.Popen([str(ROOT/'scripts/fuzz-smoke.sh')], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors='replace', start_new_session=True)
        try:
            for line in proc.stdout:
                log.write(line)
                log.flush()
                if line.startswith('N2Q_FUZZ_TARGET ') or line.startswith('Done '):
                    print(line.strip(),flush=True)
            returncode = proc.wait()
        except KeyboardInterrupt:
            interrupted = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                returncode = proc.wait()
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            proc.stdout.close()
    report.update(returncode=returncode, wall_seconds=round(time.monotonic()-started,3),
                  inputs_unchanged=inputs() == report['inputs'],
                  final_corpus=archive_corpus(args.output, 'final-corpus.tar.gz'))
    try:
        report.update(parse_log((args.output/'campaign.log').read_text()))
        report['status'] = 'passed' if returncode == 0 and report['complete'] and report['inputs_unchanged'] and not report['sanitizer_or_fuzzer_diagnostic'] else 'failed'
    except ValueError as error:
        report.update(status='failed', parse_error=str(error))
    if interrupted:
        report['status'] = 'interrupted'
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    print('Campaign '+report['status']+': '+str(report_path),flush=True)
    return 0 if report['status'] == 'passed' else 130 if interrupted else 1


if __name__ == '__main__':
    sys.exit(main())
