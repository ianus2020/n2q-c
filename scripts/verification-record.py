#!/usr/bin/env python3
"""Emit only public build inputs/tool versions; never dump environment or secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import platform
import os

ROOT=Path(__file__).resolve().parents[1]
def version(command):
    try:
        p=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                         text=True,timeout=20,check=False)
        return {"exit_code":p.returncode,"first_line":p.stdout.splitlines()[0][:300] if p.stdout else ""}
    except (OSError,subprocess.TimeoutExpired):
        return {"available":False}
def record(job):
    paths=[".github/workflows/security.yml","impl/conformance/vectors.txt",
        "impl/n2q-c-ref/Cargo.lock","impl/n2q-c-wasm/Cargo.lock","fuzz/Cargo.lock",
        "tools/bench/Cargo.lock","tools/cryptanalysis/Cargo.lock","package-lock.json",
        "impl/c/n2qc.c","scripts/check.sh","scripts/check-sanitizers.sh",
        "tests/sanitizer_probe.c","scripts/fuzz-smoke.sh","scripts/fuzz-seeds.py",
        "scripts/fuzz-campaign.py","scripts/fuzz-series.py","tests/test_fuzz_campaign.py","scripts/build-web.sh",
        "scripts/serve-web.py","tests/test_web_server.py","scripts/dependency-audit.sh",
        "scripts/audit-summary.py","tests/test_audit_summary.py","scripts/verification-record.py",
        "impl/n2q-c-wasm/web/app.js","impl/n2q-c-wasm/web/crypto-worker.js",
        "impl/n2q-c-wasm/web/index.html","impl/n2q-c-wasm/web/app.css","tests/web.cjs",
        "tools/cryptanalysis/exact.py","tools/cryptanalysis/trails.py",
        "tools/cryptanalysis/src/bin/audit.rs","tools/cryptanalysis/summarize.py",
        "tools/anchor/server.py","tools/local_stand/tls.py","tools/local_stand/pki.py",
        "tools/local_stand/web.py","tools/local_stand/run.py",
        "tools/migration/n2q_migrate.py","impl/n2q-c-ref/examples/migration_keys.rs",
        "impl/c/n2q_cone_anchor_http.c","impl/c/n2q_cone_anchor_http.h"]
    paths += [str(path.relative_to(ROOT)) for path in sorted((ROOT/'fuzz/c').glob('*.c'))]
    paths += [str(path.relative_to(ROOT)) for path in sorted((ROOT/'fuzz/fuzz_targets').glob('*.rs'))]
    hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
    manifest=ROOT/"impl/n2q-c-wasm/web/pkg/build-manifest.json"
    commands={
        "c":["cc","--version"],"rust":["rustc","--version"],"go":["go","version"],
        "php":["php","--version"],"python":["python3","--version"],
        "python-ssl":["python3","-c","import ssl; print(ssl.OPENSSL_VERSION)"],
        "openssl":["openssl","version"],
        "node":["node","--version"],"swift":["swiftc","--version"]}
    if job=="fuzz":
        commands.update({"rust-fuzz":["rustc","+nightly-2026-10-18","--version"],
                         "cargo-fuzz":["cargo","+1.96.1","fuzz","--version"]})
    if job=="dependencies":
        commands.update({"cargo-audit":["cargo","+1.96.1","audit","--version"],"gitleaks":["gitleaks","version"]})
    return {"schema":1,"job":job,"platform":platform.platform(),
        "checkout":version(["git","rev-parse","HEAD"]),
        "source_commit":os.environ.get("N2Q_SOURCE_COMMIT","not-reported"),
        "ci_status":os.environ.get("N2Q_VERIFICATION_STATUS","not-reported"),
        "input_sha256":hashes,
        "tools":{name:version(command) for name,command in commands.items()},
        "web_manifest":json.loads(manifest.read_text()) if manifest.exists() else None,
        "limits":{"fuzz_targets":7,"fuzz_runs_per_target":2000,
                  "meaning":"smoke budget; no exhaustive search or cryptographic certification"}}
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--job",required=True);parser.add_argument("--output",required=True)
    args=parser.parse_args()
    Path(args.output).write_text(json.dumps(record(args.job),indent=2,sort_keys=True)+"\n")
