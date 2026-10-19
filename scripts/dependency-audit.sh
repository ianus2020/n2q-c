#!/bin/sh
# Audit checked-in locks. Never generate locks or suppress vulnerability IDs.
set -eu
cd "$(dirname "$0")/.."
n2q_audit_output=${1:-/tmp/n2q-dependency-audit}
mkdir -p "$n2q_audit_output"
n2q_audit_status=0
for n2q_audit_label in native wasm fuzz bench cryptanalysis; do
    case "$n2q_audit_label" in
        native) n2q_audit_lock=impl/n2q-c-ref/Cargo.lock ;;
        wasm) n2q_audit_lock=impl/n2q-c-wasm/Cargo.lock ;;
        fuzz) n2q_audit_lock=fuzz/Cargo.lock ;;
        bench) n2q_audit_lock=tools/bench/Cargo.lock ;;
        cryptanalysis) n2q_audit_lock=tools/cryptanalysis/Cargo.lock ;;
    esac
    cargo +1.96.1 audit --file "$n2q_audit_lock" --json > "$n2q_audit_output/$n2q_audit_label.json" || n2q_audit_status=1
done
gitleaks git --redact=100 --report-format json --report-path "$n2q_audit_output/gitleaks.json" --log-opts="--all" . || n2q_audit_status=1
npm audit --json --audit-level=low > "$n2q_audit_output/npm.json" || n2q_audit_status=1
python3 scripts/audit-summary.py "$n2q_audit_output" || n2q_audit_status=1
if [ "$n2q_audit_status" -ne 0 ]; then
    echo "Dependency audit failed; inspect every JSON report in the artifact." >&2
fi
exit "$n2q_audit_status"
