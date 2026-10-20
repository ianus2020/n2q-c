#!/bin/sh
# Prove that instrumented failures fail the gate, rather than merely print a report.
set -eu
cd "$(dirname "$0")/.."
n2q_sanitizer_cc=${1:-cc}
n2q_sanitizer_build=$(mktemp -d)
trap 'rm -rf "$n2q_sanitizer_build"' EXIT HUP INT TERM
ulimit -c 0 2>/dev/null || true
"$n2q_sanitizer_cc" -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    -fno-sanitize-recover=all tests/sanitizer_probe.c -o "$n2q_sanitizer_build/probe"
"$n2q_sanitizer_build/probe" control
for n2q_sanitizer_mode in undefined address; do
    n2q_sanitizer_status=0
    "$n2q_sanitizer_build/probe" "$n2q_sanitizer_mode" \
        > "$n2q_sanitizer_build/$n2q_sanitizer_mode.log" 2>&1 || n2q_sanitizer_status=$?
    if [ "$n2q_sanitizer_status" -eq 0 ]; then
        echo "Sanitizer failed to reject $n2q_sanitizer_mode control" >&2
        exit 1
    fi
    python3 - "$n2q_sanitizer_mode" "$n2q_sanitizer_build/$n2q_sanitizer_mode.log" <<'PY'
from pathlib import Path
import sys
mode, path = sys.argv[1:]
report = Path(path).read_text(errors='replace')
expected = 'runtime error: signed integer overflow' if mode == 'undefined' else 'AddressSanitizer: heap-use-after-free'
if expected not in report:
    raise SystemExit('Sanitizer control failed without its expected diagnostic: '+mode)
PY
done
echo 'ASan/UBSan controls: clean execution PASS; both instrumented faults rejected'
