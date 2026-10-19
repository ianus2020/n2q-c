#!/bin/sh
# Linux clang/libFuzzer + Rust cargo-fuzz smoke. No production secrets are used.
set -eu
cd "$(dirname "$0")/.."
n2q_fuzz_seconds=${N2Q_FUZZ_SECONDS:-20}
n2q_fuzz_runs=${N2Q_FUZZ_RUNS:-2000}
n2q_fuzz_toolchain=${N2Q_FUZZ_TOOLCHAIN:-nightly-2026-10-18}
case "$n2q_fuzz_seconds:$n2q_fuzz_runs" in *[!0-9:]*|:*) echo "invalid fuzz budget" >&2; exit 1;; esac
[ "$n2q_fuzz_seconds" -gt 0 ] && [ "$n2q_fuzz_runs" -gt 0 ]
n2q_fuzz_build=$(mktemp -d)
trap 'rm -rf "$n2q_fuzz_build"' EXIT HUP INT TERM
scripts/check-sanitizers.sh clang
python3 scripts/fuzz-seeds.py
for target in fireline n2qf siv; do
    clang -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all "fuzz/c/$target.c" -o "$n2q_fuzz_build/$target"
    mkdir -p "fuzz/artifacts/c/$target"
    "$n2q_fuzz_build/$target" "fuzz/corpus/$target" "-max_total_time=$n2q_fuzz_seconds" \
        "-runs=$n2q_fuzz_runs" -max_len=4096 -rss_limit_mb=512 -timeout=5 -seed=20261019 \
        "-artifact_prefix=$PWD/fuzz/artifacts/c/$target/"
done
cargo +"$n2q_fuzz_toolchain" metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 > /dev/null
for target in frames n2qf; do
    cargo +"$n2q_fuzz_toolchain" fuzz run --fuzz-dir fuzz "$target" -- \
        "-max_total_time=$n2q_fuzz_seconds" "-runs=$n2q_fuzz_runs" \
        -max_len=4096 -rss_limit_mb=512 -timeout=5 -seed=20261019
done
git diff --exit-code -- fuzz/Cargo.lock
