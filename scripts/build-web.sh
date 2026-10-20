#!/bin/sh
set -eu
cd "$(dirname "$0")/../impl/n2q-c-wasm"
wasm-pack build --locked --target web --out-dir web/pkg --release
python3 ../../scripts/web-manifest.py
