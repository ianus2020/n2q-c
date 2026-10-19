#!/bin/sh
# Native tools required: C compiler, Rust, Python, Go, PHP; Swift optional.
set -eu
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT HUP INT TERM
python3 -m unittest discover -s tests -v
python3 impl/python/test_kat.py
python3 impl/python/n2qc_modes.py
cc -O1 -g -fsanitize=address,undefined impl/c/n2qc.c -o "$build/n2qc"
"$build/n2qc"
cc -O1 -g -fsanitize=address,undefined tests/security.c -o "$build/security"
"$build/security"
cc -O1 -g -fsanitize=address,undefined -DN2Q_SEEK_DEMO impl/c/n2q_seek.c -o "$build/seek"
"$build/seek"
cc -O1 -g -fsanitize=address,undefined -DN2Q_FPE_DEMO impl/c/n2q_fpe.c -o "$build/fpe"
"$build/fpe"
cc -O1 -g -fsanitize=address,undefined tests/fpe_security.c -o "$build/fpe-security"
"$build/fpe-security"
cc -O1 -g -fsanitize=address,undefined tests/fireline_security.c -o "$build/fireline-security"
"$build/fireline-security"
cc -O1 -g -fsanitize=address,undefined -DN2Q_FIRELINE_DEMO impl/c/n2q_fireline.c -o "$build/fireline"
"$build/fireline"
python3 impl/python/n2qc_fireline.py
cc -O1 -g -pthread -fsanitize=address,undefined tests/cone_security.c -o "$build/cone-security"
"$build/cone-security"
cc -O1 -g -pthread -fsanitize=thread tests/cone_security.c -o "$build/cone-thread"
"$build/cone-thread" --threads
cargo metadata --locked --format-version 1 --manifest-path tools/bench/Cargo.toml >/dev/null
cargo metadata --locked --format-version 1 --manifest-path tools/cryptanalysis/Cargo.toml >/dev/null
cargo test --locked --manifest-path impl/n2q-c-ref/Cargo.toml
cargo test --locked --manifest-path impl/n2q-c-wasm/Cargo.toml
cargo build --locked --release --example file --manifest-path impl/n2q-c-ref/Cargo.toml
(cd impl/go && go test -race ./... && go run . && go build -o "$build/go-n2qc" .)
php impl/php/n2qc.php
php tests/php_streaming.php
export N2Q_C="$build/n2qc" N2Q_RUST="$PWD/impl/n2q-c-ref/target/release/examples/file" N2Q_GO="$build/go-n2qc"
export N2Q_PHP="php $PWD/impl/php/file_cli.php"
if command -v swiftc >/dev/null; then
    swiftc -O impl/swift/n2qc.swift -o "$build/swift-n2qc"
    "$build/swift-n2qc"
    python3 -c 'import pathlib,sys; source=pathlib.Path("impl/swift/n2qc.swift").read_text().split("// ---- self-test ----")[0]; pathlib.Path(sys.argv[1]).write_text(source+pathlib.Path("tests/swift_streaming.swift").read_text())' "$build/swift-streaming.swift"
    swiftc -O "$build/swift-streaming.swift" -o "$build/swift-streaming"
    "$build/swift-streaming"
    export N2Q_SWIFT="$build/swift-n2qc"
fi
python3 tests/interop.py
