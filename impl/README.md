# N2Q-C reference implementations (M3)

Two independent, constant-time implementations of N2Q-128 (permutation QP-320 /
QP-640 + modes), cross-validated against each other **and** against the
table-based `tools/const-search` output (Appendix A). Three independent code
paths agreeing byte-for-byte is the milestone-M3 evidence that the algorithm is
unambiguously specified and correctly implemented.

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.

## Layout

| path | what |
|---|---|
| [`n2q-c-ref/`](n2q-c-ref) | Rust reference (`#![forbid(unsafe_code)]`) — QP-320/640; N2Q-128 **and** N2Q-256 modes (hash, SIV-AEAD, blind index, streaming AEAD); N2Q-PW password KDF (`pw.rs`); wire frame (`frame.rs`) |
| [`c/n2qc.c`](c/n2qc.c) | single-file C reference — full parity: permutation + N2Q-128 **and** N2Q-256 modes incl. streaming, with a KAT self-test |
| [`n2q-c-wasm/`](n2q-c-wasm) | WASM bindings + browser tester (`web/index.html`) driving the own cipher |

## Constant-time by construction

The S-box is evaluated from its algebraic normal form using only AND/XOR/NOT on
whole lanes — **no table lookup, no branch, no secret-dependent memory access**.
The linear layer is rotations and XOR. Tag comparison is constant-time. (A
measured timing check — dudect — is milestone M4.)

## Test

Rust (permutation KATs + mode round-trip / tamper / SIV / blind-index tests):
```sh
cd n2q-c-ref && cargo test
cargo run --release --example katgen    # print mode KAT vectors
```

C (self-test reproduces Appendix A permutation KATs + Rust mode vectors):
```sh
cd c && cc -O2 -Wall -Wextra n2qc.c -o n2qc && ./n2qc
```

Both must print all-PASS; the C mode vectors are asserted equal to the Rust ones.

## Web tester

```sh
cd n2q-c-wasm
wasm-pack build --target web --out-dir web/pkg
cd web && python3 -m http.server 8790     # open http://localhost:8790
```
Encrypt/decrypt (SIV), hash and blind-index for **both** N2Q-128 and N2Q-256,
plus a one-click self-test — all in the browser, on the own cipher.

## What M3 covers vs. leaves for later

Done: QP-320 & QP-640 permutation; **all** N2Q-128 and N2Q-256 modes — hash,
SIV-AEAD, blind index, streaming AEAD — in **both** C and Rust, cross-checked
C↔Rust↔tool with KAT vectors; WASM browser tester (both suites, self-test
verified).

Pending: measured constant-time verification (dudect) — that is M4. Round counts
remain provisional until M4.
