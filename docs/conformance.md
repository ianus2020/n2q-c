# N2Q conformance & reproducible builds

Two promises make an implementation trustworthy: **any port computes the same
answers**, and **you can rebuild the artifact from source and get the same bytes**.

## Conformance vectors

[`impl/conformance/vectors.txt`](../impl/conformance/vectors.txt) is the canonical
known-answer set: `hash`, `seal` (both profiles), `blind index` and the raw QP
permutation, for both suites, over fixed inputs. **A conforming port must
reproduce every line byte-for-byte.**

Every reference already checks these at build time — the vectors are baked into
each self-test:

```bash
cd impl/python && python3 test_kat.py            # Python  → ALL PASS
cd impl/c      && cc -O2 n2qc.c -o n2qc && ./n2qc # C       → ALL PASS
cd impl/go     && go run .                        # Go      → ALL PASS
swift impl/swift/n2qc.swift                        # Swift   → ALL PASS
```

To validate a **new** port, print its `hash128("")`, `seal128` (Secure and Fast),
etc. for the fixed inputs and diff against `vectors.txt`. If all lines match, the
port is byte-compatible with every other N2Q implementation (a file sealed in
one decrypts in all — see the cross-language test on the media page).

## Reproducible constants

None of the constants are "magic": the S-box, rotations and round constants are
**derived deterministically from a public seed** by
[`tools/const-search`](../tools/const-search). Re-running it reproduces exactly
the values in [`APPENDIX-A.md`](../APPENDIX-A.md) — there is no room to hide a
trapdoor in a hand-picked constant.

```bash
cd tools/const-search && cargo run --release -- construct | rotations | finalize
```

## Reproducible builds

The reference implementations are single files with no code generation, no
timestamps and no network access, so a build is a pure function of (source,
compiler, flags). To reproduce bit-identically, pin the toolchain and use fixed
flags, e.g. `cc -O2 -fno-common` for C or `cargo build --release --locked` for
Rust. Publish the source archive's hash next to each release so anyone can
confirm the shipped binary was built from exactly this source.

*Status: the vectors and reproducible constants are in place today; signed
releases and a hosted CI attestation are milestone-M6 items.*
