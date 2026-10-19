# Bounded implementation fuzzing

The campaign uses synthetic data and public fixture keys. It checks implementation
properties; it does not establish the security level of N2Q or replace external
cryptanalysis.

| Target | Coverage goal |
|---|---|
| C `fireline` | Untrusted parcel framing and authenticated open |
| C `n2qf` | Untrusted 128-bit seek containers, authenticated EOF, output bounds |
| C `siv` | Untrusted 128/256-bit SIV ciphertext, both round profiles |
| C `modes_roundtrip` | Construct valid SIV/stream ciphertext on each eligible input, authenticate it, mutate it, verify rejection and plaintext clearing; both widths/profiles |
| C `convergent` | Determinism, successful authentication, logical output capacities/canaries, invalid master-key lengths, SIZE_MAX and tampering; fixed 16-byte master key |
| Rust `frames` | Canonical token decoding and capsule open in both widths |
| Rust `n2qf` | In-memory 128-bit file/seek consistency and malformed framing |

All inputs are bounded to 4096 bytes. Large-file streaming and other ports have
separate native/interop tests. These targets do not exhaust their input domains.
`modes_roundtrip` and `convergent` count completed property checks by variant;
these counters are separate from libFuzzer executions. Executions can include
short/rejected inputs and repetitions. Do not add the counters to the execution
total or infer attack probabilities from them.

Mutation position/bit controls are independent of mode/profile flags and can
reach the entire ciphertext. Convergent capacity controls use 16 bits, including
values above 255. Deterministic seeds cover every tag byte and all eight bit
choices separately, plus first/middle/last ciphertext positions and output
capacity boundaries; they do not exhaust the Cartesian product of these inputs.

## Environment and invocation

Use Linux with Clang + compiler-rt/libFuzzer, Python 3, Git, Rust 1.96.1,
nightly-2026-10-18 and cargo-fuzz 0.13.2. The reference aarch64 run used Debian
Clang 14.0.6; its minimal image needed explicit `libclang-rt-14-dev`:

```sh
apt-get update
apt-get install -y --no-install-recommends clang libclang-rt-14-dev python3 git ca-certificates procps
rustup toolchain install nightly-2026-10-18 --profile minimal
cargo +1.96.1 install cargo-fuzz --version 0.13.2 --locked
python3 scripts/fuzz-campaign.py --output /tmp/n2q-fuzz-smoke --runs 2000 --seconds 20
python3 scripts/fuzz-campaign.py --output /tmp/n2q-fuzz-expanded --runs 1000000 --seconds 180
```

Each target receives execution and time budgets. Corpus initialization can exceed
a small execution request; a time limit can stop a target before that request.
The output directory must be new. The runner records actual counts/coverage edges/peak RSS, tool versions,
source hashes, raw logs and initial/final corpus archives. Missing targets,
incomplete logs, sanitizer diagnostics, source modifications and nonzero exits
fail the report. SIGINT/SIGTERM/SIGHUP stop the child process group and mark
interruption; stubborn descendants are killed after a five-second grace period.
Atomic checkpoints keep running results separate from completed results.
The whole child process has a deadline of 600 + 7 * (seconds + 5), overridable
with `--wall-seconds`; exceeding it produces `timed_out`, never success.
The C compiler is first checked with clean, signed-overflow and heap-UAF controls;
all C sanitizer findings are fatal. Core dumps are disabled in the smoke script.
The per-input timeout is 5 seconds and the fuzzer RSS cap is 512 MiB; these are
separate from resource limits for compilation or a container.

Use a fresh ignored `fuzz/corpus` for a fresh campaign, or retain its recorded
initial archive when continuing. Named deterministic seeds are regenerated.
Coverage edges depend on compiler/instrumentation; they are not a percentage of
all paths. Time-bounded aggregate results are not guaranteed byte-reproducible.

The optional `scripts/fuzz-series.py` accepts an explicit finite `--seeds` list,
uses a recorded warm start and stops on the first non-success. It creates
`series.json` and one campaign directory per seed. It is not scheduled by default.
Process-control regression tests and retained evidence are documented in
[stage 25](../docs/stage-25-long-fuzz-runner.ru.md).

## Isolated source snapshot

The local campaign image is the official
`rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3`.
No services or container ports are needed. The reference container is capped at
2 CPUs / 2 GiB, with CARGO_BUILD_JOBS=2. Transfer only source files:

```sh
git archive --format=tar --output=/tmp/n2q-fuzz-source.tar HEAD \
  .gitignore .github/workflows/security.yml impl/c impl/python impl/n2q-c-ref \
  fuzz scripts tests/sanitizer_probe.c tests/test_fuzz_campaign.py
```

Extract into a new directory in the container, initialize a local Git snapshot
for the lockfile-diff check, and set N2Q_SOURCE_COMMIT to the real source commit.
The report distinguishes that source commit from the synthetic checkout commit;
compare every recorded file hash with the source tree. The archive excludes
ignored PKI, data, credentials, build output and Git authentication settings.
After a smoke run has compiled/fetched the Rust targets, the expanded run can use
CARGO_NET_OFFLINE=true with the container network disconnected. Retain evidence
before removing the temporary container.
