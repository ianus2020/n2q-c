# Security remediation record

This change addresses implementation defects found in the `ianus2020/n2q-c`
source. It does not constitute independent cryptanalysis, certification or a
claim that every weakness in this experimental project has been eliminated.

| Area | Fix |
|---|---|
| C file reader | Validate type, suite and both buffer capacities before reading attacker-controlled lengths; bound allocations and handle errors |
| File integrity, all six ports | N2QF v2: fresh file identity, authenticated position/total and mandatory final record/EOF; reject v1 and trailing data |
| Output integrity | Private temporary files, complete authentication and atomic rename; preserve previous output on failure |
| C SIV/stream opens | Wipe tentative plaintext and set length to zero on failed authentication; remove heap allocation from sponge absorption |
| Parameters | Exact supported profiles, key sizes and nonce lengths; no zero-round encryption or short-key slice panics in high-level modes |
| Tokens | Exact prefix/version/suite, canonical unpadded base64url and a 24 MiB encoded-body limit |
| Core S-box | ANF lane operations in Python/Go/PHP/Swift; valid cipher outputs unchanged; no claim of interpreter/JIT constant-time behavior |
| File CLIs | Explicit binary key files and Secure default; remove fixed public demo keys from actual encryption paths |
| WASM parser | ASCII hex parsing without UTF-8 slicing, bounded lengths, non-panicking Unicode rejection |
| Browser | Worker, CSP, text-only rendering, input limits, explicit key replacement, fresh nonce, safe copy and clear/cancellation |
| Extended input handling | Short packet rejection, bounded skipped-key caches, FPE ASCII/length/tweak guards and removal of C tweak truncation |
| Specification | Correct actual 16/8 profiles, constant selection tooling, tag ordering/sizes, 256-bit hash KAT; withdraw RUP and unproved margin claims |

## Compatibility changes

[N2QF v2](n2qf.md) intentionally rejects the insecure v1 container. It adds
randomness, so entire encrypted files are no longer deterministic. See the
migration policy before touching old data. Raw SIV and valid `nqc.` tokens
remain compatible with their existing KATs. Malformed/noncanonical frames are
now rejected.

C `dec_file` now takes `bits`; `n2q_seek_chunk` takes `outcap`. Rust
`n2qf_build` and Go `N2qfBuild` return error results. Chunk selection verifies
all records. FPE accepts only 2–18 ASCII digits and at most 255 tweak bytes;
invalid inputs raise ValueError in Python and return an empty String in Go/Rust.
FPE remains an experimental, unauthenticated transform and is not claimed to be
standard FF1 or compatible with C's distinct MAC domain.

C's file helpers use POSIX APIs. PHP requires a 64-bit PHP 8 runtime. Raw C
primitives require correctly sized pointers/output buffers and initialized ANF;
they are not a general safe public library API. All ports need application
resource budgets; several file helpers buffer the whole input. Fast, password
KDF, FPE, ratchets, CoNe and FireLine remain research features.

## Reproduce validation

Use `scripts/check.sh` with a native C compiler, Rust 1.96.1, Python 3.9+,
Go 1.26, PHP 8 on a 64-bit host and optionally Swift. It runs KATs, security
regressions, C ASan/UBSan, Go race checks, all native tests and file interop.
`tests/interop.py` exercises every configured writer/reader pair, empty and
multi-block files, malformed files and preservation of existing output. Its
`N2Q_*` environment variables can point at equivalent container-based CLIs.

Build and test the actual browser WASM using the
[web instructions](../impl/n2q-c-wasm/README.md). Browser checks cover both
sizes/profiles, Unicode, escaping, key preservation, malformed input, automatic
nonce renewal, copy failures, worker cancellation, storage and network behavior.
GitHub Actions repeats native and browser checks with read-only repository
permissions; action references and package dependencies are pinned.

## Remaining project work

1. Obtain independent permutation and mode cryptanalysis, including actual 16/8
   profiles and 256-bit parameters; publish rigorous differential/linear bounds.
2. Audit stateful CoNe index persistence, rollback/concurrency and multi-target
   signature security, plus FireLine certificate/replay/key-management protocols.
3. Review PW/KDF construction and deployment budgets, streaming/session APIs and
   all extended modes independently. Passing round-trip vectors is not proof.
4. Add coverage-guided fuzzing and hardware/compiler-specific side-channel tests.
5. Design and review a production library API, secure key lifecycle and bounded
   streaming file readers for every port; test cross-platform filesystem behavior.
6. Complete deployment-specific HTTPS/security headers, release signing, branch
   protection and dependency monitoring in the repository owner's environment.

No live service was deployed, no production key was rotated and no historical
v1 data was migrated by this source change. These operational actions require
actual deployment/data context; they cannot be inferred from library code.
