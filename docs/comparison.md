# N2Q vs. market algorithms — security (by design) & speed (as implemented)

This compares N2Q's **designed** security and its **as-coded** speed against
established AEADs. Audit status is deliberately set aside (N2Q is unaudited;
the others are standardized and analyzed for years) — this looks only at what is
built into the construction and the code.

## 1. Speed (measured, same machine, single-threaded)

Apples-to-apples: N2Q and the RustCrypto reference ciphers benchmarked in the
same process on the same CPU (Apple Silicon, arm64), 1 MiB buffer, release+LTO.

| Algorithm | Throughput | vs XChaCha |
|---|--:|--:|
| XChaCha20-Poly1305 (RustCrypto, SIMD) | **712 MB/s** | 1× |
| AES-256-GCM (RustCrypto) | **245 MB/s** | 0.34× |
| N2Q-256 streaming — **Fast** (8 rnd) | 24.1 MB/s | ~30× slower |
| N2Q-256 streaming — Secure (16 rnd) | 12.2 MB/s | ~58× slower |
| N2Q-128 streaming — **Fast** (8 rnd) | 16.0 MB/s | ~44× slower |
| N2Q-128 streaming — Secure (16 rnd) | 8.0 MB/s | ~89× slower |
| N2Q-128 SIV — Secure (2-pass) | 4.0 MB/s | ~180× slower |

The **Fast profile** (user-selectable, recorded in the token) roughly **doubles**
throughput for a labelled margin trade — still ~2.4× above the M4 saturation
point.

### Why N2Q is slow *as implemented* (and the ceiling)
The gap is implementation, not an inherent property of the design:

1. **Rounds per block.** The reference runs the full `p^a = 16` rounds for every
   rate block. Ascon (same family) uses 6–8 data rounds. Switching to `p^b = 12`
   between data blocks — or fewer — is a legal ~1.3–2.7× win.
2. **Rate.** N2Q-128 absorbs 8 bytes/permutation; N2Q-256 absorbs 16 (which is
   why 256 benches *faster* here). A higher-rate 128-bit suite (like Ascon-128a)
   would roughly double throughput.
3. **No SIMD.** The bitsliced S-box processes 64 columns per 64-bit word but does
   not use NEON/AVX; ChaCha and AES here use vector units / AES-NI.
4. **SIV is 2-pass** by nature (MAC then encrypt) → ~2× the streaming mode. Use
   streaming where nonce uniqueness holds.

Realistic optimized ceiling: an Ascon-class implementation of N2Q (fewer data
rounds, higher rate, SIMD) would plausibly land in the ~100–300 MB/s range —
i.e. ~2–7× slower than vectorized ChaCha, comparable to software Ascon. It will
**not** beat AES-NI/AEGIS on CPUs with AES hardware. N2Q trades speed for
margin and a table-free constant-time core.

## 2. Security by design

| | **N2Q** | AES-256-GCM | (X)ChaCha20-Poly1305 | Ascon-128 |
|---|---|---|---|---|
| Construction | SPN sponge/duplex | AES + GHASH | ARX stream + Poly1305 | SPN sponge/duplex |
| Closest relative | **Ascon** | Rijndael | Salsa/ChaCha | Keccak/Ascon |
| Key / tag | 128 & 256 / 128 & 256 | 256 / 128 | 256 / 128 | 128 / 128 |
| Nonce | 128 | 96 | 96 / 192 | 128 |
| **Nonce-misuse resistant** | **Yes (SIV default)** | No (catastrophic) | No (catastrophic) | No |
| Constant-time by design | **Yes** (bitsliced, no tables) | Only with AES-NI | Yes (ARX) | Yes |
| S-box quality | APN, deg 4 (optimal DU/deg) | inverse (DU 4) | n/a (ARX) | quadratic (deg 2) |
| Security margin (rounds) | ~2.4–4× (empirical) | ~1.4× (14 rnd) | ~2.8× (20 rnd) | well-characterized |
| Diff/linear bound | empirical + partial trail search | MILP-proven (community) | analyzed | **MILP-proven** |
| Built-in hash | Yes | No | No | Yes |
| Built-in searchable index | **Yes (blind index)** | No | No | No |
| Built-in password KDF | Yes (Argon2id v19; external RustCrypto dependency) | No | No | No |
| External analysis / standard | **None yet** | NIST, decades | RFC, decades | NIST LWC winner |

### Reading the table
- **Structurally**, N2Q is an Ascon-family cipher. The design choices are sound
  and mainstream: wide-trail SPN, bitsliced constant-time core, sponge reduction.
- **Design edges over the market:**
  - *Misuse-resistant by default.* AES-GCM and ChaCha-Poly leak catastrophically
    on nonce reuse; N2Q's primary mode (SIV) degrades to leaking only equality.
  - *Stronger S-box than Ascon* on paper: APN (differential uniformity 2) with
    algebraic degree 4, vs Ascon's degree-2 quadratic S-box (Ascon compensates
    with structure and proven bounds).
  - *One primitive → whole toolkit*: AEAD + hash + KDF + **searchable index** +
    password hashing, all from QP. Market AEADs give you encryption only; you bolt
    on a separate hash, KDF, and a searchable-encryption library.
  - *Generous, measured margin* (~2.4–4×), comparable to ChaCha, better than
    AES-256's ~1.4×.
- **Where it is behind (design-wise, audit aside):**
  - Ascon's differential/linear resistance is **MILP-proven**; N2Q's is
    empirical + a partial solver-free trail search (the one open rigorous item).
  - AES/ChaCha/Ascon have enormous third-party cryptanalysis; N2Q has the
    designer's own only.

## 3. Honest verdict

- **Security (by design):** N2Q sits in the same class as Ascon and ChaCha —
  a well-structured, constant-time AEAD with a strong S-box and a healthy margin,
  and it adds misuse-resistance and a searchable index that the mainstream AEADs
  don't ship. The design is credible. Its gap to Ascon is a *proof* (MILP) and
  third-party review, not a structural weakness.
- **Speed (as coded):** clearly the weakest axis — ~45–67× slower than vectorized
  ChaCha in the streaming mode, because the reference favors clarity and margin
  over optimization. The design can be sped up ~10–30× to Ascon-class, but will
  not match AES-NI/AEGIS on AES-capable hardware.
- **Net:** as a *design*, competitive and feature-rich; as *shipped code*, a
  correct, constant-time, but unoptimized reference. Pick N2Q for its features
  (misuse-resistance, searchable encryption, one-primitive toolkit) and margin,
  not for raw speed — and only after the external review the others already have.

*Reproduce speed: `cd tools/bench && cargo run --release`.*
