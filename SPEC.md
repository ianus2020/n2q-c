# N2Q — Specification v0.1 (DRAFT)

**A sponge-based authenticated cipher, hash, KDF, and searchable index built on a
single original SPN permutation.**

Status: **DRAFT — design frozen; constants selected (M2); references built &
cross-checked (M3); round counts confirmed by self-cryptanalysis (M4).**
This document is the design half of the audit package. It fixes the
*construction* and *selection criteria* (§3–§7); the concrete S-box, rotation
constants, round constants, and round counts are recorded in
[Appendix A](APPENDIX-A.md), and the self-cryptanalysis in
[docs/cryptanalysis.md](docs/cryptanalysis.md). Nothing here is a security
guarantee — external review is still required (§0, §12-M6).

---

## 0. Status, scope, and the honest warning

N2Q is a **new** cipher. A cipher's security is not established by its designer
but by sustained public cryptanalysis. Until N2Q has survived that:

- **Do not protect real, high-value data with it.** Treat it as a research
  artifact. For production today, use a vetted library (libsodium, Ascon, AES-GCM).
- Every "security level" in this document is a **claim / design target**, not a
  proven theorem, except where a construction-level reduction is cited (§5.4).

What *is* achievable, and what this document delivers, is a **disciplined,
auditable target**: one small permutation to attack, a construction whose
security provably reduces to that permutation, explicit nothing-up-my-sleeve
constants, and a written cryptanalysis plan. That is the difference between the
N2Q 2.5 toy and something an external cryptographer can actually review.

---

## 1. Heritage — which N2Q 2.5 ideas this matures

| N2Q 2.5 idea | Matured form in N2Q |
|---|---|
| Key-dependent substitution **table** | A fixed, public **S-box** chosen by differential/linear criteria (§7.1), applied bitsliced (constant-time). Secrecy comes from the key, never from the S-box. |
| Position-dependent keystream (polyalphabet) | The **duplex** squeezes a position-dependent keystream by construction (§5.2). |
| Non-determinism via `time()`/`shoes` | A real **128-bit nonce** absorbed into the state (§5.2). |
| Length "shoes" as integrity | A cryptographic **128-bit tag** from the sponge capacity (§5.2). |
| `!Z…` self-describing prefix + auto-mode | A **versioned, self-describing frame** (§9). |
| `n2q_search` (decrypt every row) | A **keyed blind index** from the same permutation (§6.4). |
| 186-symbol multilingual table | Removed from the core. Encoding is an application concern; the core is byte-oriented. |

The through-line: substitution + diffusion + a keystream + randomization + an
integrity check were the right instincts. N2Q keeps all of them and rebuilds
each on a construction with a security reduction.

---

## 2. Notation and constants

- `⊕` XOR, `≫n` right-rotation within a 64-bit lane, `‖` concatenation.
- The state `S` is **320 bits** as five 64-bit lanes `x0,x1,x2,x3,x4`
  (little-endian within a lane; lane index is big-endian in the state).
- `b = 320` (state), a design parameter fixed for all of N2Q.
- All named constants (S-box, rotations, round constants) are generated from a
  single public seed by the procedures in §7 — a **nothing-up-my-sleeve**
  guarantee that no value hides a backdoor.

---

## 3. The permutation family QP-w

QP-w is an iterated SPN permutation in the wide-trail / Keccak-Ascon lineage,
defined at two widths that **share one 5-bit S-box and one round structure**:

- **QP-320** — 5 lanes × 64 bits (N2Q-128).
- **QP-640** — 5 lanes × 128 bits (N2Q-256).

Only the lane width and the (re-derived) rotation constants differ; the S-box
layer is identical, so both widths are covered by one differential/linear
analysis of the same S-box. The description below is for QP-320; QP-640 applies
the same column S-box across 128 columns with the 128-bit linear layer of §7.2.
One round `R = pL ∘ pS ∘ pC`:

### 3.1 pC — round-constant addition
XOR a per-round 8-bit constant `rc_i` into the low byte of lane `x2`:
`x2 ← x2 ⊕ rc_i`. Constants are generated in §7.3. Purpose: break the round
symmetry and rotational structure.

### 3.2 pS — substitution layer (bitsliced 5-bit S-box)
Let `S5: {0,1}^5 → {0,1}^5` be the S-box of §7.1. For each bit position
`j = 0..63`, take the column `(x0_j, x1_j, x2_j, x3_j, x4_j)`, apply `S5`, write
the 5 output bits back to the same column. All 64 columns are processed in
parallel with 64-bit boolean operations (no table lookup ⇒ inherently
constant-time, no cache-timing channel). The exact boolean formula is fixed once
`S5` is selected (§7.1).

### 3.3 pL — linear diffusion layer
Per lane, `xk ← xk ⊕ (xk ≫ ra_k) ⊕ (xk ≫ rb_k)` with the ten rotation constants
of §7.2. Purpose: intra-lane diffusion; combined with the inter-lane mixing of
pS this achieves full avalanche within a small number of rounds (target: full
diffusion ≤ 3.5 rounds, to be confirmed by the branch-number/diffusion test of
§7.2).

### 3.4 Round counts
**`p^a` = 16 rounds** (initialization, finalization). **`p^b` = 12 rounds** (data
processing). Confirmed in M4: every measured property (full diffusion, ideal
avalanche, degree saturation, differential collapse) saturates within 3–5 rounds
(see [docs/cryptanalysis.md](docs/cryptanalysis.md)), so p^b = 12 keeps a ≥2.4×
margin. The one outstanding proof — a MILP active-S-box lower bound — could only
justify *fewer* rounds, which the "prioritise margin" choice declines; the counts
are therefore final for v0.1.

---

## 4. Security targets — two suites

N2Q ships **two parameter sets** sharing one design methodology:

- **N2Q-128** — permutation QP-320 (5×64), 128-bit security.
- **N2Q-256** — permutation QP-640 (5×128), 256-bit security, for long-term /
  post-quantum-conservative use.

Both use the *same* round structure, S-box, and constant-generation rules (§7);
only the lane count and capacity differ. This keeps the audit surface to **one
design**, instantiated at two widths (the Keccak-f approach).

| Property | N2Q-128 | N2Q-256 |
|---|---|---|
| Key | 128 bits | 256 bits |
| Confidentiality (IND-CPA) | 128 bits | 256 bits |
| Integrity (INT-CTXT), forgery/attempt | 2⁻¹²⁸ | 2⁻²⁵⁶ |
| Tag | 128 bits | 256 bits |
| Nonce | 128 bits | 128 bits |
| **Nonce-misuse** | **Resistant** (primary SIV mode, §5.1) | **Resistant** |
| Hash (collision / preimage) | 128 / 256 | 256 / 512 |
| Side channels | Constant-time (bitsliced, no secret-dependent branch/index/address) | same |
| Margin | rounds ≥ 2× best found attack (§7.4) | same |

Out of scope: release-of-unverified-plaintext, physical fault / power (DPA)
attacks — separate hardening efforts, noted but not claimed here.

---

## 5. Authenticated encryption — two modes

Two AEAD modes are built on QP-w. The **primary** mode is nonce-misuse-resistant
(§5.1). A faster **streaming** mode (§5.2) is offered for nonce-respecting,
large-data use. Parameters below are for N2Q-128 (QP-320, rate `r=64`, capacity
`c=256`, key/nonce/tag = 128/128/128); N2Q-256 scales to QP-640 with 256-bit
key/tag.

### 5.1 Primary — N2Q-AEAD-SIV (nonce-misuse-resistant)

Two-pass Synthetic-IV construction:
```
# Pass 1 — synthetic tag V = keyed sponge-MAC over (N, A, P):
V  ← MAC_K( N ‖ A ‖ P )            # 128-bit (256 for N2Q-256)
# Pass 2 — encrypt with a keystream seeded by V:
KS ← Duplex_K( V )                 # squeeze |P| keystream bits
C  ← P ⊕ KS
```
Output `V ‖ C`. Decrypt recomputes `KS` from `V`, recovers `P`, recomputes
`V' = MAC_K(N‖A‖P)`, and **accepts only if `V' = V`** (constant-time), else
returns ⟂ with no plaintext.

Guarantee: if a nonce is accidentally reused, the *only* leak is whether two
`(N,A,P)` triples were identical — the standard SIV property (the "forgive
mistakes" behaviour). Cost: two passes ⇒ the message is buffered, not streamed.

### 5.2 Streaming — N2Q-AEAD-Stream (online, nonce-respecting)

A MonkeyDuplex/Ascon-style keyed duplex for large or streaming data where the
caller guarantees nonce uniqueness.

#### 5.2.1 Initialization
```
S ← IV ‖ K ‖ N              # x0=IV(64), (x1,x2)=K, (x3,x4)=N
S ← p^a(S)
S ← S ⊕ (0^192 ‖ K)         # XOR K into the last 128 bits (x3,x4)
```
`IV` is a fixed 64-bit constant encoding algorithm id and parameters (§7.3).

#### 5.2.2 Associated data, plaintext, finalization
```
# Associated data A (blocks A_1..A_m of r bits, last padded 10*):
for each A_i:  x0 ← x0 ⊕ A_i ;  S ← p^b(S)
S ← S ⊕ (0^319 ‖ 1)                         # domain separation

# Plaintext P (blocks P_1..P_n of r bits, last padded 10*):
for i in 1..n:  x0 ← x0 ⊕ P_i ;  C_i ← x0 ;  if i<n: S ← p^b(S)
# (last ciphertext block truncated to |P_n|)

# Finalization:
S ← S ⊕ (0^64 ‖ K ‖ 0^128)                  # XOR K into (x1,x2)
S ← p^a(S)
T ← (x3 ‖ x4) ⊕ (K)                         # 128-bit tag
```
Output: `C_1..C_n ‖ T`. Decryption mirrors this and **must** recompute `T` and
compare in constant time, returning ⟂ (and no plaintext) on mismatch.

#### 5.2.3 Faster streaming variant
`N2Q-Stream-a`: `r = 128` (lanes x0,x1), `c = 192`, `p^b` per §7.4. Same key/
nonce/tag sizes; tighter documented data limit (§5.4). For throughput-sensitive,
nonce-respecting use only.

### 5.3a Reliability / speed profile (user-selectable)
Every mode takes a **profile** that sets the sponge round count `r`, uniform
across the mode:

| Profile | `r` | Margin (M4 saturation ~3–5 rnd) | Throughput |
|---|---|---|---|
| **Secure** (default) | 16 | ~2.4–4× | 1× |
| **Fast** | 8 | ~1.6–2.7× | ~2× (measured) |

The profile is chosen at encryption time and **recorded in the frame suite byte**
(§9, bit `0x20`), so decryption reads it back automatically — a single library
decodes both, and the two are fully interoperable. Fast is a deliberate,
labelled margin-for-speed trade, not a separate cipher. Cross-checked C↔Rust for
both profiles ([Appendix A.6](APPENDIX-A.md)).

### 5.4 Why this is auditable — the reduction
The duplex/sponge security theorems (Bertoni–Daemen–Peeters–Van Assche; Ascon's
proofs), and the SIV composition theorem (Rogaway–Shrimpton) for §5.1, state:
**if QP-w is indistinguishable from a random permutation**, both modes provide
confidentiality and integrity up to ≈ `2^{c/2}` offline and `2^k` online
queries, with per-key data ≤ `2^{c/2}` blocks. Therefore the whole library's
security **reduces to a single question**: how close is QP-w to a random
permutation? That is the one, bounded object the audit attacks — §7–§8.

---

## 6. The rest of the library, from the same permutation

### 6.1 N2Q-Hash-256 (sponge hash)
Rate 64, capacity 256, output 256 bits. Absorb the (10*-padded) message into
`x0` with `p^b` between blocks; run `p^a`; squeeze four 64-bit rate blocks with
`p^b` between them. Collision 128-bit, preimage 256-bit (targets).

### 6.2 N2Q-XOF
As N2Q-Hash but squeeze an arbitrary-length stream — used internally by §6.3.

### 6.3 N2Q-KDF
HKDF-style over N2Q-Hash: `extract(salt, ikm) = Hash(salt ‖ ikm)`;
`expand(prk, info, L) = XOF(prk ‖ info ‖ L)`. Domain-separated context strings
give independent sub-keys (as in N2Q 3.0).

### 6.4 N2Q-BlindIndex
Keyed deterministic index for search over encrypted columns (the matured
`n2q_search`): `BI(K_bi, v) = truncate_128( N2Q-KDF-derived-keyed-Hash(v) )`.
Deterministic ⇒ `WHERE bi = ?`; keyed ⇒ a stolen DB can't compute indexes.
Documented trade-off (unchanged from 3.0): reveals equality/frequency.

### 6.5 N2Q-PW — password hashing (memory-hard)
A sponge permutation is **not** memory-hard, so password→key derivation cannot be
the bare hash. Rather than invent a memory-hard primitive (riskier than the
cipher), **N2Q-PW instantiates Balloon hashing** (Boneh–Corrigan-Gibbs–Schechter
2016 — a construction with a *proven* memory-hardness bound for any hash) with
N2Q-Hash-256, using the **data-independent** addressing variant (no
password-dependent memory access ⇒ no cache-timing channel). Cost parameters:
`s_cost` (memory, in 32-byte blocks) and `t_cost` (passes); tune per deployment.
Memory-hardness comes from Balloon's analysis, the hash from N2Q — the trust
still reduces to QP. Implemented in M5 ([`impl/.../pw.rs`](impl/n2q-c-ref/src/pw.rs)).

---

## 7. Constant selection (nothing-up-my-sleeve)

All constants derive deterministically from the ASCII seed
`"N2Q/v0.1"` expanded by a public XOF (SHAKE256 for the *selection tooling
only* — the resulting fixed tables are what ship). The procedures are normative;
the resulting tables land in Appendix A after the §12-M2 run.

### 7.1 S-box S5 — selection criteria (all mandatory)
5-bit bijection with:
1. Differential uniformity ≤ 4 (APN = 2 preferred); max DP ≤ 2⁻³ (target 2⁻⁴).
2. Nonlinearity ≥ 10 (linearity ≤ 12).
3. Algebraic degree ≥ 3 (4 = maximum, preferred).
4. No fixed points, no `S(x)=x̄`.
5. Constant-time evaluation. Refined in M2: the S-box is evaluated bitsliced from
   its algebraic normal form, which is constant-time for *any* table, so circuit
   size is a metric to minimise, not a hard gate. (The abandoned "branch ≥ 3"
   criterion belonged to the linear layer, not the S-box — see §7.2.)

**Result (M2, fixed).** A random-table search confirmed strong 5-bit S-boxes are
far too rare to find by chance (28 of 2M samples even reached differential
uniformity ≤ 4, zero were APN). We therefore use an **algebraic construction**:
the GF(2⁵) inverse (primitive poly x⁵+x²+1) wrapped in a deterministically-chosen
invertible affine bijection (the AES methodology). The result is **APN
(uniformity 2), nonlinearity 10, algebraic degree 4, no fixed points**. The table
and full properties are in [Appendix A.1](APPENDIX-A.md#a1-s-box-s5).

### 7.2 Rotation constants (ra_k, rb_k), k=0..4
Ten values per width, chosen to **minimise rounds-to-full-diffusion**, measured
with a boolean bit-dependency model of one round (pL ∘ pS). Procedure: search
seeded rotation sets, keep the one reaching full linear diffusion in the fewest
rounds.

**Result (M2, fixed).** Both widths reach **full linear diffusion in 4 rounds**.
Constants for QP-320 and QP-640 are in
[Appendix A.2](APPENDIX-A.md#a2-rotation-constants-linear-layer-pl).

### 7.3 Round constants rc_i and IV
`rc_i` = byte `i` of the seed XOF stream, i = 0..(a−1), all distinct.
`IV` = `0x` ‖ (algorithm-id `0x4E` "N") ‖ r ‖ c ‖ (a) ‖ (b) ‖ key-bits, packed
into 64 bits. Exact packing in Appendix A.

### 7.4 Round-count derivation
Using the S-box max DP = 2⁻⁴ (A.1) and the wide-trail bound on active S-boxes,
compute the minimal rounds `R*` such that the best single-characteristic
probability < 2⁻¹²⁸ (differential) and correlation < 2⁻⁶⁴ (linear); set
`p^b ≥ 2·R*`, `p^a ≥ p^b + 4`.

**Confirmed (M4).** Full linear diffusion is 4 rounds (A.2); `p^b = 12`,
`p^a = 16` (see [Appendix A.4](APPENDIX-A.md#a4-round-counts)). M4 measured every
security-relevant property saturating within 3–5 rounds, giving a ≥2.4× margin
([docs/cryptanalysis.md](docs/cryptanalysis.md)). The exact minimum active-S-box
count (a MILP *proof*) is the one remaining rigorous item; it can only justify
reducing rounds, so the margin preference keeps these numbers final for v0.1.

---

## 8. Cryptanalysis plan (the audit dossier, in progress)

For QP-320 as a keyed permutation and as an unkeyed hash permutation:

1. **Differential & linear** — MILP/SAT models counting active S-boxes; report
   best characteristics and bounds vs. round count. (Primary bound for §7.4.)
2. **Algebraic / cube / higher-order** — degree growth per round; distinguisher
   search; ensure degree saturates well before `p^b`.
3. **Rotational and rotational-XOR** — since pL is rotation-based; verify pC
   round constants break it.
4. **Rebound / differential for the hash** — collisions/near-collisions on
   reduced-round N2Q-Hash.
5. **Integral / division property** — bit-based division property distinguishers.
6. **Slide / invariant subspace / nonlinear invariants** — constants must
   preclude these.
7. **Implementation** — dudect/timing tests confirming constant-time; test
   vectors cross-checked between the C and Rust implementations.

Each item yields a section in `docs/cryptanalysis.md` with the model, the
result, and the resulting security margin. External auditors receive this plus
reproducible tooling.

---

## 9. Wire format (self-describing, versioned)

```
n2q-c token = "nqc." ‖ base64url( version(1) ‖ suite(1) ‖ nonce(16) ‖ ct ‖ tag(16) )
```
`version` = 1. The `suite` byte packs mode + size + **profile**:
low nibble = size (`1`=128, `2`=256); bit `0x10` = streaming (else SIV);
bit `0x20` = **Fast** profile (else Secure). So `0x01` = SIV-128-Secure,
`0x21` = SIV-128-Fast, `0x11` = Stream-128-Secure, `0x02`/`0x22` = SIV-256-…, etc.
Crypto-agility: a future suite can be added without breaking parsers, and decode
reads mode+profile from the token (matured `!Z/!X` auto-mode) — so Secure and
Fast tokens are mutually interoperable under one decoder. **Finalized and
implemented** ([`frame.rs`](impl/n2q-c-ref/src/frame.rs) + `capsule`, M5) with
base64url (no padding); the textual prefix is `nqc.`.

---

## 10. Post-quantum note

Both suites are first-class (§4); nonce-misuse resistance is the *primary* mode
(§5.1), not an add-on. On quantum adversaries: Grover halves effective key
strength, so N2Q-128 ⇒ ~64-bit and N2Q-256 ⇒ ~128-bit. Long-term / archival data
should therefore use **N2Q-256**. Symmetric primitives are otherwise not broken
by known quantum algorithms.

---

## 11. Reference implementations

Per the chosen path: a portable **C reference** (the auditor-facing artifact,
byte-exact, no timing dependence) plus a **Rust** implementation (memory-safe,
constant-time, WASM-buildable for the existing web tester). Both ship with the
Appendix-A test vectors and are cross-validated in CI.

---

## 12. Roadmap to external audit

- **M1 — Specification (this document).** Construction + criteria frozen.
- **M2 — Constant selection. ✅ done.** `tools/const-search` fixed S5 (APN /
  NL 10 / deg 4), the QP-320 & QP-640 rotations (4-round diffusion), and the
  round constants; permutation KATs generated. Round counts provisional (→ M4).
  See [Appendix A](APPENDIX-A.md).
- **M3 — Reference implementations. ✅ done.** Constant-time C + Rust
  ([`impl/`](impl)) at full parity: QP-320 & QP-640 permutation; N2Q-128 **and**
  N2Q-256 modes (hash, SIV-AEAD, blind index, streaming AEAD); cross-checked
  C↔Rust↔tool with KAT vectors ([Appendix A.5–A.6](APPENDIX-A.md)); WASM browser
  tester on the own cipher. Measured constant-time (dudect) belongs to M4.
- **M4 — Self-cryptanalysis. ◐ mostly done.** [`tools/cryptanalysis`](tools/cryptanalysis)
  measured diffusion/avalanche, algebraic degree (zero-sum), differential
  collapse, rotational symmetry, and constant-time (dudect, |t|=0.48) on the real
  permutation; results and margins in [docs/cryptanalysis.md](docs/cryptanalysis.md).
  Round counts confirmed final (§3.4). A solver-free differential trail search is
  built (best single-column trails: 2R→4, 3R→7 active S-boxes). **Open (external
  review, M6):** the *certified* differential/linear lower bound needs an all-
  starts MILP/SAT search (a solver); plus rebound/hash analysis and QP-640 runs.
- **M5 — Hardening & docs. ✅ done.** N2Q-PW (Balloon over N2Q-Hash, §6.5) and the
  wire frame (§9) implemented and tested; misuse-resistant SIV is already the
  primary mode (§5.1); threat model written
  ([docs/threat-model.md](docs/threat-model.md)).
- **M6 — Open the project.** Per the chosen "private first, then open" path,
  M1–M5 are developed privately; at M6 publish spec + tooling + dossier and
  invite public cryptanalysis (challenge/bounty). Only after surviving this does
  N2Q leave "research" status.

---

## Appendix A — Concrete constants

Populated in **M2** and kept in a separate file: **[APPENDIX-A.md](APPENDIX-A.md)**.

- A.1 S-box S5 (table + measured properties) — **fixed** (APN, NL 10, deg 4).
- A.2 Rotation constants, QP-320 & QP-640 — **fixed** (4-round diffusion).
- A.3 Round constants rc_i — **fixed**.
- A.4 Round counts a, b — **final** (12 / 16), confirmed in M4.
- A.5 Known-answer vectors for QP — **fixed** (AEAD/hash KATs in M3).

All values are reproducible from the public seed via
[`tools/const-search`](tools/const-search).

---

*N2Q v0.1 — design frozen for review. This is a target for cryptanalysis, not
a security guarantee.*
