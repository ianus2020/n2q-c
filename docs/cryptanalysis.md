# N2Q — Cryptanalysis dossier

Self-cryptanalysis of the QP permutation and modes. Each section states the
model, the result, and the security margin. Measurements are reproducible with
[`tools/cryptanalysis`](../tools/cryptanalysis) (run on QP-320). This is the
designer's own analysis — external cryptanalysis is still required (SPEC §0, M6).

Legend: ☑ done · ◐ partial · ☐ open. Result type: **[P]** proven · **[E]**
empirical/measured · **[X]** extrapolated.

## Target
QP permutation (SPEC §3): 5×64 (QP-320) / 5×128 (QP-640), Ascon-lineage SPN
sponge. Security of the whole library reduces to QP behaving like a random
permutation (SPEC §5.4). Provisional round counts entering M4: p^b = 12,
p^a = 16.

## Summary of measured margins

| Property | Saturates at | Full rounds (p^b / p^a) | Margin |
|---|---|---|---|
| Full bit diffusion (avalanche) **[E]** | 4 rounds | 12 / 16 | ~3× |
| Ideal flip prob (SAC ≈ 0.5) **[E]** | 5 rounds | 12 / 16 | ~2.4× |
| Algebraic degree (no zero-sum, dim ≤16) **[E]** | 3 rounds | 12 / 16 | ~4× |
| 1-bit differential < 2⁻¹⁶ **[E]** | 3 rounds | 12 / 16 | ~4× |
| Rotational relation broken **[E]** | 1 round | 12 / 16 | — |
| Constant-time (dudect) **[E]** | — | — | \|t\|=0.48 |

Every measured property saturates within 3–5 rounds; p^b = 12 keeps a ≥2.4×
cushion. **Round counts are kept at p^b = 12 / p^a = 16** (the "prioritise
margin" choice). The one outstanding item — a *proven* differential/linear lower
bound via MILP — can only justify *reducing* rounds, which we decline; so the
counts and the Appendix-A KATs are final for v0.1.

## 1. Differential cryptanalysis ◐
- S-box max differential probability = 2/32 = **2⁻⁴** (APN) **[P]**.
- Measured best output-diff probability for a single-bit input difference **[E]**:
  1 round 2⁻³·⁹⁷ (one active S-box), 2 rounds 2⁻¹³, ≥3 rounds below the 2⁻¹⁶
  sampling floor.
- **Solver-free branch-and-bound trail search** (`cryptanalysis activesboxes`):
  the fewest active S-boxes among *single-active-column* differential trails is
  **4 over 2 rounds, 7 over 3 rounds** (differentials cancel the round constants,
  so the structure is rotation-invariant and the start is pinned to position 0).
  The 4-round search exceeds 80M nodes without completing — the minimum grows
  fast, consistent with the empirical collapse above.
- **Honest scope / open item:** those trail counts are single-column-initiated
  and thus an *upper* bound on the true per-window minimum (multi-column starts
  may cancel in the linear layer and do better), so they do **not** by themselves
  certify a security bound. A valid lower bound must search **all** starting
  differences — the full **MILP/SAT** model, which needs a solver. This is the
  one item that cannot be closed rigorously solver-free; it belongs to external
  review (M6). With ≥ 32 active S-boxes a characteristic is < 2⁻¹²⁸ **[X]** — the
  target the MILP would confirm.

## 2. Linear cryptanalysis ◐
- S-box max correlation = 12/32 ≈ 2⁻¹·⁴² **[P]**.
- ≥ 46 active S-boxes ⇒ characteristic correlation < 2⁻⁶⁴ **[X]**.
- **Open:** MILP over the LAT (pairs with §1).

## 3. Algebraic / higher-order ☑ (for the AEAD-relevant range)
- Zero-sum / cube distinguisher **[E]**: for cube dimensions 8, 12, 16 the sum is
  zero only up to **3 rounds**; degree exceeds the cube dimension by round 4.
- Note: bare-permutation zero-sums at high rounds are expected for sponge
  permutations and do not translate into AEAD attacks (the mode never exposes the
  full permutation to chosen inputs at the required rounds).

## 4. Rotational / rotational-XOR ☑
- Rotational relation (rotate all lanes, compare) holds **0 / 2000** trials at
  every round tested **[E]** — the round constants break it in the first round.

## 5. Rebound / hash-specific ☐
- Collision / near-collision search on reduced-round N2Q-Hash — not yet run.

## 6. Integral / division property ◐
- Covered indirectly by the cube/zero-sum results (§3); a dedicated bit-based
  division-property distinguisher is not yet run.

## 7. Structural (slide / invariant subspace / nonlinear invariants) ◐
- Round constants are 16 distinct values XORed into x2 (SPEC §7.3), precluding
  round self-similarity; the rotational result (§4) rules out the simplest
  invariants. A dedicated invariant-subspace search is not yet run.

## 8. Implementation security ☑
- **dudect-lite** Welch t-test over 200k timed permutations, all-zero vs. random
  input class: **|t| = 0.48** (≪ 4.5) — no timing dependence detected **[E]**.
- Consistent with the design: bitsliced S-box (no table), no secret-dependent
  branches or memory addresses; constant-time tag comparison.
- KATs cross-validated across the tool, Rust, and C (Appendix A).

## Remaining for a complete dossier (→ external review, M6)
1. MILP/SAT active-S-box **lower** bounds (§1–§2) — the headline open item. A
   solver-free branch-and-bound is built (best single-column trails: 2R→4, 3R→7)
   but a certified bound needs the all-starts search a solver provides.
2. Rebound analysis of the hash (§5).
3. Dedicated division-property and invariant-subspace searches (§6–§7).
4. The same measurements on QP-640 (the tooling is width-generic).
