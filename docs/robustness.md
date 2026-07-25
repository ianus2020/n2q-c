# N2Q robustness (release of unverified plaintext)

Most AEADs come with a footnote: **do not use any plaintext until the tag
verifies.** In practice implementations break that rule — they decrypt a large
message in a streaming buffer, or a parser touches bytes early — and some modes
degrade badly when that happens. The property that survives such mistakes is
called **robustness under release of unverified plaintext (RUP)**.

## Why N2Q's default mode is naturally robust

The primary mode is **SIV** and it is **two-pass**:

1. the synthetic tag `V` is computed as a PRF over `(nonce, ad, plaintext)`;
2. the keystream that encrypts the plaintext is derived **from `V`**.

Decryption reverses this: recover the plaintext from `V` and the ciphertext, then
recompute the PRF and compare. Two consequences matter for RUP:

- **No public, malleable IV drives the keystream.** In online AEADs (GCM,
  ChaCha-Poly) the keystream depends only on key+nonce, so an attacker who learns
  released plaintext can XOR-manipulate ciphertext into chosen plaintext. In SIV
  the keystream depends on `V`, which depends on the *plaintext itself* — an
  attacker cannot steer it without already knowing the tag.
- **Nonce misuse is already contained.** Repeating a nonce leaks only whether two
  (ad, plaintext) pairs were equal — not a catastrophic keystream reuse.

So even a decryptor that leaks plaintext before checking the tag does not hand an
attacker a chosen-ciphertext lever. The sponge/duplex and SIV proofs are what
underwrite this; the reference `open` still returns nothing on a failed tag.

## Honest scope

RUP-robustness here is a **design property inherited from the SIV/sponge
construction**, argued above — not a machine-checked theorem for N2Q
specifically. Like every other security claim in this project it assumes the QP
permutation is close to ideal and is pending external review (milestone M6).
The practical guidance is unchanged: **still verify before you act on
plaintext** — robustness is a safety net, not a licence.
