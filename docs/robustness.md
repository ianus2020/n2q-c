# Plaintext must remain private until authentication succeeds

N2Q's SIV mode does **not** establish robustness under release of unverified
plaintext (RUP). The earlier argument in this document was incorrect and is
withdrawn. No RUP security proof for N2Q is provided.

A sealed message is `V || C`. The tag `V` is public. If a decryptor releases
plaintext before verifying the tag, an attacker can keep `V`, replace `C` with
zeroes, and obtain the keystream for that `V`. XOR with the original ciphertext
then reveals the original plaintext. The final tag rejection does not undo this
leak. SIV nonce-misuse resistance does not imply safe release before verification.

The reference `open` APIs return plaintext only after checking the tag. C callers
must check the return value: failed SIV/stream opens set the output length to zero
and wipe tentative plaintext in the caller's buffer. The raw C APIs still require
correctly sized buffers and keys; they cannot infer pointer capacities. They do
not make concurrent reads of tentative plaintext safe.

N2QF v2 file helpers use private temporary output and only publish it after the
mandatory final record and EOF have been verified. Chunk-selection helpers also
verify the whole container before releasing the selected chunk. See
[n2qf.md](n2qf.md) for framing, migration and limits.

These implementation rules prevent known release paths. They do not constitute
an independent cryptographic audit or a general memory-erasure guarantee.
