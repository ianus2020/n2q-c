/*
 * n2q_commit — key-committing AEAD on top of N2Q-C.
 *
 * A normal AEAD only promises "you can't decrypt without the key". It does NOT
 * promise that a ciphertext belongs to exactly one key. AES-GCM and ChaCha20-
 * Poly1305 are *not* committing: an attacker can craft one ciphertext that
 * decrypts to valid (different) plaintexts under many keys. That is what powers
 * the partitioning-oracle attacks (password-guessing, key-recovery) and the
 * Facebook "franking" break.
 *
 * n2q_commit binds the ciphertext to its key. Alongside the SIV token it emits a
 * 32-byte key commitment  KC = H( 0x07 | key | tag )  which the receiver checks
 * before anything else. To make one ciphertext validate under a second key you
 * would need a hash preimage/collision on KC — infeasible. So each ciphertext
 * commits to exactly one key: the partitioning-oracle class does not apply.
 *
 *   Wire token:  KC(32) | sealed( tag16 | ciphertext )     // +32 B vs plain AEAD
 *
 * Research artifact — committing by construction; a formal bound is an audit item.
 * Not externally audited; not for protecting real data yet.
 */
#ifndef N2Q_COMMIT_H
#define N2Q_COMMIT_H

#include <stddef.h>
#include <stdint.h>

#define N2Q_COMMIT_KC   32                 /* key-commitment bytes */
#define N2Q_COMMIT_OVERHEAD (N2Q_COMMIT_KC + 16) /* KC + 16-byte tag */

/* keylen 16 -> N2Q-128, 32 -> N2Q-256.  fast != 0 -> Fast profile (8 rounds).
 * out needs ptlen + N2Q_COMMIT_OVERHEAD bytes. Returns token length (>0) or 0. */
size_t n2q_seal_committing(const uint8_t *key, int keylen, const uint8_t nonce[16],
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *pt, size_t ptlen, uint8_t *out, int fast);

/* Returns 1 and writes *ptlen on success; 0 on wrong key / wrong commitment /
 * tamper. The key commitment is checked before the SIV tag. */
int n2q_open_committing(const uint8_t *key, int keylen, const uint8_t nonce[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *token, size_t tlen,
                        uint8_t *pt, size_t *ptlen, int fast);

#endif /* N2Q_COMMIT_H */
