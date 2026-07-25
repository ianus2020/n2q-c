/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_envelope — envelope encryption & key rotation on top of N2Q.
 *
 * Bulk data is encrypted once under a random per-object data key (DEK); the DEK
 * is then wrapped (sealed) under a key-encryption key (KEK) and stored next to
 * the ciphertext. To rotate the KEK you only re-wrap the tiny DEK blob — the
 * bulk ciphertext is never touched or re-encrypted. This is the AWS-KMS-style
 * pattern that lets you rotate keys across terabytes of data in milliseconds.
 *
 *   wrap:    blob = SIV_seal(KEK, "n2q-envelope-v1", DEK)      // +16 B tag
 *   rotate:  blob' = wrap(KEK_new, unwrap(KEK_old, blob))      // data untouched
 */
#ifndef N2Q_ENVELOPE_H
#define N2Q_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>

#define N2Q_WRAP_OVERHEAD 16 /* SIV tag */

/* Wrap a data key. keklen 16 -> N2Q-128, 32 -> N2Q-256. out needs
 * deklen + N2Q_WRAP_OVERHEAD bytes. Returns blob length or 0 on bad args. */
size_t n2q_wrap(const uint8_t *kek, int keklen,
                const uint8_t *dek, size_t deklen, uint8_t *out);

/* Unwrap. Returns 1 and writes dek and deklen on success; 0 on wrong KEK / tamper. */
int n2q_unwrap(const uint8_t *kek, int keklen,
               const uint8_t *blob, size_t blen, uint8_t *dek, size_t *deklen);

/* Rotate the KEK: unwrap under old, re-wrap under new. The bulk data that the
 * DEK protects is not touched. Returns the new blob length, or 0 if the old blob
 * does not authenticate under old_kek. */
size_t n2q_rewrap(const uint8_t *old_kek, int oklen, const uint8_t *new_kek, int nklen,
                  const uint8_t *blob, size_t blen, uint8_t *out);

#endif /* N2Q_ENVELOPE_H */
