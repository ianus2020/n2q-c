#ifndef N2Q_CONE_STATE_H
#define N2Q_CONE_STATE_H
#include <stddef.h>
#include <stdint.h>
#define N2Q_CONE_SEED_BYTES 32
#define N2Q_CONE_ROOT_BYTES 32
#define N2Q_CONE_SIGNATURE_BYTES 2276
#define N2Q_CONE_MAX_MESSAGE (1U << 20)
enum {
    N2Q_CN_OK = 0, N2Q_CN_ARG = -1, N2Q_CN_IO = -2,
    N2Q_CN_STATE = -3, N2Q_CN_EXHAUSTED = -4, N2Q_CN_ANCHOR = -5
};
/* REQUIRED trust boundary: atomically and durably accept index only if it is
 * greater than EVERY previously accepted index for key_id, across all copies,
 * processes and restored snapshots. Return exactly 1 only after persistence.
 * The anchor must live outside the signer's rollback domain; an in-memory
 * callback or a backup of the same local file does not meet this contract. */
typedef int (*n2q_cone_anchor_fn)(void *context, const uint8_t key_id[32], uint32_t index);
int n2q_cone_public_root(const uint8_t seed[32], uint8_t *root, size_t rootcap);
int n2q_cone_verify_certificate(const uint8_t root[32], const uint8_t *msg, size_t mlen,
                                 const uint8_t *sig, size_t slen);
/* Creates a NEW journal exclusively; never recreates/reset state while signing.
 * Journal stores no seed. Path parent must be owned by the effective user and
 * must not be group/world-writable. Existing paths and symlinks are rejected. */
int n2q_cone_state_create(const uint8_t seed[32], const char *path);
/* Reserve + fsync local state, then confirm the external monotonic anchor,
 * then sign. Failures may burn an index; they never roll it back. Missing,
 * malformed, copied-to-another-key or exhausted journals fail closed.
 * A missing/unavailable anchor produces no signature. */
int n2q_cone_sign_reserved(const uint8_t seed[32], const char *path,
                            n2q_cone_anchor_fn anchor, void *context,
                            const uint8_t *msg, size_t mlen,
                            uint8_t *sig, size_t sigcap, size_t *siglen);
#endif
