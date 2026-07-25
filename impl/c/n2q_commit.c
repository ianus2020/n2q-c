/*
 * n2q_commit — key-committing AEAD. See n2q_commit.h.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_COMMIT_DEMO n2q_commit.c -o n2q_commit && ./n2q_commit
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c" /* seal_128/open_128, seal_256/open_256, hash_128 */

#include "n2q_commit.h"
#include <string.h>

/* KC = H( 0x07 | key | tag ) — binds the ciphertext to exactly one key. */
static void commit(const uint8_t *key, int keylen, const uint8_t *tag, uint8_t kc[32]) {
    uint8_t buf[1 + 32 + 16];
    buf[0] = 0x07;
    memcpy(buf + 1, key, (size_t)keylen);
    memcpy(buf + 1 + keylen, tag, 16);
    hash_128(buf, (size_t)(1 + keylen + 16), kc, 32, 16); /* Secure rounds */
    memset(buf, 0, sizeof buf);
}

size_t n2q_seal_committing(const uint8_t *key, int keylen, const uint8_t nonce[16],
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *pt, size_t ptlen, uint8_t *out, int fast) {
    if (!key || !out || (keylen != 16 && keylen != 32)) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;

    size_t sn = (keylen == 16) ? seal_128(key, nonce, a, adlen, pt, ptlen, out + N2Q_COMMIT_KC, r)
                               : seal_256(key, nonce, a, adlen, pt, ptlen, out + N2Q_COMMIT_KC, r);
    commit(key, keylen, out + N2Q_COMMIT_KC, out); /* tag is the first 16 bytes of the token */
    return N2Q_COMMIT_KC + sn;
}

int n2q_open_committing(const uint8_t *key, int keylen, const uint8_t nonce[16],
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *token, size_t tlen,
                        uint8_t *pt, size_t *ptlen, int fast) {
    if (!key || !token || (keylen != 16 && keylen != 32)) return 0;
    if (tlen < (size_t)N2Q_COMMIT_OVERHEAD) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;

    const uint8_t *kc = token;
    const uint8_t *inner = token + N2Q_COMMIT_KC;
    size_t il = tlen - N2Q_COMMIT_KC;

    /* check the key commitment first (constant time) */
    uint8_t kc2[32];
    commit(key, keylen, inner, kc2); /* inner starts with the 16-byte tag */
    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= kc[i] ^ kc2[i];
    memset(kc2, 0, sizeof kc2);
    if (diff) return 0; /* ciphertext does not commit to this key */

    return (keylen == 16) ? open_128(key, nonce, a, adlen, inner, il, pt, ptlen, r)
                          : open_256(key, nonce, a, adlen, inner, il, pt, ptlen, r);
}

/* -------------------------------------------------------------------------- */
#ifdef N2Q_COMMIT_DEMO
#include <stdio.h>

static int failc = 0;
static void expect(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) failc++;
}

int main(void) {
    init_anf();
    printf("n2q_commit self-test (key-committing AEAD)\n");

    uint8_t key[16], nonce[16], token[256], out[256];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)(0x30 + i); nonce[i] = (uint8_t)(0xa0 + i); }
    const uint8_t ad[3] = {'a', 'd', 0};
    const uint8_t pt[] = "transfer 100 to bob";
    size_t ptlen = sizeof pt - 1, ol;

    size_t tl = n2q_seal_committing(key, 16, nonce, ad, sizeof ad, pt, ptlen, token, 1);

    expect("correct key opens and matches",
           n2q_open_committing(key, 16, nonce, ad, sizeof ad, token, tl, out, &ol, 1) == 1 &&
               ol == ptlen && memcmp(out, pt, ptlen) == 0);

    /* wrong key -> rejected at the commitment layer */
    { uint8_t k2[16]; memcpy(k2, key, 16); k2[0] ^= 1;
      expect("wrong key rejected",
             n2q_open_committing(k2, 16, nonce, ad, sizeof ad, token, tl, out, &ol, 1) == 0); }

    /* tamper the key commitment -> rejected */
    { uint8_t bad[256]; memcpy(bad, token, tl); bad[3] ^= 0x40;
      expect("tampered commitment rejected",
             n2q_open_committing(key, 16, nonce, ad, sizeof ad, bad, tl, out, &ol, 1) == 0); }

    /* tamper the ciphertext -> rejected */
    { uint8_t bad[256]; memcpy(bad, token, tl); bad[tl - 1] ^= 0x40;
      expect("tampered ciphertext rejected",
             n2q_open_committing(key, 16, nonce, ad, sizeof ad, bad, tl, out, &ol, 1) == 0); }

    /* THE committing property: sweep random keys; NONE may validate this one
       ciphertext (that impossibility is exactly what stops partitioning oracles). */
    long N = 100000, hits = 0;
    uint8_t rk[16];
    uint32_t x = 0x9e3779b9u;
    for (long i = 0; i < N; i++) {
        for (int b = 0; b < 16; b++) { x = x * 1664525u + 1013904223u; rk[b] = (uint8_t)(x >> 17); }
        if (n2q_open_committing(rk, 16, nonce, ad, sizeof ad, token, tl, out, &ol, 1) == 1) hits++;
    }
    printf("  swept %ld random keys against one ciphertext -> %ld opened\n", N, hits);
    expect("no random key opens the ciphertext (commits to one key)", hits == 0);

    printf("%s (%d failures)\n", failc == 0 ? "ALL PASS" : "FAILURES", failc);
    return failc ? 1 : 0;
}
#endif /* N2Q_COMMIT_DEMO */
