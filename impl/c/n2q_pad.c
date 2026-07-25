/*
 * n2q_pad — length-hiding AEAD on top of N2Q-C.
 *
 * A normal AEAD leaks the exact plaintext length through the ciphertext length.
 * On chat / VoIP / web traffic that length alone reveals a lot (which message,
 * which page, typing patterns). n2q_pad hides it: the plaintext is length-
 * prefixed and zero-padded up to the next `bucket` boundary before sealing, so
 * the ciphertext size only reveals which bucket the message fell into.
 *
 *   padded = le32(len) | plaintext | 0x00…   (rounded up to a multiple of bucket)
 *   token  = SIV_seal(key, nonce, ad, padded)
 *
 * API (keylen 16 -> N2Q-128, 32 -> N2Q-256; fast != 0 -> Fast profile):
 *   size_t n2q_seal_padded(key,keylen,nonce,ad,adlen,pt,ptlen,out,fast,bucket)
 *   int    n2q_open_padded(key,keylen,nonce,ad,adlen,token,tlen,pt,*ptlen,fast)
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_PAD_DEMO n2q_pad.c -o n2q_pad && ./n2q_pad
 * Research artifact — not externally audited; not for protecting real data yet.
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

size_t n2q_seal_padded(const uint8_t *key, int keylen, const uint8_t nonce[16],
                       const uint8_t *ad, size_t adlen, const uint8_t *pt, size_t ptlen,
                       uint8_t *out, int fast, size_t bucket) {
    if ((keylen != 16 && keylen != 32) || bucket == 0) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;

    size_t need = 4 + ptlen;
    size_t padded = ((need + bucket - 1) / bucket) * bucket;
    uint8_t *buf = calloc(padded ? padded : 1, 1);
    for (int i = 0; i < 4; i++) buf[i] = (uint8_t)((uint32_t)ptlen >> (8 * i));
    memcpy(buf + 4, pt, ptlen);

    size_t n = (keylen == 16) ? seal_128(key, nonce, a, adlen, buf, padded, out, r)
                              : seal_256(key, nonce, a, adlen, buf, padded, out, r);
    memset(buf, 0, padded);
    free(buf);
    return n;
}

int n2q_open_padded(const uint8_t *key, int keylen, const uint8_t nonce[16],
                    const uint8_t *ad, size_t adlen, const uint8_t *token, size_t tlen,
                    uint8_t *pt, size_t *ptlen, int fast) {
    if (keylen != 16 && keylen != 32) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;

    uint8_t *buf = calloc(tlen ? tlen : 1, 1);
    size_t plen = 0;
    int ok = (keylen == 16) ? open_128(key, nonce, a, adlen, token, tlen, buf, &plen, r)
                            : open_256(key, nonce, a, adlen, token, tlen, buf, &plen, r);
    if (!ok || plen < 4) { free(buf); return 0; }
    uint32_t real = 0;
    for (int i = 0; i < 4; i++) real |= (uint32_t)buf[i] << (8 * i);
    if (4 + (size_t)real > plen) { memset(buf, 0, plen); free(buf); return 0; }
    memcpy(pt, buf + 4, real);
    *ptlen = real;
    memset(buf, 0, plen);
    free(buf);
    return 1;
}

#ifdef N2Q_PAD_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    init_anf();
    printf("n2q_pad self-test (length-hiding)\n");
    uint8_t key[16], nonce[16];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)i; nonce[i] = (uint8_t)(0x20 + i); }
    const size_t B = 256;

    uint8_t a[300], b[300], out[1024];
    memset(a, 'A', sizeof a);
    memset(b, 'B', sizeof b);

    /* two very different lengths (10 and 200) fall in the same 256-byte bucket */
    size_t t1 = n2q_seal_padded(key, 16, nonce, NULL, 0, a, 10, out, 1, B);
    uint8_t out2[1024];
    size_t t2 = n2q_seal_padded(key, 16, nonce, NULL, 0, b, 200, out2, 1, B);
    ex("10-byte and 200-byte messages produce equal-length ciphertext", t1 == t2);

    /* a 300-byte message spills into the next bucket (512) -> larger */
    uint8_t out3[1024];
    size_t t3 = n2q_seal_padded(key, 16, nonce, NULL, 0, a, 300, out3, 1, B);
    ex("300-byte message uses the next bucket (larger ciphertext)", t3 > t1);

    /* round-trip recovers the exact plaintext and length */
    uint8_t rec[300]; size_t rl;
    ex("round-trip recovers exact plaintext (10 bytes)",
       n2q_open_padded(key, 16, nonce, NULL, 0, out, t1, rec, &rl, 1) == 1 && rl == 10 &&
           memcmp(rec, a, 10) == 0);
    ex("round-trip recovers exact plaintext (300 bytes)",
       n2q_open_padded(key, 16, nonce, NULL, 0, out3, t3, rec, &rl, 1) == 1 && rl == 300 &&
           memcmp(rec, a, 300) == 0);

    /* tamper -> rejected */
    out[t1 - 1] ^= 0x40;
    ex("tampered ciphertext rejected", n2q_open_padded(key, 16, nonce, NULL, 0, out, t1, rec, &rl, 1) == 0);

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
