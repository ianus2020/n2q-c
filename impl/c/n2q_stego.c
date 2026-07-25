/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_stego — opt-in "indistinguishable-from-random" framing on top of N2Q.
 *
 * The normal N2Q token is self-describing: it starts with "nqc." and carries a
 * version+suite byte so any decoder can read it. That convenience is also a
 * fingerprint — a censor's deep-packet-inspection can spot it. Stego framing is
 * the OPT-IN alternative: it drops every marker and emits raw bytes
 *
 *     out = nonce(16) | sealed( tag | ciphertext )
 *
 * The nonce is random, the tag is a PRF output and the ciphertext is plaintext
 * XOR keystream, so the whole blob is uniform-looking — no header, no version,
 * nothing to match on. The price of hiding the markers is that the suite
 * (128/256) and profile (Fast/Secure) are NOT in the wire: both sides must agree
 * on them out of band. This mode is never on by default; the caller enables it.
 *
 *   size_t n2q_stego_seal(key,keylen,nonce,ad,adlen,pt,ptlen,out,fast)
 *   int    n2q_stego_open(key,keylen,ad,adlen,in,inlen,out,*outlen,fast)
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_STEGO_DEMO n2q_stego.c -o n2q_stego && ./n2q_stego
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

#define N2Q_STEGO_NONCE 16
#define N2Q_STEGO_OVERHEAD (N2Q_STEGO_NONCE + 16) /* random nonce + tag; no header */

/* The caller MUST pass a random `nonce` (16 bytes); otherwise the leading bytes
 * become predictable and the "looks random" property is lost. keylen 16/32. */
size_t n2q_stego_seal(const uint8_t *key, int keylen, const uint8_t nonce[16],
                      const uint8_t *ad, size_t adlen, const uint8_t *pt, size_t ptlen,
                      uint8_t *out, int fast) {
    if (keylen != 16 && keylen != 32) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;
    memcpy(out, nonce, 16); /* raw nonce, no base64, no marker */
    size_t sn = (keylen == 16) ? seal_128(key, nonce, a, adlen, pt, ptlen, out + 16, r)
                               : seal_256(key, nonce, a, adlen, pt, ptlen, out + 16, r);
    return 16 + sn;
}

int n2q_stego_open(const uint8_t *key, int keylen, const uint8_t *ad, size_t adlen,
                   const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen, int fast) {
    if (keylen != 16 && keylen != 32) return 0;
    if (inlen < (size_t)N2Q_STEGO_OVERHEAD) return 0;
    if (!ad) adlen = 0;
    const uint8_t *a = ad ? ad : (const uint8_t *)"";
    int r = fast ? 8 : 16;
    const uint8_t *nonce = in;
    return (keylen == 16) ? open_128(key, nonce, a, adlen, in + 16, inlen - 16, out, outlen, r)
                          : open_256(key, nonce, a, adlen, in + 16, inlen - 16, out, outlen, r);
}

#ifdef N2Q_STEGO_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    init_anf();
    printf("n2q_stego self-test (indistinguishable-from-random framing)\n");
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x60 + i);

    /* a "random" nonce (in real use: from a CSPRNG). Here: derived per message. */
    uint8_t nonce[16];
    hash_128((const uint8_t *)"nonce-seed", 10, nonce, 16, 16);

    const uint8_t msg[] = "meet at the usual place";
    size_t mlen = sizeof msg - 1;
    uint8_t out[128], back[128]; size_t ol;

    size_t n = n2q_stego_seal(key, 16, nonce, NULL, 0, msg, mlen, out, 1);
    ex("round-trip recovers the plaintext",
       n2q_stego_open(key, 16, NULL, 0, out, n, back, &ol, 1) == 1 && ol == mlen &&
           memcmp(back, msg, mlen) == 0);

    /* no recognizable marker: unlike the "nqc." token, nothing fixed at the front */
    ex("output carries no 'nqc.' / 'N2QF' marker",
       memcmp(out, "nqc.", 4) != 0 && memcmp(out, "N2QF", 4) != 0);

    /* differing random nonces -> no constant prefix across messages */
    { uint8_t o2[128]; uint8_t nonce2[16];
      hash_128((const uint8_t *)"nonce-seed-2", 12, nonce2, 16, 16);
      n2q_stego_seal(key, 16, nonce2, NULL, 0, msg, mlen, o2, 1);
      ex("two encryptions share no fixed leading bytes", out[0] != o2[0] || out[1] != o2[1]); }

    /* uniformity: encrypt 64 KiB of ZEROS; the ciphertext byte histogram must look
       flat (chi-square near the 255 d.o.f. mean) — no structure a censor can match */
    {
        enum { M = 65536 };
        static uint8_t zeros[M], big[M + 64];
        memset(zeros, 0, M);
        uint8_t nz[16];
        hash_128((const uint8_t *)"big", 3, nz, 16, 16);
        size_t bn = n2q_stego_seal(key, 16, nz, NULL, 0, zeros, M, big, 1);
        long hist[256] = {0};
        for (size_t i = 16; i < bn; i++) hist[big[i]]++; /* skip the 16 nonce bytes */
        long total = (long)(bn - 16);
        double exp = total / 256.0, chi = 0;
        int covered = 0;
        for (int v = 0; v < 256; v++) { if (hist[v]) covered++; double d = hist[v] - exp; chi += d * d / exp; }
        printf("  all-zero plaintext -> ciphertext histogram: chi-square=%.1f (df 255), byte values seen=%d/256\n",
               chi, covered);
        ex("ciphertext of all-zeros looks uniform (chi-square < 350, full coverage)",
           chi < 350.0 && covered == 256);
    }

    /* tamper -> rejected */
    out[n - 1] ^= 0x40;
    ex("tampered blob rejected", n2q_stego_open(key, 16, NULL, 0, out, n, back, &ol, 1) == 0);

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
