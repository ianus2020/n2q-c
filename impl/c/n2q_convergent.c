/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_convergent — convergent (dedup-friendly) encryption on top of N2Q.
 *
 * Cloud/backup storage wants to store identical blobs once, even when encrypted.
 * Convergent encryption derives the data key deterministically from the content,
 * so identical plaintext always yields identical ciphertext and can be
 * deduplicated — while a plain random-keyed AEAD would produce a different blob
 * every time. We key the derivation with a per-tenant master key so that only
 * holders of that key can produce/deduplicate, blunting the confirmation-of-file
 * attack that unkeyed convergent encryption suffers from.
 *
 *   dek = H( masterkey_16_bytes | content )[0:16] // fixed boundary, deterministic
 *   ct  = SIV_seal(dek, nonce=0, "n2q-conv", content)
 *   (store `ct` once; each owner keeps the small `dek` to read it back)
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_CONV_DEMO n2q_convergent.c -o n2q_conv && ./n2q_conv
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

static const uint8_t CONV_AD[] = "n2q-conv";
static const uint8_t CONV_NONCE[16] = {0}; /* deterministic on purpose (SIV) */
#define N2Q_CONV_MAX_CONTENT (16U * 1024U * 1024U)

/* Derive the convergent key and seal. Outputs dek (16 bytes) and returns ct length. */
size_t n2q_conv_seal(const uint8_t *mk, int mklen, const uint8_t *content, size_t len,
                     uint8_t dek[16], uint8_t *out, size_t outcap, int fast) {
    if (!mk || mklen != 16 || !dek || !out || (len && !content) ||
        len > N2Q_CONV_MAX_CONTENT || outcap < len + 16 || (fast != 0 && fast != 1)) return 0;
    /* dek = H(mk | content) truncated to 16 bytes */
    uint8_t *buf = malloc((size_t)mklen + len);
    if (!buf) return 0;
    memcpy(buf, mk, (size_t)mklen);
    if (len) memcpy(buf + mklen, content, len);
    uint8_t h[32];
    hash_128(buf, (size_t)mklen + len, h, 32, 16);
    memcpy(dek, h, 16);
    secure_wipe(buf, (size_t)mklen + len);
    secure_wipe(h, sizeof h);
    free(buf);
    return seal_128(dek, CONV_NONCE, CONV_AD, sizeof CONV_AD - 1, content, len, out, fast ? 8 : 16);
}

int n2q_conv_open(const uint8_t dek[16], const uint8_t *ct, size_t ctlen,
                  uint8_t *out, size_t outcap, size_t *outlen, int fast) {
    if (outlen) *outlen = 0;
    if (!dek || !ct || !out || !outlen || ctlen < 16 || ctlen > N2Q_CONV_MAX_CONTENT + 16 ||
        outcap < ctlen - 16 || (fast != 0 && fast != 1)) return 0;
    return open_128(dek, CONV_NONCE, CONV_AD, sizeof CONV_AD - 1, ct, ctlen, out, outlen, fast ? 8 : 16);
}

#ifdef N2Q_CONV_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    init_anf();
    printf("n2q_convergent self-test (dedup-friendly encryption)\n");
    uint8_t mk[16];
    for (int i = 0; i < 16; i++) mk[i] = (uint8_t)(0x11 * i);

    const uint8_t fileA[] = "the same backup blob, byte for byte";
    const uint8_t fileB[] = "a different file entirely";
    size_t la = sizeof fileA - 1, lb = sizeof fileB - 1;

    uint8_t d1[16], d2[16], d3[16], c1[128], c2[128], c3[128];
    size_t n1 = n2q_conv_seal(mk, 16, fileA, la, d1, c1, sizeof c1, 1);
    size_t n2 = n2q_conv_seal(mk, 16, fileA, la, d2, c2, sizeof c2, 1); /* same content again */
    size_t n3 = n2q_conv_seal(mk, 16, fileB, lb, d3, c3, sizeof c3, 1);

    ex("identical content -> identical ciphertext (dedup)",
       n1 == n2 && memcmp(c1, c2, n1) == 0 && memcmp(d1, d2, 16) == 0);
    ex("different content -> different ciphertext",
       n1 != n3 || memcmp(c1, c3, n1 < n3 ? n1 : n3) != 0);

    uint8_t out[128]; size_t ol;
    ex("decrypt with the derived key recovers content",
       n2q_conv_open(d1, c1, n1, out, sizeof out, &ol, 1) == 1 && ol == la && memcmp(out, fileA, la) == 0);

    /* wrong master key -> different dek -> cannot decrypt this ciphertext */
    uint8_t mk2[16]; memcpy(mk2, mk, 16); mk2[0] ^= 1;
    uint8_t dx[16], cx[128];
    n2q_conv_seal(mk2, 16, fileA, la, dx, cx, sizeof cx, 1);
    ex("a different tenant key yields a different dek", memcmp(d1, dx, 16) != 0);

    /* tamper -> rejected */
    c1[n1 - 1] ^= 0x40;
    ex("tampered ciphertext rejected", n2q_conv_open(d1, c1, n1, out, sizeof out, &ol, 1) == 0);

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
