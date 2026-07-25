/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_seek — random-access (seekable) decryption for the N2QF container.
 *
 * N2QF stores a file as independent, individually-authenticated chunks, each
 * sealed under a nonce derived from its index. That means you can jump straight
 * to any chunk and decrypt just it — scrub an encrypted 4K video, range-read an
 * encrypted archive, resume a download — without processing everything before
 * it. This is the seek that a single big AEAD blob cannot give you.
 *
 *   container: "N2QF" | ver | suite | { le32(len) | sealed(tag|ct) }*
 *   chunk i nonce = 16-byte little-endian i
 *
 *   int n2q_seek_chunk(key, buf, buflen, index, out, *outlen)  // 0 on success
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_SEEK_DEMO n2q_seek.c -o n2q_seek && ./n2q_seek
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

enum { N2Q_SEEK_OK = 0, N2Q_SEEK_RANGE = -1, N2Q_SEEK_FORMAT = -2,
       N2Q_SEEK_TRUNC = -3, N2Q_SEEK_AUTH = -4, N2Q_SEEK_SUITE = -5 };

/* Decrypt only chunk `index` of an in-memory N2QF container (N2Q-128 suite). */
int n2q_seek_chunk(const uint8_t *key, const uint8_t *buf, size_t buflen,
                   uint64_t index, uint8_t *out, size_t *outlen) {
    if (buflen < 6 || memcmp(buf, "N2QF", 4) != 0) return N2Q_SEEK_FORMAT;
    if ((buf[5] & 0x0f) != 0x01) return N2Q_SEEK_SUITE; /* this helper handles N2Q-128 */
    int r = (buf[5] & 0x20) ? 8 : 16;

    size_t p = 6;
    uint64_t i = 0;
    while (p + 4 <= buflen) {
        uint32_t l = (uint32_t)buf[p] | ((uint32_t)buf[p + 1] << 8) |
                     ((uint32_t)buf[p + 2] << 16) | ((uint32_t)buf[p + 3] << 24);
        p += 4;
        if (p + l > buflen) return N2Q_SEEK_TRUNC;
        if (i == index) {
            uint8_t nonce[16] = {0};
            for (int b = 0; b < 8; b++) nonce[b] = (uint8_t)(index >> (8 * b));
            return open_128(key, nonce, (const uint8_t *)"", 0, buf + p, l, out, outlen, r)
                       ? N2Q_SEEK_OK : N2Q_SEEK_AUTH;
        }
        p += l;
        i++;
    }
    return N2Q_SEEK_RANGE;
}

#ifdef N2Q_SEEK_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

/* build a small N2QF container in-memory from `n` fixed-size chunks */
static size_t build(const uint8_t *key, uint8_t plain[][100], int n, uint8_t *buf) {
    buf[0] = 'N'; buf[1] = '2'; buf[2] = 'Q'; buf[3] = 'F'; buf[4] = 1; buf[5] = 0x21; /* 128 Fast */
    size_t p = 6;
    for (int i = 0; i < n; i++) {
        uint8_t nonce[16] = {0};
        for (int b = 0; b < 8; b++) nonce[b] = (uint8_t)((uint64_t)i >> (8 * b));
        uint8_t sealed[160];
        size_t sn = seal_128(key, nonce, (const uint8_t *)"", 0, plain[i], 100, sealed, 8);
        buf[p] = (uint8_t)sn; buf[p + 1] = (uint8_t)(sn >> 8); buf[p + 2] = 0; buf[p + 3] = 0;
        p += 4;
        memcpy(buf + p, sealed, sn);
        p += sn;
    }
    return p;
}

int main(void) {
    init_anf();
    printf("n2q_seek self-test (random-access N2QF)\n");
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x44 + i);

    enum { N = 6 };
    static uint8_t plain[N][100];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < 100; j++) plain[i][j] = (uint8_t)(i * 41 + j);

    static uint8_t buf[4096];
    size_t blen = build(key, plain, N, buf);

    uint8_t out[100]; size_t ol;
    /* jump straight to chunk 4 without touching 0..3 */
    ex("seek chunk 4 decrypts to the right block",
       n2q_seek_chunk(key, buf, blen, 4, out, &ol) == N2Q_SEEK_OK && ol == 100 &&
           memcmp(out, plain[4], 100) == 0);
    /* and to chunk 1 */
    ex("seek chunk 1 decrypts to the right block",
       n2q_seek_chunk(key, buf, blen, 1, out, &ol) == N2Q_SEEK_OK && memcmp(out, plain[1], 100) == 0);
    /* out-of-range index */
    ex("seek past the end reports range error",
       n2q_seek_chunk(key, buf, blen, 99, out, &ol) == N2Q_SEEK_RANGE);
    /* a tampered chunk fails its own auth without affecting the others */
    { size_t save_i = 6 + 4 + 20; uint8_t save = buf[save_i]; buf[save_i] ^= 0x40;
      ex("tampered chunk 0 fails auth", n2q_seek_chunk(key, buf, blen, 0, out, &ol) == N2Q_SEEK_AUTH);
      buf[save_i] = save;
      ex("chunk 5 still fine after another chunk was tampered",
         n2q_seek_chunk(key, buf, blen, 5, out, &ol) == N2Q_SEEK_OK && memcmp(out, plain[5], 100) == 0); }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
