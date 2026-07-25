/*
 * N2Q-C reference implementation (C) — QP permutation, constant-time bitsliced.
 *
 * The S-box is applied from its algebraic normal form (no table lookup, no
 * branch, no secret-dependent memory access). The built-in self-test reproduces
 * the Appendix A known-answer vectors and cross-checks against the Rust/tool
 * references.  Research artifact — not for protecting real data yet.
 *
 * Build & self-test:  cc -O2 -Wall -Wextra n2qc.c -o n2qc && ./n2qc
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- fixed constants (Appendix A / M2) ---- */
static const uint8_t SBOX[32] = {
    0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
    0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09};
static const uint8_t RC[16] = {0x15, 0xe3, 0x2d, 0xa2, 0x5e, 0x5c, 0xab, 0xae,
                               0xc8, 0x9b, 0xb6, 0xb3, 0xeb, 0xbf, 0xd9, 0xf2};
static const unsigned ROTS320[5][2] = {{38, 55}, {1, 23}, {23, 36}, {16, 14}, {20, 46}};
static const unsigned ROTS640[5][2] = {{75, 7}, {89, 21}, {56, 111}, {30, 54}, {25, 52}};

/* ---- S-box ANF (derived once from the table) ---- */
static uint8_t anf_mono[5][32];
static int anf_cnt[5];

static void init_anf(void) {
    for (int bit = 0; bit < 5; bit++) {
        uint8_t tt[32];
        for (int x = 0; x < 32; x++)
            tt[x] = (SBOX[x] >> bit) & 1;
        for (int step = 1; step < 32; step <<= 1)
            for (int i = 0; i < 32; i += step << 1)
                for (int j = i; j < i + step; j++)
                    tt[j + step] ^= tt[j];
        int c = 0;
        for (int m = 0; m < 32; m++)
            if (tt[m] & 1)
                anf_mono[bit][c++] = (uint8_t)m;
        anf_cnt[bit] = c;
    }
}

/* ---- permutation, one definition per lane width via a macro ---- */
#define DEFINE_QP(NAME, TYPE, WIDTH)                                              \
    static TYPE rotr_##NAME(TYPE x, unsigned r) {                                 \
        return (TYPE)((x >> r) | (x << (WIDTH - r)));                             \
    }                                                                            \
    static void NAME(TYPE s[5], const unsigned rots[5][2], int rounds) {         \
        const TYPE ONES = (TYPE)~(TYPE)0;                                         \
        for (int i = 0; i < rounds; i++) {                                        \
            s[2] ^= (TYPE)RC[i];                       /* pC */                   \
            TYPE out[5];                                /* pS (bitsliced ANF) */  \
            for (int k = 0; k < 5; k++) {                                         \
                TYPE acc = 0;                                                     \
                for (int t = 0; t < anf_cnt[k]; t++) {                            \
                    uint8_t m = anf_mono[k][t];                                   \
                    TYPE term = ONES;                                             \
                    for (int b = 0; b < 5; b++)                                   \
                        if ((m >> b) & 1)                                         \
                            term &= s[b];                                         \
                    acc ^= term;                                                  \
                }                                                                 \
                out[k] = acc;                                                     \
            }                                                                    \
            for (int k = 0; k < 5; k++)                                           \
                s[k] = out[k];                                                    \
            for (int k = 0; k < 5; k++)               /* pL */                    \
                s[k] ^= rotr_##NAME(s[k], rots[k][0]) ^ rotr_##NAME(s[k], rots[k][1]); \
        }                                                                        \
    }

DEFINE_QP(qp320, uint64_t, 64)
DEFINE_QP(qp640, __uint128_t, 128)

/* ---- N2Q modes (macro over lane width; must match the Rust reference) ---- */
#define ROUNDS_A 16
#define ROUNDS_B 12
#define DOM_HASH 1
#define DOM_MAC 2
#define DOM_ENC 3
#define DOM_BI 4
#define DOM_STREAM 5

/* width-independent SIV framing: nonce ‖ le64(|ad|) ‖ ad ‖ le64(|pt|) ‖ pt */
static uint8_t *siv_input(const uint8_t *nonce, const uint8_t *ad, size_t adlen, const uint8_t *pt,
                          size_t ptlen, size_t *outlen) {
    size_t ilen = 16 + 8 + adlen + 8 + ptlen;
    uint8_t *in = calloc(ilen, 1);
    size_t p = 0;
    memcpy(in + p, nonce, 16);
    p += 16;
    for (int i = 0; i < 8; i++)
        in[p + i] = (uint8_t)((uint64_t)adlen >> (8 * i));
    p += 8;
    memcpy(in + p, ad, adlen);
    p += adlen;
    for (int i = 0; i < 8; i++)
        in[p + i] = (uint8_t)((uint64_t)ptlen >> (8 * i));
    p += 8;
    memcpy(in + p, pt, ptlen);
    *outlen = ilen;
    return in;
}

/* `r` = round count for the sponge f (Secure=16, Fast=8), used uniformly. */
#define DEFINE_MODES(SFX, TYPE, B, QPFUN, ROTS)                                                  \
    static TYPE rd_##SFX(const uint8_t *p) {                                                     \
        TYPE v = 0;                                                                              \
        for (int i = 0; i < B; i++)                                                              \
            v |= (TYPE)p[i] << (8 * i);                                                          \
        return v;                                                                                \
    }                                                                                            \
    static void wr_##SFX(uint8_t *p, TYPE v) {                                                   \
        for (int i = 0; i < B; i++)                                                              \
            p[i] = (uint8_t)(v >> (8 * i));                                                      \
    }                                                                                            \
    static void f_##SFX(TYPE s[5], int r) { QPFUN(s, ROTS, r); }                                 \
    static void absorb_##SFX(TYPE s[5], const uint8_t *m, size_t len, int r) {                   \
        size_t pl = ((len + 1 + (B - 1)) / B) * B;                                               \
        uint8_t *b = calloc(pl, 1);                                                              \
        memcpy(b, m, len);                                                                       \
        b[len] = 0x01;                                                                           \
        b[pl - 1] |= 0x80;                                                                       \
        for (size_t o = 0; o < pl; o += B) {                                                     \
            s[0] ^= rd_##SFX(b + o);                                                             \
            f_##SFX(s, r);                                                                       \
        }                                                                                        \
        free(b);                                                                                 \
    }                                                                                            \
    static void squeeze_##SFX(TYPE s[5], uint8_t *out, size_t n, int r) {                        \
        size_t d = 0;                                                                            \
        while (d < n) {                                                                          \
            uint8_t blk[16];                                                                     \
            wr_##SFX(blk, s[0]);                                                                 \
            size_t take = (n - d < (size_t)B) ? (n - d) : (size_t)B;                             \
            memcpy(out + d, blk, take);                                                          \
            d += B;                                                                              \
            f_##SFX(s, r);                                                                       \
        }                                                                                        \
    }                                                                                            \
    static void hash_##SFX(const uint8_t *m, size_t len, uint8_t *out, size_t ol, int r) {       \
        TYPE s[5] = {0, 0, 0, 0, 0};                                                             \
        s[4] ^= (TYPE)DOM_HASH;                                                                  \
        f_##SFX(s, r);                                                                           \
        absorb_##SFX(s, m, len, r);                                                              \
        squeeze_##SFX(s, out, ol, r);                                                            \
    }                                                                                            \
    static void mac_##SFX(const uint8_t *k, const uint8_t *dt, size_t len, int dom, uint8_t *out, int r) { \
        TYPE s[5] = {0, 0, 0, 0, 0};                                                             \
        s[1] = rd_##SFX(k);                                                                      \
        s[2] = rd_##SFX(k + B);                                                                  \
        s[4] ^= (TYPE)dom;                                                                       \
        f_##SFX(s, r);                                                                           \
        absorb_##SFX(s, dt, len, r);                                                             \
        squeeze_##SFX(s, out, 2 * B, r);                                                         \
    }                                                                                            \
    static void ks_##SFX(const uint8_t *k, const uint8_t *v, uint8_t *out, size_t n, int r) {    \
        TYPE s[5] = {0, 0, 0, 0, 0};                                                             \
        s[1] = rd_##SFX(k);                                                                      \
        s[2] = rd_##SFX(k + B);                                                                  \
        s[3] = rd_##SFX(v);                                                                      \
        s[4] = rd_##SFX(v + B) ^ (TYPE)DOM_ENC;                                                  \
        f_##SFX(s, r);                                                                           \
        squeeze_##SFX(s, out, n, r);                                                             \
    }                                                                                            \
    static size_t seal_##SFX(const uint8_t *k, const uint8_t *nc, const uint8_t *ad, size_t al,  \
                             const uint8_t *pt, size_t pl, uint8_t *out, int r) {                \
        size_t il;                                                                               \
        uint8_t *in = siv_input(nc, ad, al, pt, pl, &il);                                        \
        uint8_t v[2 * B];                                                                        \
        mac_##SFX(k, in, il, DOM_MAC, v, r);                                                     \
        free(in);                                                                                \
        uint8_t *kbuf = calloc(pl ? pl : 1, 1);                                                  \
        ks_##SFX(k, v, kbuf, pl, r);                                                             \
        memcpy(out, v, 2 * B);                                                                   \
        for (size_t i = 0; i < pl; i++)                                                          \
            out[2 * B + i] = pt[i] ^ kbuf[i];                                                    \
        free(kbuf);                                                                              \
        return 2 * B + pl;                                                                       \
    }                                                                                            \
    static int open_##SFX(const uint8_t *k, const uint8_t *nc, const uint8_t *ad, size_t al,     \
                          const uint8_t *sealed, size_t slen, uint8_t *pt, size_t *ptlen, int r) { \
        if (slen < (size_t)(2 * B))                                                              \
            return 0;                                                                            \
        const uint8_t *v = sealed, *ct = sealed + 2 * B;                                         \
        size_t ctl = slen - 2 * B;                                                               \
        uint8_t *kbuf = calloc(ctl ? ctl : 1, 1);                                                \
        ks_##SFX(k, v, kbuf, ctl, r);                                                            \
        for (size_t i = 0; i < ctl; i++)                                                         \
            pt[i] = ct[i] ^ kbuf[i];                                                             \
        free(kbuf);                                                                              \
        size_t il;                                                                               \
        uint8_t *in = siv_input(nc, ad, al, pt, ctl, &il);                                       \
        uint8_t v2[2 * B];                                                                       \
        mac_##SFX(k, in, il, DOM_MAC, v2, r);                                                    \
        free(in);                                                                                \
        int diff = 0;                                                                            \
        for (int i = 0; i < 2 * B; i++)                                                          \
            diff |= v[i] ^ v2[i];                                                                \
        *ptlen = ctl;                                                                            \
        return diff == 0;                                                                        \
    }                                                                                            \
    static void blind_##SFX(const uint8_t *k, const uint8_t *v, size_t len, uint8_t *out, int r) { \
        mac_##SFX(k, v, len, DOM_BI, out, r);                                                    \
    }                                                                                            \
    static void sinit_##SFX(TYPE s[5], const uint8_t *k, const uint8_t *nc, int r) {             \
        uint8_t nb[32];                                                                          \
        memset(nb, 0, 32);                                                                       \
        memcpy(nb, nc, 16);                                                                      \
        s[0] = 0;                                                                                \
        s[1] = rd_##SFX(k);                                                                      \
        s[2] = rd_##SFX(k + B);                                                                  \
        s[3] = rd_##SFX(nb);                                                                     \
        s[4] = rd_##SFX(nb + B) ^ (TYPE)DOM_STREAM;                                              \
        f_##SFX(s, r);                                                                           \
        s[3] ^= rd_##SFX(k);                                                                     \
        s[4] ^= rd_##SFX(k + B);                                                                 \
    }                                                                                            \
    static void sad_##SFX(TYPE s[5], const uint8_t *ad, size_t len, int r) {                     \
        size_t pl = ((len + 1 + (B - 1)) / B) * B;                                               \
        uint8_t *b = calloc(pl, 1);                                                              \
        memcpy(b, ad, len);                                                                      \
        b[len] = 0x01;                                                                           \
        b[pl - 1] |= 0x80;                                                                       \
        for (size_t o = 0; o < pl; o += B) {                                                     \
            s[0] ^= rd_##SFX(b + o);                                                             \
            f_##SFX(s, r);                                                                       \
        }                                                                                        \
        free(b);                                                                                 \
        s[4] ^= (TYPE)1;                                                                         \
    }                                                                                            \
    static void sfin_##SFX(TYPE s[5], const uint8_t *k, uint8_t *tag, int r) {                   \
        s[3] ^= rd_##SFX(k);                                                                     \
        s[4] ^= rd_##SFX(k + B);                                                                 \
        f_##SFX(s, r);                                                                           \
        wr_##SFX(tag, s[3]);                                                                     \
        wr_##SFX(tag + B, s[4]);                                                                 \
    }                                                                                            \
    static size_t sseal_##SFX(const uint8_t *k, const uint8_t *nc, const uint8_t *ad, size_t al, \
                              const uint8_t *pt, size_t pl, uint8_t *out, int r) {               \
        TYPE s[5];                                                                               \
        sinit_##SFX(s, k, nc, r);                                                                \
        sad_##SFX(s, ad, al, r);                                                                 \
        size_t oi = 0, full = pl / B;                                                            \
        for (size_t i = 0; i < full; i++) {                                                      \
            s[0] ^= rd_##SFX(pt + i * B);                                                        \
            wr_##SFX(out + oi, s[0]);                                                            \
            oi += B;                                                                             \
            f_##SFX(s, r);                                                                       \
        }                                                                                        \
        size_t l = pl - full * B;                                                                \
        uint8_t rb[16];                                                                          \
        wr_##SFX(rb, s[0]);                                                                      \
        for (size_t j = 0; j < l; j++)                                                           \
            out[oi++] = pt[full * B + j] ^ rb[j];                                                \
        uint8_t pb[16];                                                                          \
        memset(pb, 0, 16);                                                                       \
        memcpy(pb, pt + full * B, l);                                                            \
        pb[l] ^= 0x01;                                                                           \
        s[0] ^= rd_##SFX(pb);                                                                    \
        uint8_t tag[2 * B];                                                                      \
        sfin_##SFX(s, k, tag, r);                                                                \
        memcpy(out + oi, tag, 2 * B);                                                            \
        return oi + 2 * B;                                                                       \
    }                                                                                            \
    static int sopen_##SFX(const uint8_t *k, const uint8_t *nc, const uint8_t *ad, size_t al,    \
                           const uint8_t *sd, size_t sl, uint8_t *pt, size_t *ptlen, int r) {    \
        if (sl < (size_t)(2 * B))                                                                \
            return 0;                                                                            \
        size_t ctl = sl - 2 * B;                                                                 \
        const uint8_t *ct = sd, *tag = sd + ctl;                                                 \
        TYPE s[5];                                                                               \
        sinit_##SFX(s, k, nc, r);                                                                \
        sad_##SFX(s, ad, al, r);                                                                 \
        size_t pi = 0, full = ctl / B;                                                           \
        for (size_t i = 0; i < full; i++) {                                                      \
            uint8_t rb[16];                                                                      \
            wr_##SFX(rb, s[0]);                                                                  \
            for (int j = 0; j < B; j++)                                                          \
                pt[pi++] = rb[j] ^ ct[i * B + j];                                                \
            s[0] = rd_##SFX(ct + i * B);                                                         \
            f_##SFX(s, r);                                                                       \
        }                                                                                        \
        size_t l = ctl - full * B;                                                               \
        uint8_t rb[16];                                                                          \
        wr_##SFX(rb, s[0]);                                                                      \
        for (size_t j = 0; j < l; j++)                                                           \
            pt[pi++] = ct[full * B + j] ^ rb[j];                                                 \
        uint8_t nr[16];                                                                          \
        memcpy(nr, rb, 16);                                                                      \
        for (size_t j = 0; j < l; j++)                                                           \
            nr[j] = ct[full * B + j];                                                            \
        nr[l] ^= 0x01;                                                                           \
        s[0] = rd_##SFX(nr);                                                                     \
        uint8_t t2[2 * B];                                                                       \
        sfin_##SFX(s, k, t2, r);                                                                 \
        int diff = 0;                                                                            \
        for (int i = 0; i < 2 * B; i++)                                                          \
            diff |= tag[i] ^ t2[i];                                                              \
        *ptlen = pi;                                                                             \
        return diff == 0;                                                                        \
    }

DEFINE_MODES(128, uint64_t, 8, qp320, ROTS320)
DEFINE_MODES(256, __uint128_t, 16, qp640, ROTS640)

/* ---- N2QF binary file container: "N2QF" | ver(1) | suite(1) | {le32|sealed}* ----
 * nonce for chunk i = 16-byte little-endian i (host is little-endian). */
static int enc_file(int profile, const uint8_t *key, int bits, const char *inp, const char *out) {
    FILE *fi = fopen(inp, "rb"), *fo = fopen(out, "wb");
    if (!fi || !fo) return -1;
    uint8_t suite = (bits == 128 ? 0x01 : 0x02) | (profile == 8 ? 0x20 : 0);
    uint8_t hdr[6] = {'N', '2', 'Q', 'F', 1, suite};
    fwrite(hdr, 1, 6, fo);
    uint8_t *buf = malloc(65536), *ob = malloc(65536 + 64);
    uint64_t idx = 0;
    size_t n;
    while ((n = fread(buf, 1, 65536, fi)) > 0) {
        uint8_t nonce[16] = {0};
        memcpy(nonce, &idx, 8);
        size_t sn = (bits == 128) ? seal_128(key, nonce, (const uint8_t *)"", 0, buf, n, ob, profile)
                                  : seal_256(key, nonce, (const uint8_t *)"", 0, buf, n, ob, profile);
        uint32_t l = (uint32_t)sn;
        fwrite(&l, 4, 1, fo);
        fwrite(ob, 1, sn, fo);
        idx++;
    }
    free(buf); free(ob); fclose(fi); fclose(fo);
    return 0;
}
static int dec_file(const uint8_t *key, const char *inp, const char *out) {
    FILE *fi = fopen(inp, "rb"), *fo = fopen(out, "wb");
    if (!fi || !fo) return -1;
    uint8_t hdr[6];
    if (fread(hdr, 1, 6, fi) != 6 || memcmp(hdr, "N2QF", 4) != 0) return -2;
    int bits = (hdr[5] & 0x0f) == 2 ? 256 : 128, r = (hdr[5] & 0x20) ? 8 : 16;
    uint8_t *sealed = malloc(65536 + 64), *pt = malloc(65536);
    uint64_t idx = 0;
    uint32_t l;
    int rc = 0;
    while (fread(&l, 4, 1, fi) == 1) {
        if (fread(sealed, 1, l, fi) != l) { rc = -3; break; }
        uint8_t nonce[16] = {0};
        memcpy(nonce, &idx, 8);
        size_t ptlen;
        int ok = (bits == 128) ? open_128(key, nonce, (const uint8_t *)"", 0, sealed, l, pt, &ptlen, r)
                               : open_256(key, nonce, (const uint8_t *)"", 0, sealed, l, pt, &ptlen, r);
        if (!ok) { rc = -4; break; }
        fwrite(pt, 1, ptlen, fo);
        idx++;
    }
    free(sealed); free(pt); fclose(fi); fclose(fo);
    return rc;
}

/* ---- self-test ---- */
static int fails = 0;

static void check320(const char *name, uint64_t in[5], int rounds, const uint64_t exp[5]) {
    uint64_t s[5];
    memcpy(s, in, sizeof s);
    qp320(s, ROTS320, rounds);
    int ok = memcmp(s, exp, sizeof s) == 0;
    printf("  [%s] QP-320 %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
        for (int i = 0; i < 5; i++)
            printf("     got %016llx exp %016llx\n", (unsigned long long)s[i],
                   (unsigned long long)exp[i]);
    }
}

static void check640(const char *name, __uint128_t in[5], int rounds,
                     const uint64_t exp_hi[5], const uint64_t exp_lo[5]) {
    __uint128_t s[5];
    memcpy(s, in, sizeof s);
    qp640(s, ROTS640, rounds);
    int ok = 1;
    for (int i = 0; i < 5; i++)
        if ((uint64_t)(s[i] >> 64) != exp_hi[i] || (uint64_t)s[i] != exp_lo[i])
            ok = 0;
    printf("  [%s] QP-640 %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        fails++;
}

static void check_hex(const char *name, const uint8_t *got, size_t n, const char *exp) {
    if (strlen(exp) != 2 * n) {
        printf("  [FAIL] %s (length)\n", name);
        fails++;
        return;
    }
    char buf[256];
    for (size_t i = 0; i < n; i++)
        sprintf(buf + 2 * i, "%02x", got[i]);
    int ok = strcmp(buf, exp) == 0;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        fails++;
        printf("     got %s\n     exp %s\n", buf, exp);
    }
}

int main(int argc, char **argv) {
    init_anf();
    /* CLI file mode:  ./n2qc encrypt|decrypt <in> <out>   (fixed demo key) */
    if (argc == 4 && (strcmp(argv[1], "encrypt") == 0 || strcmp(argv[1], "decrypt") == 0)) {
        uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        int rc = strcmp(argv[1], "encrypt") == 0
                     ? enc_file(8 /*Fast*/, key, 128, argv[2], argv[3])
                     : dec_file(key, argv[2], argv[3]);
        if (rc != 0) fprintf(stderr, "error %d\n", rc);
        return rc == 0 ? 0 : 1;
    }
    printf("N2Q-C C reference — Appendix A known-answer self-test\n");

    uint64_t zero[5] = {0, 0, 0, 0, 0};
    uint64_t z12[5] = {0x6c3d34cc09474fbb, 0x4ad0c1e3cc099b31, 0xe4493f2ea310ec56,
                       0x4e5d2d1f0f612aa3, 0xa629041fa88cbba2};
    uint64_t z16[5] = {0x0a80d3fda988ac26, 0x221c8fdc996d211e, 0x4970cbaefa3be331,
                       0xc52528314439a60d, 0xb15ae981e77924c9};
    check320("zero p^12", zero, 12, z12);
    check320("zero p^16", zero, 16, z16);

    uint64_t pat[5] = {0x0123456789abcdef, 0xfedcba9876543210, 0x0f1e2d3c4b5a6978,
                       0x1122334455667788, 0x8090a0b0c0d0e0f0};
    uint64_t p12[5] = {0xcacee3c01fa6963e, 0xf808bd597a3cf500, 0x8ded22db7633bad2,
                       0x8f876e846c9ea9a8, 0x5130139b0338a456};
    check320("pattern p^12", pat, 12, p12);

    __uint128_t z6[5] = {0, 0, 0, 0, 0};
    uint64_t hi[5] = {0x92d9767d204356d5, 0xc810337e8e03196a, 0xc8f6c409f8e38370,
                      0x0b312a32ac9c8523, 0x47ed01c11be8cc1d};
    uint64_t lo[5] = {0xbf69412869804a6a, 0x656eea5765acdcdf, 0xb1621e358303e666,
                      0xa94c52eb50bcdc8f, 0x9bd809f54ccff628};
    check640("zero p^12", z6, 12, hi, lo);

    /* mode cross-checks against the Rust reference vectors */
    printf("mode cross-check (vs Rust):\n");
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key32[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                         0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
                         0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
    uint8_t nonce[16];
    memset(nonce, 0xa5, 16);
    const uint8_t *AD = (const uint8_t *)"header";
    const uint8_t *PT = (const uint8_t *)"hello n2q-c";

    /* N2Q-128 */
    uint8_t h[64], sealed[128], bi[32];
    const int SEC = 16, FAST = 8;
    hash_128((const uint8_t *)"", 0, h, 32, SEC);
    check_hex("128 hash(\"\")", h, 32,
              "5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed");
    hash_128((const uint8_t *)"abc", 3, h, 32, SEC);
    check_hex("128 hash(\"abc\")", h, 32,
              "9b8d0f3ff48bf6627114eeace965cccb2d2266f01d44e475b074e2be3d19203f");
    size_t sl = seal_128(key, nonce, AD, 6, PT, 11, sealed, SEC);
    check_hex("128 seal (Secure)", sealed, sl, "44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57");
    sl = seal_128(key, nonce, AD, 6, PT, 11, sealed, FAST);
    check_hex("128 seal (Fast)", sealed, sl, "e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0");
    blind_128(key, (const uint8_t *)"alice@x.com", 11, bi, SEC);
    check_hex("128 blind_index", bi, 16, "15b058f9a3b1f5935899d03ac71ba415");
    size_t ssl = sseal_128(key, nonce, AD, 6, PT, 11, sealed, SEC);
    check_hex("128 stream (Secure)", sealed, ssl, "f312993bb6e3c11c6951eff7098585fbbfd70ccf54cbe45e498afa");

    /* N2Q-256 */
    hash_256((const uint8_t *)"abc", 3, h, 64, SEC);
    check_hex("256 hash(\"abc\")", h, 64,
              "8d3bbe5cb8f1c4b0158aabdaf1881ff050fda245352efdf0106b1b4664861b7243597d460e32661c"
              "b56f1399f619219e8122cc474e90fd3d2e9c03a3b6947fb3");
    sl = seal_256(key32, nonce, AD, 6, PT, 11, sealed, SEC);
    check_hex("256 seal (Secure)", sealed, sl,
              "0fc0b54697f0dd3cce390382e15918473bd858843f0957b958a6cafe95c01f5e10e8d7ad55996a2bfd1037");
    sl = seal_256(key32, nonce, AD, 6, PT, 11, sealed, FAST);
    check_hex("256 seal (Fast)", sealed, sl,
              "c885b4aa03afcc4a2c42b39d240f578fc9bebcb9e0459528624aa0d87052ce501a5ede276eb42de92b0bd0");
    blind_256(key32, (const uint8_t *)"alice@x.com", 11, bi, SEC);
    check_hex("256 blind_index", bi, 32,
              "7e99c9501484b22156a3fc3c98b10f88149cfe2396b5250df737a34a4f50de75");
    ssl = sseal_256(key32, nonce, AD, 6, PT, 11, sealed, SEC);
    check_hex("256 stream (Secure)", sealed, ssl,
              "2562bd9a4879f0df72d710f9401ae4566c153e1758352d42086b38b8652c2cc913c4523887a9fd53b3bf6e");

    /* streaming round-trip (C-internal, both widths, both profiles, partial blocks) */
    for (int r = 0; r < 2; r++) {
        int rounds = r == 0 ? SEC : FAST;
        for (int w = 0; w < 2; w++) {
            for (size_t len = 0; len <= 40; len += 7) {
                uint8_t pt[40], ct[80], out[40];
                for (size_t i = 0; i < len; i++)
                    pt[i] = (uint8_t)(i * 5 + w + r);
                size_t clen, olen;
                int ok;
                if (w == 0) {
                    clen = sseal_128(key, nonce, AD, 6, pt, len, ct, rounds);
                    ok = sopen_128(key, nonce, AD, 6, ct, clen, out, &olen, rounds);
                } else {
                    clen = sseal_256(key32, nonce, AD, 6, pt, len, ct, rounds);
                    ok = sopen_256(key32, nonce, AD, 6, ct, clen, out, &olen, rounds);
                }
                if (!ok || olen != len || memcmp(pt, out, len) != 0) {
                    printf("  [FAIL] stream roundtrip r=%d w=%d len=%zu\n", rounds, w, len);
                    fails++;
                }
            }
        }
    }
    printf("  [%s] streaming round-trip (both widths, both profiles, partial blocks)\n",
           fails == 0 ? "PASS" : "FAIL");

    /* N2QF cross-language interop: decrypt the Python-produced container */
    FILE *tf = fopen("/tmp/filedemo/photo.n2q", "rb");
    if (tf) {
        fclose(tf);
        int eq = 0;
        if (dec_file(key, "/tmp/filedemo/photo.n2q", "/tmp/filedemo/photo.c.png") == 0) {
            FILE *fa = fopen("/tmp/filedemo/photo.png", "rb"), *fb = fopen("/tmp/filedemo/photo.c.png", "rb");
            if (fa && fb) {
                eq = 1;
                int ca, cb;
                while ((ca = fgetc(fa)) != EOF) {
                    cb = fgetc(fb);
                    if (ca != cb) { eq = 0; break; }
                }
                if (eq && fgetc(fb) != EOF) eq = 0;
            }
            if (fa) fclose(fa);
            if (fb) fclose(fb);
        }
        printf("  [%s] N2QF cross-decrypt (Python -> C)\n", eq ? "PASS" : "FAIL");
        if (!eq) fails++;
    }

    printf("%s (%d failures)\n", fails == 0 ? "ALL PASS" : "FAILURES", fails);
    return fails == 0 ? 0 : 1;
}
