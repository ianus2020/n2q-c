/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_fpe — opt-in format-preserving encryption (FF1 construction) on N2Q.
 *
 * Encrypts a decimal string into another decimal string of the SAME length:
 * a 16-digit card number becomes a 16-digit number, a 9-digit SSN stays 9
 * digits. That lets you encrypt a sensitive column in a legacy database WITHOUT
 * changing its type, length or format checks — the classic fintech ask.
 *
 * This is the **FF1 construction** (NIST SP 800-38G): a 10-round unbalanced
 * Feistel network. The only change is the round function — instead of AES we use
 * the keyed N2Q sponge PRF. So it is *the standard, well-analysed design*, keyed
 * by our primitive (not NIST-certified FF1, which mandates AES). FF3 was broken
 * in 2017; FF1 is the safe choice and the one we follow.
 *
 * Opt-in and additive: nothing here touches the AEAD / hash / token API. Enable
 * it only where you need in-place, format-preserving encryption.
 *
 *   int n2q_fpe_encrypt(key, tweak, tlen, in, out, n)   // n decimal digits
 *   int n2q_fpe_decrypt(key, tweak, tlen, in, out, n)
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_FPE_DEMO n2q_fpe.c -o n2q_fpe && ./n2q_fpe
 *  * Note: small domains (e.g. a 4-digit PIN) are format-preserving *tokenisation*,
 * not strong encryption — the domain itself is tiny.
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

#define N2Q_FPE_MIN 2
#define N2Q_FPE_MAX 18 /* halves stay <= 9 digits, well within uint64 */

static uint64_t p10(int m) { uint64_t v = 1; while (m-- > 0) v *= 10u; return v; }
static uint64_t num_str(const char *s, int len) { uint64_t v = 0; for (int i = 0; i < len; i++) v = v * 10u + (uint64_t)(s[i] - '0'); return v; }
static void str_num(uint64_t v, int len, char *out) { for (int i = len - 1; i >= 0; i--) { out[i] = (char)('0' + (v % 10u)); v /= 10u; } }

/* round function: pseudorandom y in [0, 10^m) from (round i, tweak, half value) */
static uint64_t fpe_round(const uint8_t key[16], const uint8_t *tw, size_t tl,
                          int i, int n, int m, uint64_t bval) {
    uint8_t buf[80];
    size_t p = 0;
    buf[p++] = (uint8_t)i; buf[p++] = (uint8_t)n; buf[p++] = (uint8_t)m; buf[p++] = (uint8_t)tl;
    for (size_t j = 0; j < tl && p < 64; j++) buf[p++] = tw[j];
    for (int b = 7; b >= 0; b--) buf[p++] = (uint8_t)(bval >> (8 * b));
    uint8_t mac[16];
    mac_128(key, buf, p, 6 /* FPE domain */, mac, 16);
    uint64_t mod = p10(m), y = 0;
    for (int b = 0; b < 16; b++) y = (y * 256u + mac[b]) % mod;
    return y;
}

static int valid(const char *s, size_t n) {
    if (n < N2Q_FPE_MIN || n > N2Q_FPE_MAX) return 0;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

int n2q_fpe_encrypt(const uint8_t key[16], const uint8_t *tweak, size_t tlen,
                    const char *in, char *out, size_t n) {
    if (!valid(in, n)) return 0;
    init_anf();
    int u = (int)n / 2, v = (int)n - u;
    uint64_t A = num_str(in, u), B = num_str(in + u, v);
    int Alen = u, Blen = v;
    for (int i = 0; i < 10; i++) {
        int m = (i % 2 == 0) ? u : v;
        uint64_t y = fpe_round(key, tweak, tlen, i, (int)n, m, B);
        uint64_t c = (A + y) % p10(m);
        uint64_t nA = B; int nAl = Blen;
        A = nA; Alen = nAl;
        B = c; Blen = m;
    }
    str_num(A, Alen, out);
    str_num(B, Blen, out + Alen);
    return 1;
}

int n2q_fpe_decrypt(const uint8_t key[16], const uint8_t *tweak, size_t tlen,
                    const char *in, char *out, size_t n) {
    if (!valid(in, n)) return 0;
    init_anf();
    int u = (int)n / 2, v = (int)n - u;
    uint64_t A = num_str(in, u), B = num_str(in + u, v);
    int Alen = u, Blen = v;
    for (int i = 9; i >= 0; i--) {
        int m = (i % 2 == 0) ? u : v;
        uint64_t C = B; int Cl = Blen;
        B = A; Blen = Alen;
        uint64_t y = fpe_round(key, tweak, tlen, i, (int)n, m, B);
        uint64_t P = p10(m);
        uint64_t c = (C + P - (y % P)) % P;
        A = c; Alen = m;
        (void)Cl;
    }
    str_num(A, Alen, out);
    str_num(B, Blen, out + Alen);
    return 1;
}

#ifdef N2Q_FPE_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    printf("n2q_fpe self-test (format-preserving encryption, FF1 construction)\n");
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x70 + i);
    const uint8_t tw[] = "acct-42";

    const char *card = "4111111111111111"; /* 16-digit card number */
    char ct[19] = {0}, back[19] = {0};
    n2q_fpe_encrypt(key, tw, sizeof tw - 1, card, ct, 16);
    n2q_fpe_decrypt(key, tw, sizeof tw - 1, ct, back, 16);
    printf("  %s  ->  %s  ->  %s\n", card, ct, back);

    ex("round-trip recovers the original number", memcmp(back, card, 16) == 0);
    int fmt = 1; for (int i = 0; i < 16; i++) if (ct[i] < '0' || ct[i] > '9') fmt = 0;
    ex("ciphertext is 16 decimal digits (format preserved)", fmt);
    ex("ciphertext differs from plaintext", memcmp(ct, card, 16) != 0);

    /* deterministic under the same (key, tweak) */
    char ct2[19] = {0};
    n2q_fpe_encrypt(key, tw, sizeof tw - 1, card, ct2, 16);
    ex("deterministic for equal (key, tweak)", memcmp(ct, ct2, 16) == 0);

    /* a different tweak yields a different ciphertext (domain separation) */
    char ctT[19] = {0};
    n2q_fpe_encrypt(key, (const uint8_t *)"acct-99", 7, card, ctT, 16);
    ex("different tweak -> different ciphertext", memcmp(ct, ctT, 16) != 0);

    /* it is a permutation: encrypt 500 distinct inputs, expect 500 distinct outputs */
    {
        static char seen[500][10];
        int uniq = 1;
        for (int k = 0; k < 500; k++) {
            char in[10] = {0}, o[10] = {0};
            str_num((uint64_t)k, 9, in); /* the 9-digit form of k -> genuinely distinct inputs */
            n2q_fpe_encrypt(key, tw, sizeof tw - 1, in, o, 9);
            memcpy(seen[k], o, 9); seen[k][9] = 0;
        }
        for (int a = 0; a < 500 && uniq; a++)
            for (int b = a + 1; b < 500; b++)
                if (memcmp(seen[a], seen[b], 9) == 0) { uniq = 0; break; }
        ex("permutation: 500 distinct 9-digit inputs -> 500 distinct outputs", uniq);
    }

    /* different lengths work (9-digit SSN, 10-digit phone) */
    { char a[11] = {0}, b[11] = {0};
      n2q_fpe_encrypt(key, tw, sizeof tw - 1, "078051120", a, 9);
      n2q_fpe_decrypt(key, tw, sizeof tw - 1, a, b, 9);
      ex("9-digit SSN round-trips", memcmp(b, "078051120", 9) == 0); }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
