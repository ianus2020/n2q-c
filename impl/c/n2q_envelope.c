/*
 * n2q_envelope — envelope encryption & key rotation. See n2q_envelope.h.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_ENVELOPE_DEMO n2q_envelope.c -o n2q_envelope && ./n2q_envelope
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c" /* seal_128/open_128, seal_256/open_256 */

#include "n2q_envelope.h"
#include <string.h>

static const uint8_t WRAP_AD[] = "n2q-envelope-v1";
static const uint8_t WRAP_NONCE[16] = {0}; /* SIV is misuse-resistant; DEKs are unique */

size_t n2q_wrap(const uint8_t *kek, int keklen, const uint8_t *dek, size_t deklen, uint8_t *out) {
    if (!kek || !dek || !out || (keklen != 16 && keklen != 32)) return 0;
    return (keklen == 16)
        ? seal_128(kek, WRAP_NONCE, WRAP_AD, sizeof WRAP_AD - 1, dek, deklen, out, 16)
        : seal_256(kek, WRAP_NONCE, WRAP_AD, sizeof WRAP_AD - 1, dek, deklen, out, 16);
}

int n2q_unwrap(const uint8_t *kek, int keklen, const uint8_t *blob, size_t blen,
               uint8_t *dek, size_t *deklen) {
    if (!kek || !blob || !dek || !deklen || (keklen != 16 && keklen != 32)) return 0;
    return (keklen == 16)
        ? open_128(kek, WRAP_NONCE, WRAP_AD, sizeof WRAP_AD - 1, blob, blen, dek, deklen, 16)
        : open_256(kek, WRAP_NONCE, WRAP_AD, sizeof WRAP_AD - 1, blob, blen, dek, deklen, 16);
}

size_t n2q_rewrap(const uint8_t *old_kek, int oklen, const uint8_t *new_kek, int nklen,
                  const uint8_t *blob, size_t blen, uint8_t *out) {
    uint8_t dek[64];
    size_t dl = 0;
    if (blen < 16 + 1 || blen - 16 > sizeof dek) return 0;
    if (!n2q_unwrap(old_kek, oklen, blob, blen, dek, &dl)) return 0;
    size_t n = n2q_wrap(new_kek, nklen, dek, dl, out);
    memset(dek, 0, sizeof dek); /* erase the DEK from the stack */
    return n;
}

/* -------------------------------------------------------------------------- */
#ifdef N2Q_ENVELOPE_DEMO
#include <stdio.h>

static int failc = 0;
static void expect(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) failc++;
}

int main(void) {
    init_anf();
    printf("n2q_envelope self-test (envelope encryption + key rotation)\n");

    /* two key-encryption keys: the old one and the rotation target */
    uint8_t kek1[16], kek2[16];
    for (int i = 0; i < 16; i++) { kek1[i] = (uint8_t)(0x10 + i); kek2[i] = (uint8_t)(0xF0 - i); }

    /* a random 32-byte data key protects the bulk object */
    uint8_t dek[32];
    for (int i = 0; i < 32; i++) dek[i] = (uint8_t)(0x55 ^ (i * 7));

    /* encrypt a "large object" once, under the DEK — this never changes on rotation */
    const uint8_t object[] = "a very large encrypted object (imagine terabytes)";
    size_t olen = sizeof object - 1;
    uint8_t bulk[128], plain[128];
    size_t bl = seal_128(dek, WRAP_NONCE, (const uint8_t *)"obj", 3, object, olen, bulk, 8);
    size_t pl;

    /* wrap the DEK under KEK1 and store the small blob next to the bulk */
    uint8_t blob[64], dek_out[64];
    size_t wl = n2q_wrap(kek1, 16, dek, 32, blob), dl;
    expect("unwrap under KEK1 returns the DEK",
           n2q_unwrap(kek1, 16, blob, wl, dek_out, &dl) == 1 && dl == 32 && memcmp(dek_out, dek, 32) == 0);

    /* wrong KEK cannot unwrap */
    expect("wrong KEK cannot unwrap", n2q_unwrap(kek2, 16, blob, wl, dek_out, &dl) == 0);

    /* ROTATE: re-wrap the DEK blob from KEK1 to KEK2. The bulk stays byte-for-byte. */
    uint8_t bulk_before[128]; memcpy(bulk_before, bulk, bl);
    uint8_t blob2[64];
    size_t wl2 = n2q_rewrap(kek1, 16, kek2, 16, blob, wl, blob2);
    expect("rotation rewraps the DEK (old KEK no longer needed)",
           wl2 > 0 && n2q_unwrap(kek2, 16, blob2, wl2, dek_out, &dl) == 1 && memcmp(dek_out, dek, 32) == 0);
    expect("bulk ciphertext was NOT touched by rotation", memcmp(bulk, bulk_before, bl) == 0);

    /* after rotation the object still decrypts with the (unchanged) DEK */
    expect("object still decrypts after rotation",
           n2q_unwrap(kek2, 16, blob2, wl2, dek_out, &dl) == 1 &&
               open_128(dek_out, WRAP_NONCE, (const uint8_t *)"obj", 3, bulk, bl, plain, &pl, 8) == 1 &&
               pl == olen && memcmp(plain, object, olen) == 0);

    /* tampered blob -> rejected */
    { uint8_t bad[64]; memcpy(bad, blob2, wl2); bad[0] ^= 0x20;
      expect("tampered wrap rejected", n2q_unwrap(kek2, 16, bad, wl2, dek_out, &dl) == 0); }

    printf("%s (%d failures)\n", failc == 0 ? "ALL PASS" : "FAILURES", failc);
    return failc ? 1 : 0;
}
#endif /* N2Q_ENVELOPE_DEMO */
