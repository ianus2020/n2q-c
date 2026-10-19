#define N2Q_CORE_NO_MAIN
#include "../../impl/c/n2qc.c"
#include <assert.h>

typedef size_t (*seal_fn)(const uint8_t *, const uint8_t *, const uint8_t *, size_t,
                          const uint8_t *, size_t, uint8_t *, int);
typedef int (*open_fn)(const uint8_t *, const uint8_t *, const uint8_t *, size_t,
                       const uint8_t *, size_t, uint8_t *, size_t *, int);
static uint64_t completed_cases[8];
static void fuzz_report_cases(void) {
    for (unsigned i = 0; i < 8; i++)
        fprintf(stderr, "N2Q_FUZZ_VARIANT %u %llu\n", i, (unsigned long long)completed_cases[i]);
}
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    assert(atexit(fuzz_report_cases) == 0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 50 || size > 4096) return 0;
    int wide = data[0] & 1, rounds = data[0] & 2 ? 8 : 16, stream = data[0] & 4;
    seal_fn seal = wide ? (stream ? sseal_256 : seal_256) : (stream ? sseal_128 : seal_128);
    open_fn open = wide ? (stream ? sopen_256 : open_256) : (stream ? sopen_128 : open_128);
    const uint8_t *key = data + 2, *nonce = data + 34, *ad = data + 50;
    size_t alen = data[1] & 63;
    if (alen > size - 50) alen = size - 50;
    const uint8_t *plain = ad + alen;
    size_t plen = size - 50 - alen;
    uint8_t sealed[4096 + 32], out[4096 + 16];
    memset(sealed, 0xa5, sizeof sealed);
    size_t clen = seal(key, nonce, ad, alen, plain, plen, sealed, rounds);
    assert(clen == plen + (wide ? 32 : 16));
    for (size_t i = clen; i < sizeof sealed; i++) assert(sealed[i] == 0xa5);
    memset(out, 0xa5, sizeof out);
    size_t olen = 999;
    assert(open(key, nonce, ad, alen, sealed, clen, out, &olen, rounds));
    assert(olen == plen && !memcmp(out, plain, plen));
    for (size_t i = plen; i < sizeof out; i++) assert(out[i] == 0xa5);
    /* Every input first reaches successful authentication; raw mutations alone
       almost always stop at a tag failure before exercising this path. */
    sealed[(size_t)data[1] % clen] ^= (uint8_t)(1u << (data[0] & 7));
    memset(out, 0xa5, sizeof out);
    olen = 999;
    assert(!open(key, nonce, ad, alen, sealed, clen, out, &olen, rounds));
    assert(olen == 0);
    for (size_t i = 0; i < plen; i++) assert(out[i] == 0);
    for (size_t i = plen; i < sizeof out; i++) assert(out[i] == 0xa5);
    completed_cases[data[0] & 7]++;
    return 0;
}
