#include "../../impl/c/n2q_convergent.c"
#include <assert.h>
static uint64_t completed_cases[2];
static void fuzz_report_cases(void) {
    for (unsigned i = 0; i < 2; i++)
        fprintf(stderr, "N2Q_FUZZ_VARIANT %u %llu\n", i, (unsigned long long)completed_cases[i]);
}
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    assert(atexit(fuzz_report_cases) == 0);
    return 0;
}

static void unchanged(const uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) assert(buffer[i] == 0xa5);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 18 || size > 4096) return 0;
    int fast = data[0] & 1;
    const uint8_t *master = data + 2, *plain = data + 18;
    size_t plen = size - 18, expected = plen + 16;
    uint8_t dek[16], second_dek[16], sealed[4096 + 32], second[4096 + 32], out[4096 + 16];
    memset(sealed, 0xa5, sizeof sealed);
    size_t clen = n2q_conv_seal(master, 16, plain, plen, dek, sealed, expected, fast);
    assert(clen == expected);
    unchanged(sealed + clen, sizeof sealed - clen);
    assert(n2q_conv_seal(master, 16, plain, plen, second_dek, second, expected, fast) == clen);
    assert(!memcmp(dek, second_dek, 16) && !memcmp(sealed, second, clen));
    memset(out, 0xa5, sizeof out);
    size_t olen = 999;
    assert(n2q_conv_open(dek, sealed, clen, out, plen, &olen, fast));
    assert(olen == plen && !memcmp(out, plain, plen));
    unchanged(out + plen, sizeof out - plen);

    size_t capacity = (size_t)data[1] % (plen + 1);
    if (capacity < plen) {
        memset(out, 0xa5, sizeof out);
        olen = 999;
        assert(!n2q_conv_open(dek, sealed, clen, out, capacity, &olen, fast) && !olen);
        unchanged(out, sizeof out);
    }
    memset(second, 0xa5, sizeof second);
    memset(second_dek, 0xa5, sizeof second_dek);
    assert(!n2q_conv_seal(master, 16, plain, plen, second_dek, second, (size_t)data[1] % clen, fast));
    unchanged(second, sizeof second);
    unchanged(second_dek, sizeof second_dek);
    int invalid_length = (int)data[1] - 128;
    if (invalid_length != 16)
        assert(!n2q_conv_seal(master, invalid_length, plain, plen, second_dek, second, sizeof second, fast));
    assert(!n2q_conv_seal(master, 16, plain, SIZE_MAX - (data[0] & 15),
                          second_dek, second, sizeof second, fast));
    olen = 999;
    assert(!n2q_conv_open(dek, sealed, SIZE_MAX, out, sizeof out, &olen, fast) && !olen);

    sealed[(size_t)data[1] % clen] ^= (uint8_t)(1u << (data[0] & 7));
    memset(out, 0xa5, sizeof out);
    olen = 999;
    assert(!n2q_conv_open(dek, sealed, clen, out, plen, &olen, fast) && !olen);
    for (size_t i = 0; i < plen; i++) assert(out[i] == 0);
    unchanged(out + plen, sizeof out - plen);
    completed_cases[fast]++;
    return 0;
}
