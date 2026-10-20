#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../impl/c/n2q_convergent.c"

int main(void) {
    uint8_t key[17], dek[16], ct[64], out[64];
    memset(key, 'A', sizeof key);
    memset(ct, 0xa5, sizeof ct);
    memset(dek, 0xa5, sizeof dek);
    const uint8_t msg[] = "Bpayload";
    for (int length = 0; length <= 17; length++) {
        if (length == 16) continue;
        assert(n2q_conv_seal(key, length, msg, 8, dek, ct, sizeof ct, 0) == 0);
        assert(ct[0] == 0xa5 && dek[0] == 0xa5);
    }
    assert(n2q_conv_seal(key, 16, msg, SIZE_MAX, dek, ct, sizeof ct, 0) == 0);
    assert(n2q_conv_seal(key, 16, NULL, 1, dek, ct, sizeof ct, 0) == 0);
    assert(n2q_conv_seal(key, 16, msg, 8, dek, ct, 23, 0) == 0);
    assert(n2q_conv_seal(key, 16, msg, 8, dek, ct, sizeof ct, 2) == 0);
    assert(ct[0] == 0xa5 && dek[0] == 0xa5);
    size_t n = n2q_conv_seal(key, 16, msg, 8, dek, ct, sizeof ct, 0), len = 999;
    assert(n == 24);
    assert(n2q_conv_open(dek, ct, n, out, 7, &len, 0) == 0 && len == 0);
    assert(n2q_conv_open(dek, ct, n, out, sizeof out, &len, 0) && len == 8 && !memcmp(out, msg, 8));
    ct[0] ^= 1;
    len = 999;
    assert(!n2q_conv_open(dek, ct, n, out, sizeof out, &len, 0) && len == 0);
    assert(n2q_conv_seal(key, 16, NULL, 0, dek, ct, sizeof ct, 1) == 16);
    puts("convergent fixed-key boundary, overflow, capacities and authentication PASS");
    return 0;
}
