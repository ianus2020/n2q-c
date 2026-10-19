#define N2Q_CORE_NO_MAIN
#include "../../impl/c/n2qc.c"
#include <assert.h>
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv; init_anf(); return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!size || size > 4096) return 0;
    uint8_t key[32] = {0}, nonce[16] = {0}, out[4096];
    size_t len = 999; int rounds = data[0] & 2 ? 8 : 16;
    int ok = data[0] & 1
        ? open_256(key,nonce,(const uint8_t *)"ctx",3,data+1,size-1,out,&len,rounds)
        : open_128(key,nonce,(const uint8_t *)"ctx",3,data+1,size-1,out,&len,rounds);
    assert(len <= sizeof out);
    if (!ok) assert(!len);
    return 0;
}
