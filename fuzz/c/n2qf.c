#include "../../impl/c/n2q_seek.c"
#include <assert.h>
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv; init_anf(); return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;
    uint8_t key[16] = {0}, out[256];
    for (uint64_t index=0;index<2;index++) {
        size_t len = 999;
        int result = n2q_seek_chunk(key,data,size,index,out,sizeof out,&len);
        assert(len <= sizeof out);
        if (result != N2Q_SEEK_OK) assert(len == 0);
    }
    return 0;
}
