#include "../../impl/c/n2q_fireline.c"
#include <assert.h>
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv; init_anf(); return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;
    n2q_fl_peer peer = {{0},{0}};
    uint8_t out[256]; size_t len = 999;
    int result = n2q_fireline_open(&peer,data,size,(const uint8_t *)"ctx",3,out,sizeof out,&len);
    assert(len <= sizeof out);
    if (result != N2Q_FL_OK) assert(len == 0);
    return 0;
}
