#define N2Q_CORE_NO_MAIN
#include "../impl/c/n2qc.c"
#include <assert.h>
#include <pthread.h>

static void coefficients(void) {
    for(int bit=0;bit<5;bit++) {
        uint8_t tt[32];for(int x=0;x<32;x++)tt[x]=(SBOX[x]>>bit)&1;
        for(int step=1;step<32;step<<=1)
            for(int i=0;i<32;i+=step<<1)
                for(int j=i;j<i+step;j++)tt[j+step]^=tt[j];
        int count=0;
        for(int mask=0;mask<32;mask++)if(tt[mask]&1) {
            assert(count<anf_cnt[bit] && anf_mono[bit][count]==mask);count++;
        }
        assert(count==anf_cnt[bit]);
    }
}
static void *worker(void *ignored) {
    (void)ignored;
    const uint8_t expected[32]={
        0x53,0x49,0xa4,0x7e,0xbb,0x78,0xbb,0x4a,0x40,0x3a,0x51,0x8a,0x28,0xf8,0x67,0x40,
        0xdd,0xfd,0x96,0xa8,0x80,0xf7,0x2e,0xa6,0xad,0xa1,0x5a,0x16,0x56,0x07,0x2b,0xed};
    for(int i=0;i<16;i++) {
        uint8_t out[32];
        /* Intentionally use the core BEFORE any legacy initializer. */
        hash_128(NULL,0,out,sizeof out,16);assert(!memcmp(out,expected,sizeof out));
        init_anf(); /* safe even while other threads read the substitution */
    }
    return NULL;
}
int main(void) {
    coefficients();
    pthread_t threads[4];
    for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,worker,NULL));
    for(int i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
    puts("C immutable initialization-free ANF/KAT/concurrency PASS");
    return 0;
}
