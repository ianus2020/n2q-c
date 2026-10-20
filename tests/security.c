#define N2Q_CORE_NO_MAIN
#include "../impl/c/n2q_seek.c"
#include <assert.h>
int main(void) {
    init_anf();
    uint8_t key[32]={0},nonce[16]={0},sealed[64],out[64];size_t len;
    for(int bits=128;bits<=256;bits+=128) for(int r=8;r<=16;r+=8) {
        size_t sn=bits==128?seal_128(key,nonce,(uint8_t*)"",0,(uint8_t*)"secret",6,sealed,r):seal_256(key,nonce,(uint8_t*)"",0,(uint8_t*)"secret",6,sealed,r);
        sealed[sn-1]^=1;memset(out,0x55,sizeof out);len=99;
        int ok=bits==128?open_128(key,nonce,(uint8_t*)"",0,sealed,sn,out,&len,r):open_256(key,nonce,(uint8_t*)"",0,sealed,sn,out,&len,r);
        assert(!ok && len==0);for(int i=0;i<6;i++) assert(out[i]==0);
        sn=bits==128?sseal_128(key,nonce,(uint8_t*)"",0,(uint8_t*)"secret",6,sealed,r):sseal_256(key,nonce,(uint8_t*)"",0,(uint8_t*)"secret",6,sealed,r);
        sealed[sn-1]^=1;memset(out,0x55,sizeof out);len=99;
        ok=bits==128?sopen_128(key,nonce,(uint8_t*)"",0,sealed,sn,out,&len,r):sopen_256(key,nonce,(uint8_t*)"",0,sealed,sn,out,&len,r);
        assert(!ok && len==0);for(int i=0;i<6;i++) assert(out[i]==0);
        len=99;assert(!open_128(key,nonce,(uint8_t*)"",0,sealed,0,out,&len,0) && len==0);
    }
    uint8_t bad[27]={'N','2','Q','F',2,1};bad[23]=bad[24]=bad[25]=bad[26]=255;
    assert(n2q_seek_chunk(key,bad,sizeof bad,0,out,sizeof out,&len)!=0 && len==0);
    puts("C security regressions PASS");return 0;
}
