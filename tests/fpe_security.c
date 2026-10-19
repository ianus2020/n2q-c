#include "../impl/c/n2q_fpe.c"
#include <assert.h>
int main(void) {
    uint8_t key[16]={0},a[256]={0},b[65]={0};char x[18],y[18];b[64]=1;
    assert(n2q_fpe_encrypt(key,a,65,"123456789012345678",x,18));
    assert(n2q_fpe_encrypt(key,b,65,"123456789012345678",y,18));
    assert(memcmp(x,y,18));
    assert(!n2q_fpe_encrypt(key,a,256,"123456789012345678",x,18));
    puts("C FPE tweak regressions PASS");
}
