#include "../impl/c/n2q_fireline.c"
#include <assert.h>
int main(void) {
    init_anf();
    n2q_fl_peer me = {{0}, {0}};
    memcpy(me.id, "node-001", 8);
    uint8_t dek[16] = {1}, nonce[16] = {2}, parcel[256], bad[256], out[8];
    for (int fast = 0; fast <= 1; fast++) {
        size_t len = n2q_fireline_seal(&me,1,dek,nonce,NULL,0,(uint8_t *)"payload",7,
                                      parcel,sizeof parcel,fast), olen = 99;
        assert(len > 0);
        memset(out,0x55,sizeof out);
        assert(n2q_fireline_open(&me,parcel,len,NULL,0,out,6,&olen) == N2Q_FL_ARG && olen == 0);
        for (size_t i=0;i<sizeof out;i++) assert(out[i] == 0x55);
        assert(n2q_fireline_open(&me,parcel,len,NULL,0,out,sizeof out,&olen) == N2Q_FL_OK);
        assert(olen == 7 && !memcmp(out,"payload",7));
        for (size_t end=0;end<len;end++) {
            olen=99;
            assert(n2q_fireline_open(&me,parcel,end,NULL,0,out,sizeof out,&olen) != N2Q_FL_OK);
            assert(olen == 0);
        }
        memcpy(bad,parcel,len); bad[len]=0; olen=99;
        assert(n2q_fireline_open(&me,bad,len+1,NULL,0,out,sizeof out,&olen) == N2Q_FL_FORMAT && !olen);
        memcpy(bad,parcel,len); bad[5]=0x81; olen=99;
        assert(n2q_fireline_open(&me,bad,len,NULL,0,out,sizeof out,&olen) == N2Q_FL_FORMAT && !olen);
        /* A valid recipient wrap plus attacker-expanded body must not overflow out. */
        memcpy(bad,parcel,48+16); memset(bad+64,0,100);
        bad[64]=80; /* sealed length; remaining length bytes are zero */
        olen=99;
        assert(n2q_fireline_open(&me,bad,48+20+80,NULL,0,out,sizeof out,&olen) != N2Q_FL_OK && !olen);
        memcpy(bad,parcel,len); bad[len-1]^=1; olen=99;
        assert(n2q_fireline_open(&me,bad,len,NULL,0,out,sizeof out,&olen) == N2Q_FL_AUTH && !olen);
        for (size_t i=0;i<7;i++) assert(out[i] == 0);
        memset(out,0x55,sizeof out);
        assert(!n2q_fireline_seal(&me,1,dek,nonce,NULL,0,(uint8_t *)"payload",7,out,sizeof out,fast));
        for (size_t i=0;i<sizeof out;i++) assert(out[i] == 0x55);
        len=n2q_fireline_seal(&me,1,dek,nonce,NULL,0,NULL,0,parcel,sizeof parcel,fast);
        assert(len && n2q_fireline_open(&me,parcel,len,NULL,0,NULL,0,&olen) == N2Q_FL_OK && !olen);
    }
    assert(!n2q_fireline_seal(&me,1,dek,nonce,NULL,0,(uint8_t *)"x",SIZE_MAX,parcel,sizeof parcel,0));
    assert(!n2q_fireline_seal(&me,1,dek,nonce,NULL,SIZE_MAX,NULL,0,parcel,sizeof parcel,0));
    n2q_fl_peer duplicate[2] = {me,me};
    assert(!n2q_fireline_seal(duplicate,2,dek,nonce,NULL,0,NULL,0,parcel,sizeof parcel,0));
    puts("FireLine capacity/framing security regressions PASS");
    return 0;
}
