/* Integration fixture only: PUBLIC fixed seed, never a production signing tool. */
#include "../impl/c/n2q_cone_state.c"
#include "../impl/c/n2q_cone_anchor_http.h"

int main(int argc,char **argv) {
    uint8_t seed[32];for(size_t i=0;i<32;i++)seed[i]=(uint8_t)i;
    if (argc==3 && !strcmp(argv[1],"create")) {
        if(n2q_cone_state_create(seed,argv[2])!=N2Q_CN_OK)return 2;
        uint8_t id[32];cs_key_id(seed,id);
        for(size_t i=0;i<32;i++)printf("%02x",id[i]);puts("");return 0;
    }
    if (argc!=7 || strcmp(argv[6],"PUBLIC_TEST_SEED")) return 2;
    n2q_cone_http_anchor config={argv[1],argv[2],argv[3],argv[4],1000,3000};
    const uint8_t msg[]="local integration test certificate";
    uint8_t sig[N2Q_CONE_SIGNATURE_BYTES],root[32];size_t size=0;
    int result=n2q_cone_sign_reserved(seed,argv[5],n2q_cone_anchor_https,&config,
                                     msg,sizeof msg-1,sig,sizeof sig,&size);
    if(result!=N2Q_CN_OK){printf("sign_failed=%d signature_bytes=%zu\n",result,size);return 3;}
    if(n2q_cone_public_root(seed,root,sizeof root)!=N2Q_CN_OK ||
       !n2q_cone_verify_certificate(root,msg,sizeof msg-1,sig,size))return 4;
    printf("verified_index=%u\n",cs_u32(sig));
    (void)argv[6]; /* explicit fixture acknowledgement required by test runner */
    return 0;
}
