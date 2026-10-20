/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_seek — random-access (seekable) decryption for the N2QF container.
 *
 * N2QF v2 selection validates all records and the final marker first.
 * This reference prioritizes whole-file integrity over random-access speed.
 *
 *   See docs/n2qf.md for the v2 wire format.
 *   chunk i nonce = 16-byte little-endian i
 *
 *   int n2q_seek_chunk(key, buf, buflen, index, out, outcap, *outlen)  // 0 on success
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_SEEK_DEMO n2q_seek.c -o n2q_seek && ./n2q_seek
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

enum { N2Q_SEEK_OK = 0, N2Q_SEEK_RANGE = -1, N2Q_SEEK_FORMAT = -2,
       N2Q_SEEK_TRUNC = -3, N2Q_SEEK_AUTH = -4, N2Q_SEEK_SUITE = -5 };

/* Authenticate the complete v2 container before releasing the requested chunk.
 * outcap is mandatory; maximum chunk size is 65536 bytes. */
int n2q_seek_chunk(const uint8_t *key, const uint8_t *buf, size_t buflen,
                   uint64_t index, uint8_t *out, size_t outcap, size_t *outlen) {
    *outlen=0;
    if(buflen<22 || memcmp(buf,"N2QF\2",5)) return N2Q_SEEK_FORMAT;
    if(buf[5]!=1 && buf[5]!=0x21) return N2Q_SEEK_SUITE;
    uint8_t *scratch=malloc(65536);if(!scratch) return N2Q_SEEK_FORMAT;
    size_t p=22, selected=0, slen=0;uint64_t i=0,total=0,selected_total=0;
    int result=N2Q_SEEK_TRUNC, r=buf[5]&0x20?8:16;
    for(;;) {
        if(buflen-p<5) break;
        int kind=buf[p];size_t len=file_len(buf+p+1);p+=5;
        if(!((kind==0 && len>16 && len<=65552) || (kind==1 && len==16))) {result=N2Q_SEEK_FORMAT;break;}
        if(len>buflen-p) break;
        uint8_t nonce[16]={0},ad[46];size_t plen=0;
        file_le(nonce,i,8);file_ad(ad,buf,kind,i,total);
        if(!open_128(key,nonce,ad,46,buf+p,len,scratch,&plen,r)) {result=N2Q_SEEK_AUTH;break;}
        if(kind) {
            if(p+len!=buflen) {result=N2Q_SEEK_FORMAT;break;}
            if(!selected) {result=N2Q_SEEK_RANGE;break;}
            if(slen-16>outcap) {result=N2Q_SEEK_RANGE;break;}
            file_le(nonce,index,8);file_ad(ad,buf,0,index,selected_total);
            result=open_128(key,nonce,ad,46,buf+selected,slen,out,outlen,r)?N2Q_SEEK_OK:N2Q_SEEK_AUTH;
            break;
        }
        if(i==index) {selected=p;slen=len;selected_total=total;}
        if(UINT64_MAX-total<plen || i==UINT64_MAX) {result=N2Q_SEEK_FORMAT;break;}
        total+=plen;i++;p+=len;
    }
    secure_wipe(scratch,65536);free(scratch);return result;
}

#ifdef N2Q_SEEK_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

/* build a small N2QF container in-memory from `n` fixed-size chunks */
static size_t build(const uint8_t *key, uint8_t plain[][100], int n, uint8_t *buf) {
    memcpy(buf,"N2QF\2",5);buf[5]=0x21;if(!file_random(buf+6,16)) return 0;
    size_t p=22;uint64_t total=0;
    for(int i=0;i<=n;i++) {
        uint8_t nonce[16]={0},ad[46],sealed[160];int kind=i==n;
        file_le(nonce,(uint64_t)i,8);file_ad(ad,buf,kind,(uint64_t)i,total);
        size_t sn=seal_128(key,nonce,ad,46,kind?(const uint8_t *)"":plain[i],kind?0:100,sealed,8);
        buf[p++]=(uint8_t)kind;file_le(buf+p,sn,4);p+=4;memcpy(buf+p,sealed,sn);p+=sn;total+=kind?0:100;
    }
    return p;
}

int main(void) {
    init_anf();
    printf("n2q_seek self-test (random-access N2QF)\n");
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x44 + i);

    enum { N = 6 };
    static uint8_t plain[N][100];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < 100; j++) plain[i][j] = (uint8_t)(i * 41 + j);

    static uint8_t buf[4096];
    size_t blen = build(key, plain, N, buf);

    uint8_t out[100]; size_t ol;
    /* jump straight to chunk 4 without touching 0..3 */
    ex("seek chunk 4 decrypts to the right block",
       n2q_seek_chunk(key, buf, blen, 4, out, sizeof out, &ol) == N2Q_SEEK_OK && ol == 100 &&
           memcmp(out, plain[4], 100) == 0);
    /* and to chunk 1 */
    ex("seek chunk 1 decrypts to the right block",
       n2q_seek_chunk(key, buf, blen, 1, out, sizeof out, &ol) == N2Q_SEEK_OK && memcmp(out, plain[1], 100) == 0);
    /* out-of-range index */
    ex("seek past the end reports range error",
       n2q_seek_chunk(key, buf, blen, 99, out, sizeof out, &ol) == N2Q_SEEK_RANGE);
    /* a tampered chunk fails its own auth without affecting the others */
    { size_t save_i = 22 + 5 + 20; uint8_t save = buf[save_i]; buf[save_i] ^= 0x40;
      ex("tampered chunk 0 fails auth", n2q_seek_chunk(key, buf, blen, 0, out, sizeof out, &ol) == N2Q_SEEK_AUTH);
      buf[save_i] = save;
      ex("chunk 5 still fine after another chunk was tampered",
         n2q_seek_chunk(key, buf, blen, 5, out, sizeof out, &ol) == N2Q_SEEK_OK && memcmp(out, plain[5], 100) == 0); }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
