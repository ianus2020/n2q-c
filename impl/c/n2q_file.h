/* POSIX N2QF v2 file helpers; included by n2qc.c. See docs/n2qf.md. */
#include <unistd.h>
static void file_le(uint8_t *p, uint64_t x, int n) {
    for (int i=0;i<n;i++) p[i]=(uint8_t)(x>>(8*i));
}
static uint32_t file_len(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void file_ad(uint8_t ad[46], const uint8_t hdr[22], int kind, uint64_t idx, uint64_t total) {
    memcpy(ad,"N2QF/v2",7); memcpy(ad+7,hdr,22); ad[29]=(uint8_t)kind;
    file_le(ad+30,idx,8); file_le(ad+38,total,8);
}
static int file_random(uint8_t *p, size_t n) {
    FILE *f=fopen("/dev/urandom","rb"); if (!f) return 0;
    int ok=fread(p,1,n,f)==n; fclose(f); return ok;
}
static FILE *file_temp(const char *out, char **name) {
    size_t n=strlen(out);
    if (n>SIZE_MAX-16) return NULL;
    *name=malloc(n+16); if (!*name) return NULL;
    snprintf(*name,n+16,"%s.n2q-XXXXXX",out);
    int fd=mkstemp(*name); if(fd<0) {free(*name); *name=NULL; return NULL;}
    FILE *f=fdopen(fd,"wb"); if(!f) {close(fd); unlink(*name); free(*name); *name=NULL;}
    return f;
}
static int file_finish(FILE *fi, FILE *fo, char *tmp, const char *out, int ok) {
    if (fi && fclose(fi)!=0) ok=0;
    if (fo) {
        if (ok && (fflush(fo)!=0 || fsync(fileno(fo))!=0)) ok=0;
        if (fclose(fo)!=0) ok=0;
    }
    if (ok && rename(tmp,out)!=0) ok=0;
    if(tmp) {if(!ok) unlink(tmp); free(tmp);}
    return ok ? 0 : -1;
}
static int enc_file(int r, const uint8_t *key, int bits, const char *inp, const char *out) {
    if ((r!=8 && r!=16) || (bits!=128 && bits!=256)) return -1;
    FILE *fi=fopen(inp,"rb"), *fo=NULL; char *tmp=NULL;
    uint8_t hdr[22]={'N','2','Q','F',2,0}, *pt=NULL, *sealed=NULL;
    int ok=0;
    if(!fi || !file_random(hdr+6,16)) goto done;
    hdr[5]=(bits==128?1:2)|(r==8?0x20:0);
    fo=file_temp(out,&tmp); if(!fo || fwrite(hdr,1,22,fo)!=22) goto done;
    pt=malloc(65536); sealed=malloc(65536+32); if(!pt || !sealed) goto done;
    uint64_t idx=0,total=0;
    for (;;) {
        size_t n=fread(pt,1,65536,fi); if(ferror(fi)) goto done;
        int kind=n==0;
        uint8_t nonce[16]={0}, ad[46], rec[5]; file_le(nonce,idx,8); file_ad(ad,hdr,kind,idx,total);
        size_t len=bits==128?seal_128(key,nonce,ad,46,pt,n,sealed,r):seal_256(key,nonce,ad,46,pt,n,sealed,r);
        if(!len) goto done;
        rec[0]=(uint8_t)kind; file_le(rec+1,len,4);
        if(fwrite(rec,1,5,fo)!=5 || fwrite(sealed,1,len,fo)!=len) goto done;
        if(kind) {ok=1; break;}
        if(UINT64_MAX-total<n || idx==UINT64_MAX) goto done;
        total+=n; idx++;
    }
done:
    if(pt) {secure_wipe(pt,65536); free(pt);} free(sealed);
    return file_finish(fi,fo,tmp,out,ok);
}
static int dec_file(const uint8_t *key, int bits, const char *inp, const char *out) {
    FILE *fi=fopen(inp,"rb"), *fo=NULL; char *tmp=NULL;
    uint8_t hdr[22], *pt=NULL, *sealed=NULL; int ok=0;
    if(!fi || (bits!=128 && bits!=256) || fread(hdr,1,22,fi)!=22 || memcmp(hdr,"N2QF\2",5)) goto done;
    if(hdr[5]!=(bits==128?1:2) && hdr[5]!=((bits==128?1:2)|0x20)) goto done;
    int r=hdr[5]&0x20?8:16; size_t tag=(size_t)bits/8;
    fo=file_temp(out,&tmp); pt=malloc(65536); sealed=malloc(65536+32);
    if(!fo || !pt || !sealed) goto done;
    uint64_t idx=0,total=0;
    for(;;) {
        uint8_t rec[5],nonce[16]={0},ad[46];
        if(fread(rec,1,5,fi)!=5) goto done;
        size_t len=file_len(rec+1); int kind=rec[0];
        /* Validate BOTH ciphertext and plaintext capacities BEFORE fread/open. */
        if(!((kind==0 && len>tag && len<=65536+tag) || (kind==1 && len==tag))) goto done;
        if(fread(sealed,1,len,fi)!=len) goto done;
        file_le(nonce,idx,8); file_ad(ad,hdr,kind,idx,total); size_t plen=0;
        int auth=bits==128?open_128(key,nonce,ad,46,sealed,len,pt,&plen,r):open_256(key,nonce,ad,46,sealed,len,pt,&plen,r);
        if(!auth) goto done;
        if(kind) {if(fgetc(fi)!=EOF || ferror(fi)) goto done; ok=1; break;}
        if(fwrite(pt,1,plen,fo)!=plen || UINT64_MAX-total<plen || idx==UINT64_MAX) goto done;
        total+=plen; idx++;
    }
done:
    if(pt) {secure_wipe(pt,65536); free(pt);} free(sealed);
    return file_finish(fi,fo,tmp,out,ok);
}
