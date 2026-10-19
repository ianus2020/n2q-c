/* POSIX reference state journal. External monotonic anchoring is mandatory. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "n2q_cone_state.h"
#include "n2q_cone.c"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(N2Q_CONE_SIGNATURE_BYTES == CN_SIG, "signature layout mismatch");
#define CS_HEADER 37
#define CS_RECORD 8
static pthread_once_t cs_once = PTHREAD_ONCE_INIT;
static int cs_ready(void) { return pthread_once(&cs_once, init_anf) == 0; }
static void cs_key_id(const uint8_t seed[32], uint8_t id[32]) {
    cn_h(0x06, seed, 32, NULL, 0, id);
}
static uint32_t cs_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void cs_put32(uint8_t *p, uint32_t n) {
    for (int i=0;i<4;i++) p[i]=(uint8_t)(n>>(i*8));
}
static int cs_read(int fd, uint8_t *out, size_t len, off_t off) {
    while (len) {
        ssize_t n=pread(fd,out,len,off);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return 0;
        out+=n;len-=(size_t)n;off+=n;
    }
    return 1;
}
static int cs_write(int fd, const uint8_t *in, size_t len, off_t off) {
    while (len) {
        ssize_t n=pwrite(fd,in,len,off);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return 0;
        in+=n;len-=(size_t)n;off+=n;
    }
    return 1;
}
/* Anchor the directory fd and use openat: do not re-resolve it after checks. */
static int cs_parent(const char *path, char **storage, const char **base) {
    if (!path || !*path) return -1;
    size_t size=strlen(path);
    if (size>SIZE_MAX-2) return -1;
    *storage=malloc(size+2);
    if (!*storage) return -1;
    memcpy(*storage,path,size+1);
    char *slash=strrchr(*storage,'/');
    const char *parent=".";
    if (slash) {
        *base=slash+1;
        if (slash==*storage) parent="/";
        else {*slash=0;parent=*storage;}
    } else *base=*storage;
    if (!**base || !strcmp(*base,".") || !strcmp(*base,"..")) return -1;
    int fd=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    struct stat st;
    if (fstat(fd,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0022)) {
        close(fd);return -1;
    }
    return fd;
}
int n2q_cone_public_root(const uint8_t seed[32], uint8_t *root, size_t rootcap) {
    if (!seed || !root || rootcap<32) return N2Q_CN_ARG;
    if (!cs_ready()) return N2Q_CN_IO;
    cn_root(seed,root);
    return N2Q_CN_OK;
}
int n2q_cone_verify_certificate(const uint8_t root[32], const uint8_t *msg, size_t mlen,
                                 const uint8_t *sig, size_t slen) {
    if (!cs_ready()) return 0;
    return n2q_cone_verify(root,msg,mlen,sig,slen);
}
int n2q_cone_state_create(const uint8_t seed[32], const char *path) {
    if (!seed || !path) return N2Q_CN_ARG;
    if (!cs_ready()) return N2Q_CN_IO;
    char *storage=NULL;const char *base=NULL;
    int parent=cs_parent(path,&storage,&base),fd=-1,result=N2Q_CN_IO;
    if (parent<0) goto done;
    fd=openat(parent,base,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) goto done;
    uint8_t header[CS_HEADER]={'N','2','Q','S',1};
    cs_key_id(seed,header+5);
    if (fchmod(fd,0600) || !cs_write(fd,header,sizeof header,0) || fsync(fd) || fsync(parent))
        goto done;
    result=N2Q_CN_OK;
done:
    if (fd>=0 && close(fd) && result==N2Q_CN_OK) result=N2Q_CN_IO;
    if (parent>=0) close(parent);
    free(storage);
    return result;
}
static int cs_reserve(const uint8_t seed[32], const char *path,
                       n2q_cone_anchor_fn anchor, void *context, uint32_t *index) {
    char *storage=NULL;const char *base=NULL;
    int parent=cs_parent(path,&storage,&base),fd=-1,result=N2Q_CN_IO;
    uint8_t expected[32],header[CS_HEADER];
    if (parent<0) goto done;
    fd=openat(parent,base,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0 || flock(fd,LOCK_EX)) goto done;
    struct stat st;
    if (fstat(fd,&st)) goto done;
    result=N2Q_CN_STATE;
    if (!S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 ||
        (st.st_mode&0077) || st.st_size<CS_HEADER ||
        st.st_size>CS_HEADER+CN_LEAVES*CS_RECORD || (st.st_size-CS_HEADER)%CS_RECORD) goto done;
    if (!cs_read(fd,header,sizeof header,0) || memcmp(header,"N2QS\1",5)) goto done;
    cs_key_id(seed,expected);
    if (memcmp(header+5,expected,32)) goto done;
    uint32_t count=(uint32_t)((st.st_size-CS_HEADER)/CS_RECORD);
    uint8_t record[CS_RECORD];
    for (uint32_t i=0;i<count;i++) {
        if (!cs_read(fd,record,sizeof record,CS_HEADER+(off_t)i*CS_RECORD) ||
            cs_u32(record)!=i || cs_u32(record+4)!=~i) goto done;
    }
    if (count>=CN_LEAVES) {result=N2Q_CN_EXHAUSTED;goto done;}
    cs_put32(record,count);cs_put32(record+4,~count);
    result=N2Q_CN_IO;
    if (!cs_write(fd,record,sizeof record,CS_HEADER+(off_t)count*CS_RECORD) ||
        fsync(fd) || fsync(parent)) goto done;
    /* Consume both reservations BEFORE signature generation. Unknown outcomes burn
     * the index. The callback must not re-enter this signer while its lock is held. */
    result=N2Q_CN_ANCHOR;
    if (anchor(context,expected,count)!=1) goto done;
    *index=count;result=N2Q_CN_OK;
done:
    if (fd>=0) close(fd); /* releases flock even on all failure paths */
    if (parent>=0) close(parent);
    free(storage);
    return result;
}
int n2q_cone_sign_reserved(const uint8_t seed[32], const char *path,
                            n2q_cone_anchor_fn anchor, void *context,
                            const uint8_t *msg, size_t mlen,
                            uint8_t *sig, size_t sigcap, size_t *siglen) {
    if (!siglen) return N2Q_CN_ARG;
    *siglen=0;
    if (!seed || !path || !anchor || !sig || sigcap<CN_SIG ||
        mlen>CN_MAX_MESSAGE || (mlen && !msg)) return N2Q_CN_ARG;
    if (!cs_ready()) return N2Q_CN_IO;
    uint32_t index=0;
    int result=cs_reserve(seed,path,anchor,context,&index);
    if (result!=N2Q_CN_OK) return result;
    size_t len=n2q_cone_sign(seed,index,msg,mlen,sig,sigcap);
    if (len!=CN_SIG) return N2Q_CN_STATE;
    *siglen=len;
    return N2Q_CN_OK;
}
