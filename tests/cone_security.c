#include "../impl/c/n2q_cone_state.c"
#include <assert.h>
#include <sys/wait.h>

typedef struct {
    pthread_mutex_t lock;
    int highest, known;
    uint8_t id[32];
} test_anchor;
/* TEST ONLY: this in-memory anchor is NOT durable and is not a deployment backend. */
static int accept_index(void *ptr, const uint8_t id[32], uint32_t index) {
    test_anchor *a=ptr;pthread_mutex_lock(&a->lock);
    int ok=(!a->known || !memcmp(a->id,id,32)) && (int)index>a->highest;
    if (ok) {memcpy(a->id,id,32);a->known=1;a->highest=(int)index;}
    pthread_mutex_unlock(&a->lock);return ok;
}
static int crash_after_local_fsync(void *ptr, const uint8_t id[32], uint32_t index) {
    (void)ptr;(void)id;(void)index;_exit(42);
}
static void hash_compatibility(void) {
    uint8_t a[64],b[64],combined[129],expected[32],got[64];
    for (int i=0;i<64;i++) {a[i]=(uint8_t)i;b[i]=(uint8_t)(255-i);}
    for (size_t al=0;al<25;al++) for (size_t bl=0;bl<17;bl++) {
        combined[0]=5;memcpy(combined+1,a,al);memcpy(combined+1+al,b,bl);
        hash_128(combined,1+al+bl,expected,32,16);
        cn_h(5,a,al,b,bl,got);assert(!memcmp(got,expected,32));
        memcpy(got,a,sizeof a);cn_h(5,got,al,b,bl,got);
        assert(!memcmp(got,expected,32)); /* chain hashing aliases input/output */
    }
}
typedef struct {
    const uint8_t *seed;
    const char *path;
    test_anchor *anchor;
    const char *message;
    uint8_t sig[CN_SIG];
    size_t len;
    int result;
} sign_job;
static void *sign_worker(void *ptr) {
    sign_job *j=ptr;
    j->result=n2q_cone_sign_reserved(j->seed,j->path,accept_index,j->anchor,
        (const uint8_t *)j->message,strlen(j->message),j->sig,sizeof j->sig,&j->len);
    return NULL;
}
typedef struct {
    const uint8_t *root,*sig;
    const char *message;
} verify_job;
static void *verify_worker(void *ptr) {
    verify_job *j=ptr;
    for (int i=0;i<8;i++)
        assert(n2q_cone_verify_certificate(j->root,(const uint8_t *)j->message,
                 strlen(j->message),j->sig,CN_SIG));
    return NULL;
}
static void concurrent_verification(void) {
    uint8_t seed[32]={1},root[32],sigs[2][CN_SIG];
    assert(n2q_cone_public_root(seed,root,sizeof root)==N2Q_CN_OK);
    for (int i=0;i<2;i++)
        assert(n2q_cone_sign(seed,(uint32_t)i,(const uint8_t *)(i?"second":"first"),
                             i?6:5,sigs[i],sizeof sigs[i])==CN_SIG);
    verify_job jobs[4];
    pthread_t threads[4];
    for (int i=0;i<4;i++) {
        jobs[i]=(verify_job){root,sigs[i%2],i%2?"second":"first"};
        assert(!pthread_create(&threads[i],NULL,verify_worker,&jobs[i]));
    }
    for (int i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
    puts("CoNe concurrent verification PASS");
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc>1) {concurrent_verification();return 0;}
    assert(cs_ready());hash_compatibility();
    char directory[]="/tmp/n2q-cone-XXXXXX";assert(mkdtemp(directory));
    char path[512],other[512],linkpath[512],torn[512],crash[512];
    snprintf(path,sizeof path,"%s/state",directory);
    snprintf(other,sizeof other,"%s/missing",directory);
    snprintf(linkpath,sizeof linkpath,"%s/link",directory);
    snprintf(torn,sizeof torn,"%s/torn",directory);
    snprintf(crash,sizeof crash,"%s/crash",directory);
    uint8_t seed[32]={1},wrong[32]={2},root[32],sig[CN_SIG],saved[CS_HEADER+CS_RECORD];
    size_t len=99;test_anchor anchor={PTHREAD_MUTEX_INITIALIZER,-1,0,{0}};
    assert(n2q_cone_public_root(seed,root,sizeof root)==N2Q_CN_OK);
    assert(n2q_cone_state_create(seed,path)==N2Q_CN_OK);
    assert(n2q_cone_state_create(seed,path)!=N2Q_CN_OK);
    assert(n2q_cone_sign_reserved(seed,path,NULL,NULL,NULL,0,sig,sizeof sig,&len)==N2Q_CN_ARG && !len);
    memset(sig,0x55,sizeof sig);
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,8,&len)==N2Q_CN_ARG && !len);
    assert(anchor.highest==-1 && sig[0]==0x55);
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,(uint8_t *)"first",5,
                                   sig,sizeof sig,&len)==N2Q_CN_OK && len==CN_SIG);
    assert(cs_u32(sig)==0 && n2q_cone_verify_certificate(root,(uint8_t *)"first",5,sig,len));
    int fd=open(path,O_RDWR);assert(fd>=0);
    assert(cs_read(fd,saved,sizeof saved,0));assert(!close(fd));
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,(uint8_t *)"second",6,
                                   sig,sizeof sig,&len)==N2Q_CN_OK && cs_u32(sig)==1);
    /* Restoring an older VALID local snapshot is rejected by the external anchor. */
    fd=open(path,O_RDWR);assert(fd>=0 && !ftruncate(fd,sizeof saved));
    assert(cs_write(fd,saved,sizeof saved,0) && !fsync(fd));close(fd);
    memset(sig,0x55,sizeof sig);len=99;
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_ANCHOR);
    assert(!len && sig[0]==0x55 && anchor.highest==1);
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_OK);
    assert(cs_u32(sig)==2);
    assert(n2q_cone_sign_reserved(wrong,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_STATE && !len);
    assert(n2q_cone_sign_reserved(seed,other,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)!=N2Q_CN_OK && !len);
    assert(access(other,F_OK));
    assert(!chmod(path,0644));
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_STATE);
    assert(!chmod(path,0600));
    assert(!symlink(path,linkpath));
    assert(n2q_cone_sign_reserved(seed,linkpath,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)!=N2Q_CN_OK);
    unlink(linkpath);
    assert(!link(path,linkpath));
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_STATE);
    unlink(linkpath);
    assert(n2q_cone_state_create(seed,torn)==N2Q_CN_OK);
    fd=open(torn,O_WRONLY|O_APPEND);assert(fd>=0 && write(fd,"x",1)==1);close(fd);
    assert(n2q_cone_sign_reserved(seed,torn,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_STATE && !len);
    /* A process exit after local reservation must burn the reserved leaf. */
    assert(n2q_cone_state_create(seed,crash)==N2Q_CN_OK);
    pid_t pid=fork();assert(pid>=0);
    if (!pid) {
        n2q_cone_sign_reserved(seed,crash,crash_after_local_fsync,NULL,NULL,0,sig,sizeof sig,&len);
        _exit(99);
    }
    int status=0;assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==42);
    test_anchor crash_anchor={PTHREAD_MUTEX_INITIALIZER,-1,0,{0}};
    assert(n2q_cone_sign_reserved(seed,crash,accept_index,&crash_anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_OK);
    assert(cs_u32(sig)==1);
    /* Independent callers on the same journal receive distinct indices. */
    sign_job jobs[2]={{seed,path,&anchor,"A",{0},0,0},{seed,path,&anchor,"B",{0},0,0}};
    pthread_t threads[2];
    for (int i=0;i<2;i++) assert(!pthread_create(&threads[i],NULL,sign_worker,&jobs[i]));
    for (int i=0;i<2;i++) {assert(!pthread_join(threads[i],NULL));assert(jobs[i].result==N2Q_CN_OK);}
    assert(cs_u32(jobs[0].sig)!=cs_u32(jobs[1].sig));
    for (int i=0;i<2;i++) assert(n2q_cone_verify_certificate(root,(uint8_t *)jobs[i].message,1,jobs[i].sig,jobs[i].len));
    while (anchor.highest<15) {
        uint32_t reserved=0;
        assert(cs_reserve(seed,path,accept_index,&anchor,&reserved)==N2Q_CN_OK);
    }
    assert(n2q_cone_sign_reserved(seed,path,accept_index,&anchor,NULL,0,sig,sizeof sig,&len)==N2Q_CN_EXHAUSTED && !len);
    assert(!n2q_cone_sign(seed,0,NULL,CN_MAX_MESSAGE+1,sig,sizeof sig));
    assert(!n2q_cone_verify_certificate(root,NULL,CN_MAX_MESSAGE+1,sig,sizeof sig));
    unlink(path);unlink(torn);unlink(crash);assert(!rmdir(directory));
    puts("CoNe durable journal, rollback rejection, crash and capacity regressions PASS");
    return 0;
}
