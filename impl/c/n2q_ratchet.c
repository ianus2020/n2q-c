/*
 * n2q_ratchet — forward-secret streaming channel. See n2q_ratchet.h.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_RATCHET_DEMO n2q_ratchet.c -o n2q_ratchet && ./n2q_ratchet
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c" /* QP core: hash_128 (KDF) + seal_128 / open_128 (AEAD) */

#include "n2q_ratchet.h"
#include <string.h>

/* one-way key-derivation from the chain: out = hash( dom | ck ), Secure rounds */
static void kdf(const uint8_t ck[16], uint8_t dom, uint8_t out[16]) {
    uint8_t buf[17];
    buf[0] = dom;
    memcpy(buf + 1, ck, 16);
    hash_128(buf, sizeof buf, out, 16, 16);
    memset(buf, 0, sizeof buf);
}
#define KDF_MSG 0x01 /* derive the one-time message key   */
#define KDF_CHN 0x02 /* advance the chain                 */

static void seq_nonce(uint64_t seq, uint8_t nonce[16]) {
    memset(nonce, 0, 16);
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(seq >> (8 * i));
}

void n2q_ratchet_tx_init(n2q_ratchet_tx *s, const uint8_t root[16]) {
    init_anf();
    memcpy(s->ck, root, 16);
    s->seq = 0;
}

void n2q_ratchet_rx_init(n2q_ratchet_rx *s, const uint8_t root[16]) {
    init_anf();
    memset(s, 0, sizeof *s);
    memcpy(s->ck, root, 16);
    s->next = 0;
}

long n2q_ratchet_seal(n2q_ratchet_tx *s, const uint8_t *aad, size_t aadlen,
                      const uint8_t *in, size_t inlen, uint8_t *out) {
    if (!s || !out || (!in && inlen)) return N2Q_R_ARG;
    if (!aad) aadlen = 0;
    const uint8_t *ad = aad ? aad : (const uint8_t *)"";

    uint8_t mk[16], ck2[16], nonce[16];
    kdf(s->ck, KDF_MSG, mk);
    kdf(s->ck, KDF_CHN, ck2);

    uint64_t seq = s->seq;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(seq >> (8 * i));
    seq_nonce(seq, nonce);
    size_t sn = seal_128(mk, nonce, ad, aadlen, in, inlen, out + 8, 8);

    memcpy(s->ck, ck2, 16); /* advance; the old chain key is overwritten (erased) */
    s->seq++;
    memset(mk, 0, 16);
    memset(ck2, 0, 16);
    return (long)(8 + sn);
}

/* --- receiver skipped-key cache (one-time keys for out-of-order packets) --- */
static int cache_find(n2q_ratchet_rx *s, uint64_t i) {
    for (int j = 0; j < N2Q_RATCHET_SKIP; j++)
        if (s->skip_used[j] && s->skip_i[j] == i) return j;
    return -1;
}
static void cache_put(n2q_ratchet_rx *s, uint64_t i, const uint8_t k[16]) {
    int slot = -1;
    for (int j = 0; j < N2Q_RATCHET_SKIP; j++)
        if (!s->skip_used[j]) { slot = j; break; }
    if (slot < 0) { /* full: evict the oldest (lowest index) */
        slot = 0;
        for (int j = 1; j < N2Q_RATCHET_SKIP; j++)
            if (s->skip_i[j] < s->skip_i[slot]) slot = j;
        memset(s->skip_k[slot], 0, 16); /* erase evicted key (forward secrecy) */
    }
    memcpy(s->skip_k[slot], k, 16);
    s->skip_i[slot] = i;
    s->skip_used[slot] = 1;
}
static void cache_consume(n2q_ratchet_rx *s, int j) {
    memset(s->skip_k[j], 0, 16); /* erase on use: replay is now impossible */
    s->skip_used[j] = 0;
}

int n2q_ratchet_open(n2q_ratchet_rx *s, const uint8_t *aad, size_t aadlen,
                     const uint8_t *pkt, size_t pktlen, uint8_t *out, size_t *outlen) {
    if (!s || !pkt || !out || !outlen) return N2Q_R_ARG;
    if (pktlen < (size_t)N2Q_RATCHET_OVERHEAD) return N2Q_R_SHORT;
    if (!aad) aadlen = 0;
    const uint8_t *ad = aad ? aad : (const uint8_t *)"";

    uint64_t seq = 0;
    for (int i = 0; i < 8; i++) seq |= (uint64_t)pkt[i] << (8 * i);

    uint8_t nonce[16];
    seq_nonce(seq, nonce);
    uint8_t mk[16];

    if (seq < s->next) {
        /* an earlier index: only openable if its one-time key is still cached */
        int j = cache_find(s, seq);
        if (j < 0) return N2Q_R_OLD; /* consumed / evicted / never seen -> forward-secret drop */
        memcpy(mk, s->skip_k[j], 16);
        int ok = open_128(mk, nonce, ad, aadlen, pkt + 8, pktlen - 8, out, outlen, 8);
        if (!ok) { memset(mk, 0, 16); return N2Q_R_AUTH; }
        cache_consume(s, j);
        memset(mk, 0, 16);
        return N2Q_R_OK;
    }

    /* seq >= next: walk the chain forward, but commit only after authentication */
    if (seq - s->next > (uint64_t)N2Q_RATCHET_SKIP) return N2Q_R_OLD; /* too far ahead */

    uint8_t ck[16], cn[16];
    memcpy(ck, s->ck, 16);
    uint8_t skip_k[N2Q_RATCHET_SKIP][16];
    uint64_t skip_i[N2Q_RATCHET_SKIP];
    int skip_n = 0;
    for (uint64_t i = s->next; i < seq; i++) { /* skipped indices -> keep their keys */
        kdf(ck, KDF_MSG, skip_k[skip_n]);
        skip_i[skip_n] = i;
        skip_n++;
        kdf(ck, KDF_CHN, cn);
        memcpy(ck, cn, 16);
    }
    kdf(ck, KDF_MSG, mk);
    kdf(ck, KDF_CHN, cn); /* chain key for index seq+1 */

    int ok = open_128(mk, nonce, ad, aadlen, pkt + 8, pktlen - 8, out, outlen, 8);
    if (!ok) {
        /* forged / not authentic: discard everything, no state change (no DoS) */
        for (int j = 0; j < skip_n; j++) memset(skip_k[j], 0, 16);
        memset(ck, 0, 16); memset(cn, 0, 16); memset(mk, 0, 16);
        return N2Q_R_AUTH;
    }
    /* authentic: commit the advance and cache the skipped keys */
    for (int j = 0; j < skip_n; j++) cache_put(s, skip_i[j], skip_k[j]);
    memcpy(s->ck, cn, 16); /* chain now at seq+1; earlier chain keys are gone */
    s->next = seq + 1;
    for (int j = 0; j < skip_n; j++) memset(skip_k[j], 0, 16);
    memset(ck, 0, 16); memset(cn, 0, 16); memset(mk, 0, 16);
    return N2Q_R_OK;
}

/* -------------------------------------------------------------------------- */
#ifdef N2Q_RATCHET_DEMO
#include <stdio.h>

static int failc = 0;
static void expect(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) failc++;
}

int main(void) {
    printf("n2q_ratchet self-test (forward-secret channel)\n");
    uint8_t root[16];
    for (int i = 0; i < 16; i++) root[i] = (uint8_t)(0x40 + i);

    n2q_ratchet_tx tx;
    n2q_ratchet_rx rx;
    n2q_ratchet_tx_init(&tx, root);
    n2q_ratchet_rx_init(&rx, root);

    enum { N = 10, MAX = 200 };
    static uint8_t plain[N][MAX], pkt[N][MAX + N2Q_RATCHET_OVERHEAD];
    size_t plen[N], pktl[N];
    const uint8_t aad[4] = {'h', 'd', 'r', 0};
    for (int i = 0; i < N; i++) {
        plen[i] = 32 + (size_t)i * 10;
        for (size_t j = 0; j < plen[i]; j++) plain[i][j] = (uint8_t)(i * 17 + (int)j);
        pktl[i] = (size_t)n2q_ratchet_seal(&tx, aad, sizeof aad, plain[i], plen[i], pkt[i]);
    }

    uint8_t out[MAX];
    size_t ol;

    /* in-order 0,1 open and match */
    int okc = 0;
    for (int i = 0; i < 2; i++)
        if (n2q_ratchet_open(&rx, aad, sizeof aad, pkt[i], pktl[i], out, &ol) == N2Q_R_OK &&
            ol == plen[i] && memcmp(out, plain[i], ol) == 0)
            okc++;
    expect("in-order packets open and match", okc == 2);

    /* out-of-order within window: deliver 4 (caches 2,3), then 3, then 2 */
    int oo = 0;
    if (n2q_ratchet_open(&rx, aad, sizeof aad, pkt[4], pktl[4], out, &ol) == N2Q_R_OK &&
        memcmp(out, plain[4], ol) == 0) oo++;
    if (n2q_ratchet_open(&rx, aad, sizeof aad, pkt[3], pktl[3], out, &ol) == N2Q_R_OK &&
        memcmp(out, plain[3], ol) == 0) oo++;
    if (n2q_ratchet_open(&rx, aad, sizeof aad, pkt[2], pktl[2], out, &ol) == N2Q_R_OK &&
        memcmp(out, plain[2], ol) == 0) oo++;
    expect("reorder within window (skipped keys cached)", oo == 3);

    /* replay of an already-consumed packet -> dropped */
    expect("replay of consumed packet rejected",
           n2q_ratchet_open(&rx, aad, sizeof aad, pkt[2], pktl[2], out, &ol) == N2Q_R_OLD);

    /* tamper -> auth fail (packet 5, not yet delivered) */
    {
        uint8_t bad[MAX + N2Q_RATCHET_OVERHEAD];
        memcpy(bad, pkt[5], pktl[5]);
        bad[10] ^= 0x20;
        expect("tampered packet rejected (auth)",
               n2q_ratchet_open(&rx, aad, sizeof aad, bad, pktl[5], out, &ol) == N2Q_R_AUTH);
    }

    /* THE forward-secrecy property: snapshot the receiver *now* (rx.next == 5,
       packets 0..4 already consumed), as if the device were seized. The snapshot
       must NOT be able to decrypt an earlier recorded packet (its key is gone). */
    n2q_ratchet_rx seized = rx; /* copy of full receiver state */
    int fs = (n2q_ratchet_open(&seized, aad, sizeof aad, pkt[1], pktl[1], out, &ol) == N2Q_R_OLD) &&
             (n2q_ratchet_open(&seized, aad, sizeof aad, pkt[0], pktl[0], out, &ol) == N2Q_R_OLD);
    expect("FORWARD SECRECY: seized state cannot decrypt earlier packets", fs);

    /* the live channel keeps flowing: packet 5 still opens */
    expect("channel keeps flowing after all of the above",
           n2q_ratchet_open(&rx, aad, sizeof aad, pkt[5], pktl[5], out, &ol) == N2Q_R_OK &&
               memcmp(out, plain[5], ol) == 0);

    printf("%s (%d failures)\n", failc == 0 ? "ALL PASS" : "FAILURES", failc);
    return failc ? 1 : 0;
}
#endif /* N2Q_RATCHET_DEMO */
