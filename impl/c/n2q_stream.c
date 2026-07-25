/*
 * n2q_stream — real-time audio/video streaming AEAD on top of N2Q.
 * See n2q_stream.h for the wire format and API contract.
 *
 * Build the self-test:
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_STREAM_DEMO n2q_stream.c -o n2q_stream && ./n2q_stream
 * Build as a library object (no main):
 *   cc -O2 -c n2q_stream.c            # links the QP core in via n2qc.c
 *
 * -Wno-unused-function is only because we embed the full n2qc.c reference core,
 * whose hash / blind-index / file helpers are unused by the streaming layer.
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c" /* QP core: seal_128 / open_128 / seal_256 / open_256 (static, same TU) */

#include "n2q_stream.h"
#include <string.h>

/* nonce = 16 bytes, sequence number little-endian in the low 8, rest zero */
static void seq_to_nonce(uint64_t seq, uint8_t nonce[16]) {
    memset(nonce, 0, 16);
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(seq >> (8 * i));
}

int n2q_stream_init(n2q_stream *s, const uint8_t *key, int keylen, int fast) {
    if (!s || !key || (keylen != 16 && keylen != 32)) return N2Q_ERR_ARG;
    init_anf(); /* build the S-box ANF tables the QP core needs (idempotent) */
    memset(s, 0, sizeof *s);
    memcpy(s->key, key, (size_t)keylen);
    s->keylen = keylen;
    s->rounds = fast ? 8 : 16;
    return N2Q_OK;
}

long n2q_stream_seal(n2q_stream *s, const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t inlen, uint8_t *out) {
    if (!s || !out || (!in && inlen)) return N2Q_ERR_ARG;
    if (!aad) aadlen = 0;
    const uint8_t *ad = aad ? aad : (const uint8_t *)"";
    uint64_t seq = s->send_seq;

    uint8_t nonce[16];
    seq_to_nonce(seq, nonce);
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(seq >> (8 * i)); /* seq header (LE) */

    size_t sn = (s->keylen == 16)
        ? seal_128(s->key, nonce, ad, aadlen, in, inlen, out + 8, s->rounds)
        : seal_256(s->key, nonce, ad, aadlen, in, inlen, out + 8, s->rounds);

    s->send_seq++;
    return (long)(8 + sn);
}

int n2q_stream_open(n2q_stream *s, const uint8_t *aad, size_t aadlen,
                    const uint8_t *pkt, size_t pktlen,
                    uint8_t *out, size_t *outlen) {
    if (!s || !pkt || !out || !outlen) return N2Q_ERR_ARG;
    if (pktlen < (size_t)N2Q_STREAM_OVERHEAD) return N2Q_ERR_SHORT;
    if (!aad) aadlen = 0;
    const uint8_t *ad = aad ? aad : (const uint8_t *)"";

    uint64_t seq = 0;
    for (int i = 0; i < 8; i++) seq |= (uint64_t)pkt[i] << (8 * i); /* seq header (LE) */

    /* replay precheck: reject clearly-old or duplicate packets before verifying */
    if (s->recv_started && seq <= s->recv_max) {
        uint64_t diff = s->recv_max - seq;
        if (diff >= N2Q_STREAM_WINDOW) return N2Q_ERR_REPLAY;   /* older than the window */
        if (s->recv_win & (1ull << diff)) return N2Q_ERR_REPLAY; /* already seen         */
    }

    uint8_t nonce[16];
    seq_to_nonce(seq, nonce);
    size_t ptlen = 0;
    int ok = (s->keylen == 16)
        ? open_128(s->key, nonce, ad, aadlen, pkt + 8, pktlen - 8, out, &ptlen, s->rounds)
        : open_256(s->key, nonce, ad, aadlen, pkt + 8, pktlen - 8, out, &ptlen, s->rounds);
    if (!ok) return N2Q_ERR_AUTH; /* window unchanged: a forged packet cannot advance it */

    /* authenticated -> commit the sliding replay window */
    if (!s->recv_started) {
        s->recv_max = seq;
        s->recv_win = 1ull;
        s->recv_started = 1;
    } else if (seq > s->recv_max) {
        uint64_t shift = seq - s->recv_max;
        s->recv_win = (shift >= 64) ? 1ull : ((s->recv_win << shift) | 1ull);
        s->recv_max = seq;
    } else {
        s->recv_win |= (1ull << (s->recv_max - seq));
    }

    *outlen = ptlen;
    return N2Q_OK;
}

/* --------------------------------------------------------------------------
 * Self-test: model a real media stream (loss, reordering, a duplicate, a
 * tampered packet, a wrong-AAD packet) and check the endpoint behaves.
 * -------------------------------------------------------------------------- */
#ifdef N2Q_STREAM_DEMO
#include <stdio.h>

static int failc = 0;
static void expect(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) failc++;
}

static void run(int keylen, int fast, const char *label) {
    printf("-- %s (overhead %d B/pkt) --\n", label, N2Q_STREAM_OVERHEAD);
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x10 + i);

    n2q_stream tx, rx;
    n2q_stream_init(&tx, key, keylen, fast);
    n2q_stream_init(&rx, key, keylen, fast);

    enum { N = 16, MAX = 320 };
    static uint8_t plain[N][MAX];
    static uint8_t pkt[N][MAX + N2Q_STREAM_OVERHEAD];
    size_t plen[N], pktl[N];
    const uint8_t aad[] = {'R', 'T', 'P', 0, 0, 0}; /* stand-in RTP header, authenticated */

    for (int i = 0; i < N; i++) {
        plen[i] = 40 + (size_t)i * 15; /* growing "frames" */
        for (size_t j = 0; j < plen[i]; j++) plain[i][j] = (uint8_t)(i * 31 + (int)j);
        long r = n2q_stream_seal(&tx, aad, sizeof aad, plain[i], plen[i], pkt[i]);
        pktl[i] = (size_t)r;
    }

    /* deliver reordered, with packet 7 lost */
    int order[] = {0, 1, 3, 2, 5, 4, 6, 8, 9, 11, 10, 13, 12, 15, 14};
    int accepted = 0, mismatch = 0;
    for (size_t k = 0; k < sizeof order / sizeof order[0]; k++) {
        int i = order[k];
        uint8_t out[MAX];
        size_t ol = 0;
        if (n2q_stream_open(&rx, aad, sizeof aad, pkt[i], pktl[i], out, &ol) == N2Q_OK) {
            accepted++;
            if (ol != plen[i] || memcmp(out, plain[i], ol) != 0) mismatch++;
        }
    }
    expect("reorder + loss: all 15 delivered packets accepted", accepted == 15);
    expect("reorder + loss: every plaintext matches", mismatch == 0);

    uint8_t out[MAX];
    size_t ol;

    /* duplicate of an already-accepted packet -> replay */
    expect("duplicate rejected (replay window)",
           n2q_stream_open(&rx, aad, sizeof aad, pkt[3], pktl[3], out, &ol) == N2Q_ERR_REPLAY);

    /* tampered ciphertext -> auth fail (uses the still-missing packet 7) */
    {
        uint8_t bad[MAX + N2Q_STREAM_OVERHEAD];
        memcpy(bad, pkt[7], pktl[7]);
        bad[N2Q_STREAM_SEQ_BYTES + 2] ^= 0x40;
        expect("tampered packet rejected (auth)",
               n2q_stream_open(&rx, aad, sizeof aad, bad, pktl[7], out, &ol) == N2Q_ERR_AUTH);
    }

    /* wrong AAD -> auth fail */
    {
        const uint8_t aad2[] = {'R', 'T', 'P', 9, 9, 9};
        expect("wrong AAD rejected (auth)",
               n2q_stream_open(&rx, aad2, sizeof aad2, pkt[7], pktl[7], out, &ol) == N2Q_ERR_AUTH);
    }

    /* forged sequence header -> nonce mismatch -> auth fail (seq is authenticated) */
    {
        uint8_t forged[MAX + N2Q_STREAM_OVERHEAD];
        memcpy(forged, pkt[9], pktl[9]);
        forged[0] ^= 0xff; /* claim a different sequence number */
        expect("forged sequence header rejected (auth)",
               n2q_stream_open(&rx, aad, sizeof aad, forged, pktl[9], out, &ol) == N2Q_ERR_AUTH);
    }

    /* the genuine late packet 7 (correct AAD) still fills the gap */
    expect("late/lost packet later accepted",
           n2q_stream_open(&rx, aad, sizeof aad, pkt[7], pktl[7], out, &ol) == N2Q_OK &&
               ol == plen[7] && memcmp(out, plain[7], ol) == 0);
}

int main(void) {
    printf("n2q_stream self-test\n");
    run(16, 1, "N2Q-128 Fast");
    run(32, 1, "N2Q-256 Fast");
    run(16, 0, "N2Q-128 Secure");
    printf("%s (%d failures)\n", failc == 0 ? "ALL PASS" : "FAILURES", failc);
    return failc ? 1 : 0;
}
#endif /* N2Q_STREAM_DEMO */
