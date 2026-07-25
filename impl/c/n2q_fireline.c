/*
 * Audit status: see STATUS.md in the repository root.
 * N2Q-FireLine — federation between independent N2Q encryption nodes.
 *
 * The problem: every organisation runs its own node with its own master keys,
 * and nobody will hand those keys to a partner. FireLine lets two (or many)
 * nodes exchange data so that **no master key ever leaves its node** — only a
 * wrap of a single-use data key travels on the wire.
 *
 * Model (architecture A of docs/federation.md): each pair of partners shares one
 * long-term *trunk key*, established once out of band (QR code, paper, courier).
 * Every parcel then carries a fresh data key, wrapped once per recipient:
 *
 *   parcel = "N2QL" | ver | suite | le16(n)
 *            { rcpt_id(8) | wrap(trunk_i, DEK)(32) } * n        <- header
 *            nonce(16) | le32(len) | sealed(DEK, hdrhash|ad, payload)
 *
 *   wrap AD    = "n2q-fireline-v1" | rcpt_id     <- binds a wrap to ONE recipient
 *   payload AD = H(0x0a | header) | caller AD    <- binds the payload to the header
 *
 * Consequences, all exercised by the self-test below:
 *   - the bulk payload is encrypted ONCE, no matter how many recipients;
 *   - a recipient can only use the wrap addressed to it (rcpt_id is bound in);
 *   - an outsider holding the parcel learns nothing;
 *   - editing any recipient block breaks the payload (header is bound in);
 *   - revocation = issue the next parcel with a fresh DEK and no wrap for them;
 *   - trunk keys never appear in the parcel bytes.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_FIRELINE_DEMO n2q_fireline.c -o fl && ./fl
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

#define N2Q_FL_RID   8  /* public routing label of a recipient */
#define N2Q_FL_WRAP 32  /* SIV wrap of a 16-byte DEK: 16 tag + 16 ct */
#define N2Q_FL_MAXR 32  /* recipients per parcel (reference limit) */

enum { N2Q_FL_OK = 0, N2Q_FL_FORMAT = -1, N2Q_FL_NOT_FOR_ME = -2,
       N2Q_FL_AUTH = -3, N2Q_FL_ARG = -4 };

typedef struct {
    uint8_t id[N2Q_FL_RID]; /* routing label, public */
    uint8_t trunk[16];      /* pairwise long-term key, never transmitted */
} n2q_fl_peer;

static const uint8_t FL_AD[] = "n2q-fireline-v1";
static const uint8_t FL_ZERO[16] = {0};

/* wrap the data key for one recipient; AD binds the wrap to that recipient */
static void fl_wrap(const uint8_t trunk[16], const uint8_t rid[N2Q_FL_RID],
                    const uint8_t dek[16], uint8_t out[N2Q_FL_WRAP]) {
    uint8_t ad[sizeof FL_AD - 1 + N2Q_FL_RID];
    memcpy(ad, FL_AD, sizeof FL_AD - 1);
    memcpy(ad + sizeof FL_AD - 1, rid, N2Q_FL_RID);
    seal_128(trunk, FL_ZERO, ad, sizeof ad, dek, 16, out, 16);
}
static int fl_unwrap(const uint8_t trunk[16], const uint8_t rid[N2Q_FL_RID],
                     const uint8_t wrap[N2Q_FL_WRAP], uint8_t dek[16]) {
    uint8_t ad[sizeof FL_AD - 1 + N2Q_FL_RID];
    memcpy(ad, FL_AD, sizeof FL_AD - 1);
    memcpy(ad + sizeof FL_AD - 1, rid, N2Q_FL_RID);
    size_t dl;
    return open_128(trunk, FL_ZERO, ad, sizeof ad, wrap, N2Q_FL_WRAP, dek, &dl, 16) && dl == 16;
}

static size_t fl_header_len(size_t n) { return 4 + 1 + 1 + 2 + n * (N2Q_FL_RID + N2Q_FL_WRAP); }

/* payload AD = H(0x0a | header) | caller AD */
static size_t fl_payload_ad(const uint8_t *hdr, size_t hlen, const uint8_t *ad, size_t adlen,
                            uint8_t *out) {
    uint8_t *buf = malloc(1 + hlen);
    buf[0] = 0x0a;
    memcpy(buf + 1, hdr, hlen);
    hash_128(buf, 1 + hlen, out, 32, 16);
    free(buf);
    if (adlen) memcpy(out + 32, ad, adlen);
    return 32 + adlen;
}

/*
 * Build a parcel. The caller supplies the one-time `dek` and `nonce` (in
 * production: from a CSPRNG; here they are parameters so the test is
 * reproducible). `out` needs fl_header_len(n) + 16 + 4 + ptlen + 16 bytes.
 * Returns the parcel length, or 0 on bad arguments.
 */
static size_t n2q_fireline_seal(const n2q_fl_peer *rcpts, size_t n, const uint8_t dek[16],
                                const uint8_t nonce[16], const uint8_t *ad, size_t adlen,
                                const uint8_t *pt, size_t ptlen, uint8_t *out, int fast) {
    if (!rcpts || n == 0 || n > N2Q_FL_MAXR || !out) return 0;
    uint8_t suite = 0x01 | (fast ? 0x20 : 0);
    size_t p = 0;
    memcpy(out, "N2QL", 4);
    p = 4;
    out[p++] = 1;
    out[p++] = suite;
    out[p++] = (uint8_t)(n & 0xff);
    out[p++] = (uint8_t)(n >> 8);
    for (size_t i = 0; i < n; i++) {
        memcpy(out + p, rcpts[i].id, N2Q_FL_RID);
        p += N2Q_FL_RID;
        fl_wrap(rcpts[i].trunk, rcpts[i].id, dek, out + p);
        p += N2Q_FL_WRAP;
    }
    size_t hlen = p; /* header is everything up to here */

    uint8_t *pad = malloc(32 + adlen);
    size_t padlen = fl_payload_ad(out, hlen, ad, adlen, pad);

    memcpy(out + p, nonce, 16);
    p += 16;
    uint8_t *lenp = out + p;
    p += 4;
    size_t sn = seal_128(dek, nonce, pad, padlen, pt, ptlen, out + p, fast ? 8 : 16);
    lenp[0] = (uint8_t)(sn & 0xff);
    lenp[1] = (uint8_t)((sn >> 8) & 0xff);
    lenp[2] = (uint8_t)((sn >> 16) & 0xff);
    lenp[3] = (uint8_t)((sn >> 24) & 0xff);
    p += sn;
    free(pad);
    return p;
}

/*
 * Open a parcel addressed to `me`. Returns N2Q_FL_OK and writes the payload, or
 * a negative code (the parcel must then be discarded).
 */
static int n2q_fireline_open(const n2q_fl_peer *me, const uint8_t *parcel, size_t plen,
                             const uint8_t *ad, size_t adlen, uint8_t *out, size_t *outlen) {
    if (!me || !parcel || plen < 8) return N2Q_FL_ARG;
    if (memcmp(parcel, "N2QL", 4) != 0 || parcel[4] != 1) return N2Q_FL_FORMAT;
    if ((parcel[5] & 0x0f) != 0x01) return N2Q_FL_FORMAT;
    int r = (parcel[5] & 0x20) ? 8 : 16;
    size_t n = (size_t)parcel[6] | ((size_t)parcel[7] << 8);
    if (n == 0 || n > N2Q_FL_MAXR) return N2Q_FL_FORMAT;
    size_t hlen = fl_header_len(n);
    if (plen < hlen + 16 + 4) return N2Q_FL_FORMAT;

    /* find our block and unwrap the data key */
    uint8_t dek[16];
    int found = 0;
    for (size_t i = 0; i < n && !found; i++) {
        const uint8_t *blk = parcel + 8 + i * (N2Q_FL_RID + N2Q_FL_WRAP);
        if (memcmp(blk, me->id, N2Q_FL_RID) != 0) continue;
        found = fl_unwrap(me->trunk, blk, blk + N2Q_FL_RID, dek);
        if (!found) return N2Q_FL_AUTH; /* our block, but it does not authenticate */
    }
    if (!found) return N2Q_FL_NOT_FOR_ME;

    const uint8_t *nonce = parcel + hlen;
    const uint8_t *lenp = nonce + 16;
    size_t sn = (size_t)lenp[0] | ((size_t)lenp[1] << 8) | ((size_t)lenp[2] << 16) |
                ((size_t)lenp[3] << 24);
    if (hlen + 16 + 4 + sn > plen) return N2Q_FL_FORMAT;

    uint8_t *pad = malloc(32 + adlen);
    size_t padlen = fl_payload_ad(parcel, hlen, ad, adlen, pad);
    int ok = open_128(dek, nonce, pad, padlen, lenp + 4, sn, out, outlen, r);
    free(pad);
    memset(dek, 0, 16);
    return ok ? N2Q_FL_OK : N2Q_FL_AUTH;
}

/* -------------------------------------------------------------------------- */
#ifdef N2Q_FIRELINE_DEMO
#include <stdio.h>

static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

static void mkpeer(n2q_fl_peer *p, const char *name, uint8_t seed) {
    memset(p->id, 0, N2Q_FL_RID);
    memcpy(p->id, name, strlen(name) < N2Q_FL_RID ? strlen(name) : N2Q_FL_RID);
    for (int i = 0; i < 16; i++) p->trunk[i] = (uint8_t)(seed + i * 7);
}

int main(void) {
    init_anf();
    printf("N2Q-FireLine self-test (federation of independent nodes)\n");

    /* node A holds one trunk key per partner; partners hold their own copy */
    n2q_fl_peer B, C, D;
    mkpeer(&B, "bank-b", 0x11);
    mkpeer(&C, "corp-c", 0x55);
    mkpeer(&D, "other-d", 0x99); /* never a recipient */

    n2q_fl_peer rcpts[2] = {B, C};
    uint8_t dek[16], nonce[16];
    for (int i = 0; i < 16; i++) { dek[i] = (uint8_t)(0xA0 + i); nonce[i] = (uint8_t)(0x30 + i); }

    const uint8_t msg[] = "quarterly settlement report";
    size_t mlen = sizeof msg - 1;
    static uint8_t parcel[1024], out[1024];
    size_t olen;
    size_t plen = n2q_fireline_seal(rcpts, 2, dek, nonce, (const uint8_t *)"ctx", 3, msg, mlen,
                                    parcel, 1);

    printf("  parcel: %zu bytes for 2 recipients (payload %zu, overhead %zu)\n", plen, mlen,
           plen - mlen);

    ex("recipient B reads the payload",
       n2q_fireline_open(&B, parcel, plen, (const uint8_t *)"ctx", 3, out, &olen) == N2Q_FL_OK &&
           olen == mlen && memcmp(out, msg, mlen) == 0);
    ex("recipient C reads the same parcel",
       n2q_fireline_open(&C, parcel, plen, (const uint8_t *)"ctx", 3, out, &olen) == N2Q_FL_OK &&
           memcmp(out, msg, mlen) == 0);
    ex("outsider D cannot read it",
       n2q_fireline_open(&D, parcel, plen, (const uint8_t *)"ctx", 3, out, &olen) == N2Q_FL_NOT_FOR_ME);

    /* B tries to use C's wrap by relabelling it with its own id */
    {
        static uint8_t forged[1024];
        memcpy(forged, parcel, plen);
        uint8_t *blkB = forged + 8;                                 /* B's block */
        uint8_t *blkC = forged + 8 + (N2Q_FL_RID + N2Q_FL_WRAP);    /* C's block */
        memcpy(blkB + N2Q_FL_RID, blkC + N2Q_FL_RID, N2Q_FL_WRAP);  /* steal C's wrap */
        ex("a recipient cannot use another recipient's wrap",
           n2q_fireline_open(&B, forged, plen, (const uint8_t *)"ctx", 3, out, &olen) != N2Q_FL_OK);
    }

    /* editing the header (e.g. deleting a recipient's wrap bytes) breaks the payload */
    {
        static uint8_t edited[1024];
        memcpy(edited, parcel, plen);
        edited[8 + N2Q_FL_RID + N2Q_FL_WRAP + 3] ^= 0x40; /* touch C's block */
        ex("editing the header invalidates the parcel for B",
           n2q_fireline_open(&B, edited, plen, (const uint8_t *)"ctx", 3, out, &olen) == N2Q_FL_AUTH);
    }

    /* tampered payload */
    {
        static uint8_t bad[1024];
        memcpy(bad, parcel, plen);
        bad[plen - 1] ^= 0x40;
        ex("tampered payload rejected",
           n2q_fireline_open(&B, bad, plen, (const uint8_t *)"ctx", 3, out, &olen) == N2Q_FL_AUTH);
    }

    /* wrong context (AAD) */
    ex("wrong context rejected",
       n2q_fireline_open(&B, parcel, plen, (const uint8_t *)"other", 5, out, &olen) == N2Q_FL_AUTH);

    /* revocation: next parcel goes to B only, with a fresh data key */
    {
        uint8_t dek2[16];
        for (int i = 0; i < 16; i++) dek2[i] = (uint8_t)(0x5A ^ (i * 3));
        static uint8_t p2[1024];
        n2q_fl_peer only_b[1] = {B};
        size_t l2 = n2q_fireline_seal(only_b, 1, dek2, nonce, NULL, 0,
                                      (const uint8_t *)"after revocation", 16, p2, 1);
        ex("after revocation B still reads",
           n2q_fireline_open(&B, p2, l2, NULL, 0, out, &olen) == N2Q_FL_OK);
        ex("after revocation C is locked out",
           n2q_fireline_open(&C, p2, l2, NULL, 0, out, &olen) == N2Q_FL_NOT_FOR_ME);
    }

    /* THE headline property: no trunk key appears anywhere in the parcel */
    {
        int leak = 0;
        for (size_t i = 0; i + 16 <= plen; i++) {
            if (memcmp(parcel + i, B.trunk, 16) == 0) leak = 1;
            if (memcmp(parcel + i, C.trunk, 16) == 0) leak = 1;
            if (memcmp(parcel + i, dek, 16) == 0) leak = 1; /* nor the raw data key */
        }
        ex("NO master/trunk key (nor the raw data key) appears in the parcel", !leak);
    }

    /* emit the parcel so the native ports can cross-check against this reference */
    {
        FILE *f = fopen("/tmp/fireline_parcel.bin", "wb");
        if (f) {
            fwrite(parcel, 1, plen, f);
            fclose(f);
            printf("  wrote /tmp/fireline_parcel.bin (%zu bytes) for the cross-check\n", plen);
        }
    }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
