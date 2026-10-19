/*
 * Audit status: see STATUS.md in the repository root.
 * N2Q-CoNe — Certificate Network: hash-based signatures for an N2Q federation.
 *
 * FireLine (docs/fireline.md) answers "how do two nodes exchange data" — but not
 * "how do I know this trunk key really belongs to that partner". That is the job
 * of a signature, and signatures are normally asymmetric (RSA/ECDSA), which is
 * both foreign to our design and broken by a quantum computer.
 *
 * CoNe takes the other road: **signatures built from a hash function and nothing
 * else** — the WOTS+ / Merkle construction behind XMSS and SLH-DSA. Instantiated
 * on the N2Q hash it gives a certificate system with no number theory and
 * experimental security targets; it is not a standards-compliant signature scheme.
 *
 *   WOTS-style one-time signature: len=67 chains of a 32-byte hash, Winternitz w=16
 *   Merkle  a tree over 2^h one-time keys -> ONE 32-byte public root = the identity
 *   sign    index | WOTS+ signature | authentication path
 *   verify  recompute the WOTS+ public key -> leaf -> walk the path -> compare root
 *
 *   Public key (a node's identity):   32 bytes
 *   Signature (a certificate):      2276 bytes  (67*32 + h*32 + 4)
 *   Capacity per identity key:      2^h certificates (h=4 here -> 16)
 *
 * !! STATEFUL — READ THIS !!  Each leaf index is a ONE-TIME key. Signing two
 * different messages under the same index breaks the scheme (an attacker can
 * forge). A real deployment MUST persist the last used index durably. This
 * low-level demo exposes the index only to demonstrate this hazard. Integrators
 * should use n2q_cone_state.h: durable reservations plus a required external
 * monotonic anchor. A local file alone cannot prevent snapshot rollback.
 *
 * Simplified vs RFC 8391 / FIPS 205: no bitmask/tweakable-hash addressing, so
 * multi-target attack resistance is weaker than the standards. Fine for a
 * reference; a production version needs the full addressing scheme.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_CONE_DEMO n2q_cone.c -o cone && ./cone
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

#define CN_N     32          /* hash output / chain element, bytes         */
#define CN_W     16          /* Winternitz parameter                       */
#define CN_LEN1  64          /* 8*32 / log2(16)                            */
#define CN_LEN2   3          /* checksum digits                            */
#define CN_LEN   (CN_LEN1 + CN_LEN2)   /* 67 chains                        */
#define CN_H      4          /* tree height -> 16 one-time keys            */
#define CN_LEAVES (1 << CN_H)
#define CN_MAX_MESSAGE (1U << 20) /* reference API resource ceiling */
#define CN_SIG   (4 + CN_LEN * CN_N + CN_H * CN_N)   /* 2276 bytes         */

/* Domain-separated hash of three spans without unchecked heap allocation.
 * Streaming absorption preserves H(dom || a || b), including split boundaries. */
static void cn_feed(uint64_t s[5], uint8_t block[8], size_t *used,
                    const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        block[(*used)++] = data[i];
        if (*used == 8) {
            s[0] ^= rd_128(block);
            f_128(s, 16);
            *used = 0;
        }
    }
}
static void cn_h(uint8_t dom, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                 uint8_t out[CN_N]) {
    uint64_t s[5] = {0};
    uint8_t block[8] = {0}; size_t used = 0;
    s[4] ^= DOM_HASH; f_128(s, 16);
    cn_feed(s, block, &used, &dom, 1);
    cn_feed(s, block, &used, a, alen);
    cn_feed(s, block, &used, b, blen);
    memset(block + used, 0, 8 - used);
    block[used] = 1; block[7] |= 0x80;
    s[0] ^= rd_128(block); f_128(s, 16);
    squeeze_128(s, out, CN_N, 16);
    secure_wipe(s, sizeof s); secure_wipe(block, sizeof block);
}

/* secret chain start i of leaf: PRF(seed, leaf, i) — never leaves the signer */
static void cn_sk(const uint8_t seed[CN_N], uint32_t leaf, int i, uint8_t out[CN_N]) {
    uint8_t idx[8] = {(uint8_t)leaf, (uint8_t)(leaf >> 8), (uint8_t)(leaf >> 16),
                      (uint8_t)(leaf >> 24), (uint8_t)i, (uint8_t)(i >> 8), 0, 0};
    cn_h(0x01, seed, CN_N, idx, sizeof idx, out);
}

/* iterate the one-way chain `steps` times */
static void cn_chain(const uint8_t in[CN_N], int steps, uint8_t out[CN_N]) {
    uint8_t t[CN_N];
    memcpy(t, in, CN_N);
    for (int s = 0; s < steps; s++) cn_h(0x02, t, CN_N, NULL, 0, t);
    memcpy(out, t, CN_N);
    secure_wipe(t, CN_N);
}

/* message digest -> 67 base-16 digits (64 message + 3 checksum) */
static void cn_digits(const uint8_t msg[CN_N], uint8_t d[CN_LEN]) {
    for (int i = 0; i < CN_LEN1; i++)
        d[i] = (i % 2 == 0) ? (msg[i / 2] >> 4) : (msg[i / 2] & 0x0f);
    unsigned csum = 0;
    for (int i = 0; i < CN_LEN1; i++) csum += (unsigned)(CN_W - 1 - d[i]);
    d[CN_LEN1 + 0] = (uint8_t)((csum >> 8) & 0x0f);
    d[CN_LEN1 + 1] = (uint8_t)((csum >> 4) & 0x0f);
    d[CN_LEN1 + 2] = (uint8_t)(csum & 0x0f);
}

/* WOTS+ public key of one leaf (67 * 32 bytes) */
static void cn_wots_pk(const uint8_t seed[CN_N], uint32_t leaf, uint8_t pk[CN_LEN][CN_N]) {
    uint8_t sk[CN_N];
    for (int i = 0; i < CN_LEN; i++) {
        cn_sk(seed, leaf, i, sk);
        cn_chain(sk, CN_W - 1, pk[i]);
    }
    secure_wipe(sk, CN_N);
}

/* compress a WOTS+ public key into one leaf node */
static void cn_leaf(const uint8_t pk[CN_LEN][CN_N], uint8_t out[CN_N]) {
    cn_h(0x03, (const uint8_t *)pk, (size_t)CN_LEN * CN_N, NULL, 0, out);
}

/* the Merkle root = this identity's public key */
static void cn_root(const uint8_t seed[CN_N], uint8_t root[CN_N]) {
    uint8_t nodes[CN_LEAVES][CN_N];
    uint8_t pk[CN_LEN][CN_N];
    for (int j = 0; j < CN_LEAVES; j++) {
        cn_wots_pk(seed, (uint32_t)j, pk);
        cn_leaf(pk, nodes[j]);
    }
    int cnt = CN_LEAVES;
    while (cnt > 1) {
        for (int j = 0; j < cnt / 2; j++)
            cn_h(0x04, nodes[2 * j], CN_N, nodes[2 * j + 1], CN_N, nodes[j]);
        cnt /= 2;
    }
    memcpy(root, nodes[0], CN_N);
}

/*
 * Issue a certificate: sign `msg` (any length — it is hashed) with one-time leaf
 * `leaf`. `sig` needs CN_SIG bytes. Returns CN_SIG, or 0 on bad arguments.
 * The SAME leaf must never sign two different messages.
 */
static size_t n2q_cone_sign(const uint8_t seed[CN_N], uint32_t leaf, const uint8_t *msg,
                            size_t mlen, uint8_t *sig, size_t sigcap) {
    if (!seed || !sig || sigcap < CN_SIG || leaf >= CN_LEAVES ||
        mlen > CN_MAX_MESSAGE || (mlen && !msg)) return 0;
    uint8_t d[CN_N], dig[CN_LEN], sk[CN_N];
    cn_h(0x05, msg, mlen, NULL, 0, d);
    cn_digits(d, dig);

    sig[0] = (uint8_t)leaf; sig[1] = (uint8_t)(leaf >> 8);
    sig[2] = (uint8_t)(leaf >> 16); sig[3] = (uint8_t)(leaf >> 24);
    uint8_t *p = sig + 4;
    for (int i = 0; i < CN_LEN; i++) {
        cn_sk(seed, leaf, i, sk);
        cn_chain(sk, dig[i], p + (size_t)i * CN_N); /* reveal only dig[i] steps */
    }
    secure_wipe(sk, CN_N);
    p += (size_t)CN_LEN * CN_N;

    /* authentication path: the sibling at each level */
    uint8_t nodes[CN_LEAVES][CN_N];
    uint8_t pk[CN_LEN][CN_N];
    for (int j = 0; j < CN_LEAVES; j++) {
        cn_wots_pk(seed, (uint32_t)j, pk);
        cn_leaf(pk, nodes[j]);
    }
    int idx = (int)leaf, cnt = CN_LEAVES;
    for (int lvl = 0; lvl < CN_H; lvl++) {
        int sib = idx ^ 1;
        memcpy(p + (size_t)lvl * CN_N, nodes[sib], CN_N);
        for (int j = 0; j < cnt / 2; j++)
            cn_h(0x04, nodes[2 * j], CN_N, nodes[2 * j + 1], CN_N, nodes[j]);
        cnt /= 2;
        idx /= 2;
    }
    return CN_SIG;
}

/* Verify a certificate against an identity root. Returns 1 on success. */
static int n2q_cone_verify(const uint8_t root[CN_N], const uint8_t *msg, size_t mlen,
                           const uint8_t *sig, size_t slen) {
    if (!root || !sig || slen != CN_SIG || mlen > CN_MAX_MESSAGE || (mlen && !msg)) return 0;
    uint32_t leaf = (uint32_t)sig[0] | ((uint32_t)sig[1] << 8) | ((uint32_t)sig[2] << 16) |
                    ((uint32_t)sig[3] << 24);
    if (leaf >= CN_LEAVES) return 0;

    uint8_t d[CN_N], dig[CN_LEN];
    cn_h(0x05, msg, mlen, NULL, 0, d);
    cn_digits(d, dig);

    /* finish each chain to recover the WOTS+ public key */
    uint8_t pk[CN_LEN][CN_N]; /* private per verification: concurrent calls are independent */
    const uint8_t *p = sig + 4;
    for (int i = 0; i < CN_LEN; i++)
        cn_chain(p + (size_t)i * CN_N, CN_W - 1 - dig[i], pk[i]);
    p += (size_t)CN_LEN * CN_N;

    uint8_t node[CN_N];
    cn_leaf(pk, node);
    int idx = (int)leaf;
    for (int lvl = 0; lvl < CN_H; lvl++) {
        const uint8_t *sib = p + (size_t)lvl * CN_N;
        if (idx & 1) cn_h(0x04, sib, CN_N, node, CN_N, node);
        else         cn_h(0x04, node, CN_N, sib, CN_N, node);
        idx /= 2;
    }
    int diff = 0;
    for (int i = 0; i < CN_N; i++) diff |= node[i] ^ root[i];
    return diff == 0;
}

/* -------------------------------------------------------------------------- */
#ifdef N2Q_CONE_DEMO
#include <stdio.h>

static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    init_anf();
    printf("N2Q-CoNe self-test (hash-based certificates)\n");

    /* the federation authority's identity: a seed (secret) and a root (public) */
    uint8_t seed[CN_N], root[CN_N];
    for (int i = 0; i < CN_N; i++) seed[i] = (uint8_t)(0xC0 + i);
    cn_root(seed, root);
    printf("  identity public key (Merkle root): %02x%02x%02x%02x…  (%d bytes)\n", root[0], root[1],
           root[2], root[3], CN_N);
    printf("  certificate size: %d bytes, capacity: %d one-time certificates\n", CN_SIG, CN_LEAVES);

    /* certify a partner: "this trunk-key fingerprint belongs to bank-b" */
    const uint8_t cert1[] = "bank-b : trunk fingerprint 9f3a…c17";
    const uint8_t cert2[] = "corp-c : trunk fingerprint 41de…8b0";
    static uint8_t sig1[CN_SIG], sig2[CN_SIG];

    ex("issue certificate for bank-b (leaf 0)",
       n2q_cone_sign(seed, 0, cert1, sizeof cert1 - 1, sig1, sizeof sig1) == CN_SIG);
    ex("verify with the public root only",
       n2q_cone_verify(root, cert1, sizeof cert1 - 1, sig1, CN_SIG) == 1);

    ex("issue certificate for corp-c (leaf 1)",
       n2q_cone_sign(seed, 1, cert2, sizeof cert2 - 1, sig2, sizeof sig2) == CN_SIG);
    ex("verify the second certificate",
       n2q_cone_verify(root, cert2, sizeof cert2 - 1, sig2, CN_SIG) == 1);

    /* a substituted fingerprint (MITM) does not verify */
    { const uint8_t fake[] = "bank-b : trunk fingerprint 0000…000";
      ex("substituted fingerprint rejected (anti-MITM)",
         n2q_cone_verify(root, fake, sizeof fake - 1, sig1, CN_SIG) == 0); }

    /* tampered signature */
    { static uint8_t bad[CN_SIG]; memcpy(bad, sig1, CN_SIG); bad[100] ^= 0x40;
      ex("tampered certificate rejected",
         n2q_cone_verify(root, cert1, sizeof cert1 - 1, bad, CN_SIG) == 0); }

    /* a certificate does not verify under a different authority */
    { uint8_t seed2[CN_N], root2[CN_N];
      for (int i = 0; i < CN_N; i++) seed2[i] = (uint8_t)(0x11 * i + 3);
      cn_root(seed2, root2);
      ex("certificate rejected under a different authority",
         n2q_cone_verify(root2, cert1, sizeof cert1 - 1, sig1, CN_SIG) == 0); }

    /* mixing the two certificates fails (each is bound to its own leaf+message) */
    ex("certificate of bank-b does not certify corp-c",
       n2q_cone_verify(root, cert2, sizeof cert2 - 1, sig1, CN_SIG) == 0);

    /* the stateful hazard, shown explicitly: reusing a leaf reveals extra chain
       links, which is exactly what an attacker needs — never do this. */
    {
        const uint8_t other[] = "bank-b : trunk fingerprint DIFFERENT";
        static uint8_t reuse[CN_SIG];
        n2q_cone_sign(seed, 0, other, sizeof other - 1, reuse, sizeof reuse); /* leaf 0 AGAIN */
        int both_valid = n2q_cone_verify(root, cert1, sizeof cert1 - 1, sig1, CN_SIG) &&
                         n2q_cone_verify(root, other, sizeof other - 1, reuse, CN_SIG);
        int differs = memcmp(sig1 + 4, reuse + 4, CN_LEN * CN_N) != 0;
        ex("leaf reuse produces two valid signatures from ONE one-time key (hazard shown)",
           both_valid && differs);
        printf("       ^ this is why the signer MUST persist the last used index\n");
    }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
