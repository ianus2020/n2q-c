/*
 * n2q_log — append-only, tamper-evident encrypted log on top of N2Q-C.
 *
 * Audit trails, supply-chain records and compliance logs need one property above
 * all: you must not be able to alter, reorder or delete past entries without it
 * showing. n2q_log seals each entry and binds it into a hash chain, so a single
 * trusted "head" hash commits to the entire history. Any edit / reorder / drop
 * changes the recomputed head, and any tampered record fails its own auth check.
 *
 *   record_i = seq(8,LE) | SIV_seal(key, nonce=seq, "n2q-log", entry_i)
 *   head_i   = H( head_{i-1} | record_i ),   head_0 = H("n2q-log-genesis")
 *
 * Keep `head` somewhere trusted (or publish it). To audit, replay the records
 * and check the recomputed head equals the trusted one.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_LOG_DEMO n2q_log.c -o n2q_log && ./n2q_log
 * Research artifact — not externally audited; not for protecting real data yet.
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

static const uint8_t LOG_AD[] = "n2q-log";

typedef struct {
    uint8_t  head[32];
    uint64_t seq;
} n2q_log;

void n2q_log_init(n2q_log *L) {
    init_anf();
    hash_128((const uint8_t *)"n2q-log-genesis", 15, L->head, 32, 16);
    L->seq = 0;
}

/* Append one entry. Writes record = seq(8) | sealed to `out`, advances the head.
 * Returns the record length. */
size_t n2q_log_append(n2q_log *L, const uint8_t *key, const uint8_t *entry, size_t elen, uint8_t *out) {
    uint64_t seq = L->seq;
    uint8_t nonce[16] = {0};
    for (int i = 0; i < 8; i++) { out[i] = (uint8_t)(seq >> (8 * i)); nonce[i] = out[i]; }
    size_t sn = seal_128(key, nonce, LOG_AD, sizeof LOG_AD - 1, entry, elen, out + 8, 16);
    size_t rl = 8 + sn;

    uint8_t buf[32 + 8 + 65536];
    if (rl > 65536) return 0;
    memcpy(buf, L->head, 32);
    memcpy(buf + 32, out, rl);
    hash_128(buf, 32 + rl, L->head, 32, 16);
    L->seq++;
    return rl;
}

/* Verify a sequence of records against a trusted head. Returns 1 if the chain is
 * intact and every record authenticates in order; 0 on any tamper/reorder/drop. */
int n2q_log_verify(const uint8_t *key, const uint8_t *const *records, const size_t *rlens,
                   size_t n, const uint8_t expected_head[32]) {
    uint8_t head[32];
    hash_128((const uint8_t *)"n2q-log-genesis", 15, head, 32, 16);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *rec = records[i];
        size_t rl = rlens[i];
        if (rl < 8 + 16) return 0;
        uint64_t seq = 0;
        for (int b = 0; b < 8; b++) seq |= (uint64_t)rec[b] << (8 * b);
        if (seq != i) return 0; /* records must be in order and complete */
        uint8_t nonce[16] = {0};
        memcpy(nonce, rec, 8);
        uint8_t pt[65536]; size_t pl;
        if (!open_128(key, nonce, LOG_AD, sizeof LOG_AD - 1, rec + 8, rl - 8, pt, &pl, 16)) return 0;
        uint8_t buf[32 + 8 + 65536];
        memcpy(buf, head, 32);
        memcpy(buf + 32, rec, rl);
        hash_128(buf, 32 + rl, head, 32, 16);
    }
    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= head[i] ^ expected_head[i];
    return diff == 0;
}

#ifdef N2Q_LOG_DEMO
#include <stdio.h>
#include <stdlib.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    printf("n2q_log self-test (append-only tamper-evident log)\n");
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x33 + i);

    n2q_log L;
    n2q_log_init(&L);
    enum { N = 5 };
    static uint8_t rec[N][256];
    size_t rl[N];
    const char *entries[N] = {"user alice login", "config changed", "shipment #42 scanned",
                              "payment approved", "user bob logout"};
    for (int i = 0; i < N; i++)
        rl[i] = n2q_log_append(&L, key, (const uint8_t *)entries[i], strlen(entries[i]), rec[i]);
    uint8_t head[32];
    memcpy(head, L.head, 32);

    const uint8_t *recs[N]; size_t lens[N];
    for (int i = 0; i < N; i++) { recs[i] = rec[i]; lens[i] = rl[i]; }
    ex("intact log verifies against its head", n2q_log_verify(key, recs, lens, N, head) == 1);

    /* tamper entry #2's ciphertext */
    { uint8_t save = rec[2][12]; rec[2][12] ^= 0x40;
      ex("tampered entry breaks verification", n2q_log_verify(key, recs, lens, N, head) == 0);
      rec[2][12] = save; }

    /* delete entry #3 (present N-1 records) */
    { const uint8_t *r2[N]; size_t l2[N]; int k = 0;
      for (int i = 0; i < N; i++) if (i != 3) { r2[k] = rec[i]; l2[k] = rl[i]; k++; }
      ex("deleting an entry breaks verification", n2q_log_verify(key, r2, l2, N - 1, head) == 0); }

    /* reorder entries #1 and #2 */
    { const uint8_t *r3[N]; size_t l3[N];
      for (int i = 0; i < N; i++) { r3[i] = rec[i]; l3[i] = rl[i]; }
      const uint8_t *tp = r3[1]; r3[1] = r3[2]; r3[2] = tp;
      size_t tl = l3[1]; l3[1] = l3[2]; l3[2] = tl;
      ex("reordering entries breaks verification", n2q_log_verify(key, r3, l3, N, head) == 0); }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
