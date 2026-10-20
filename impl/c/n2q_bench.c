/*
 * n2q_bench — throughput benchmark for the n2q_stream streaming library.
 *
 *   cc -O2 -Wno-unused-function n2q_bench.c -o n2q_bench && ./n2q_bench
 *
 * Measures per-packet seal/open throughput (MB/s of plaintext) and packet rate
 * at a typical 1200-byte media-packet size, for both suites and both profiles.
 * Reference implementation, single core — see the numbers as a floor, not a
 * ceiling.
 *
 * Audit status: see STATUS.md in the repository root.
 */
#include "n2q_stream.c" /* stream layer + QP core (no main: N2Q_STREAM_DEMO off) */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void bench(int keylen, int fast, const char *label, size_t S) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x10 + i);
    const uint8_t aad[12] = {0};

    uint8_t *frame = malloc(S), *pkt = malloc(S + 64), *out = malloc(S + 64);
    for (size_t j = 0; j < S; j++) frame[j] = (uint8_t)j;

    n2q_stream tx;
    n2q_stream_init(&tx, key, keylen, fast);
    for (int i = 0; i < 500; i++) n2q_stream_seal(&tx, aad, 12, frame, S, pkt); /* warm up */

    const long M = 20000;
    double t0 = now();
    for (long i = 0; i < M; i++) n2q_stream_seal(&tx, aad, 12, frame, S, pkt);
    double ts = now() - t0;

    /* pre-seal a batch so the open loop measures pure decrypt+verify cost */
    const long B = 2000, R = 10;
    uint8_t *store = malloc((size_t)B * (S + N2Q_STREAM_OVERHEAD));
    n2q_stream txb;
    n2q_stream_init(&txb, key, keylen, fast);
    for (long i = 0; i < B; i++)
        n2q_stream_seal(&txb, aad, 12, frame, S, store + (size_t)i * (S + N2Q_STREAM_OVERHEAD));

    n2q_stream rx;
    size_t ol;
    double t1 = now();
    for (long r = 0; r < R; r++) {
        n2q_stream_init(&rx, key, keylen, fast);
        for (long i = 0; i < B; i++)
            n2q_stream_open(&rx, aad, 12, store + (size_t)i * (S + N2Q_STREAM_OVERHEAD),
                            S + N2Q_STREAM_OVERHEAD, out, &ol);
    }
    double to = now() - t1;

    double mb = (double)M * S / 1e6, mbo = (double)B * R * S / 1e6;
    printf("%-16s  seal %5.1f MB/s (%4.0fk pkt/s)   open %5.1f MB/s\n", label, mb / ts,
           (double)M / ts / 1000.0, mbo / to);

    free(frame);
    free(pkt);
    free(out);
    free(store);
}

int main(void) {
    printf("n2q_stream throughput -- 1200-byte packets, single core:\n");
    bench(16, 1, "N2Q-128 Fast", 1200);
    bench(32, 1, "N2Q-256 Fast", 1200);
    bench(16, 0, "N2Q-128 Secure", 1200);
    bench(32, 0, "N2Q-256 Secure", 1200);
    return 0;
}
