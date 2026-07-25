/*
 * n2q_stream — real-time audio/video streaming AEAD on top of N2Q-C.
 *
 * Model: one media packet -> one authenticated datagram. Each packet is sealed
 * under a nonce derived from a monotonically increasing sequence number, so no
 * nonce is ever reused and none has to be re-derived from shared state. The
 * sequence number travels in the packet, so the receiver copes with the packet
 * loss and reordering that are normal on RTP/UDP/WebRTC transports; a sliding
 * replay window rejects duplicates and stale packets. A bad packet is dropped
 * locally and the stream keeps flowing.
 *
 *   Wire packet:  seq(8, little-endian) | sealed( ciphertext || 16-byte tag )
 *   Overhead:     8 (seq) + 16 (tag) = 24 bytes per packet
 *   AAD:          authenticated-but-not-encrypted header (e.g. an RTP header),
 *                 optional; if given at seal it must match at open.
 *
 * Research artifact — not externally audited; not for protecting real data yet.
 */
#ifndef N2Q_STREAM_H
#define N2Q_STREAM_H

#include <stddef.h>
#include <stdint.h>

#define N2Q_STREAM_SEQ_BYTES 8
#define N2Q_STREAM_TAG       16
#define N2Q_STREAM_OVERHEAD  (N2Q_STREAM_SEQ_BYTES + N2Q_STREAM_TAG) /* 24 */
#define N2Q_STREAM_WINDOW    64  /* replay window, in packets */

/* return codes */
enum {
    N2Q_OK         =  0, /* packet accepted; plaintext written  */
    N2Q_ERR_AUTH   = -1, /* authentication failed  -> drop      */
    N2Q_ERR_REPLAY = -2, /* duplicate or too old   -> drop      */
    N2Q_ERR_SHORT  = -3, /* malformed / truncated  -> drop      */
    N2Q_ERR_ARG    = -4  /* bad argument                        */
};

typedef struct {
    uint8_t  key[32];
    int      keylen;      /* 16 -> N2Q-128, 32 -> N2Q-256      */
    int      rounds;      /* 16 = Secure, 8 = Fast             */
    uint64_t send_seq;    /* next sequence number to send      */
    uint64_t recv_max;    /* highest sequence accepted so far  */
    uint64_t recv_win;    /* sliding replay bitmap (bit i = recv_max-i seen) */
    int      recv_started;/* have we accepted any packet yet   */
} n2q_stream;

/*
 * Initialise a stream endpoint. keylen must be 16 (N2Q-128) or 32 (N2Q-256).
 * fast != 0 selects the Fast profile (8 rounds, lower latency); fast == 0
 * selects Secure (16 rounds). The two endpoints of a session must agree.
 * Returns N2Q_OK or N2Q_ERR_ARG.
 */
int n2q_stream_init(n2q_stream *s, const uint8_t *key, int keylen, int fast);

/*
 * Seal one media packet. `out` must have room for inlen + N2Q_STREAM_OVERHEAD
 * bytes. `aad`/`aadlen` (may be NULL/0) is authenticated but not encrypted.
 * Advances the send sequence. Returns the packet length, or a negative error.
 */
long n2q_stream_seal(n2q_stream *s, const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t inlen, uint8_t *out);

/*
 * Open one received packet. `out` must have room for pktlen - N2Q_STREAM_OVERHEAD
 * bytes. On N2Q_OK, *outlen holds the plaintext length. On any negative code the
 * packet must be dropped; the stream state is unchanged and later packets still
 * decrypt. The replay window is only advanced after successful authentication.
 */
int n2q_stream_open(n2q_stream *s, const uint8_t *aad, size_t aadlen,
                    const uint8_t *pkt, size_t pktlen,
                    uint8_t *out, size_t *outlen);

#endif /* N2Q_STREAM_H */
