/*
 * n2q_ratchet — forward-secret streaming channel on top of N2Q-C.
 *
 * A symmetric key ratchet (Signal-style chain): every packet is sealed under a
 * fresh one-time message key derived from a chain key, and the chain key is then
 * advanced one-way and the old value erased. Consequence: once the receiver has
 * moved past packet i, packet i's key is unrecoverable — a captured device or
 * seized server cannot decrypt earlier traffic. That is **forward secrecy**.
 *
 *   chain step:   mk_i  = KDF(0x01 | ck_i)      // one-time key for packet i
 *                 ck_i+1 = KDF(0x02 | ck_i)     // advance, then erase ck_i
 *   packet i is sealed with mk_i via the QP SIV core (nonce = i).
 *   Wire packet:  seq(8, LE) | sealed(ct || tag16)      // 24 B overhead
 *
 * Loss / reordering are tolerated up to N2Q_RATCHET_SKIP packets ahead: skipped
 * one-time keys are cached so late-but-recent packets still open, then erased on
 * use. A packet older than the window (or replayed) is dropped. Erasing consumed
 * keys is what makes the channel forward-secret AND replay-proof at once.
 *
 * Research artifact — not externally audited; not for protecting real data yet.
 */
#ifndef N2Q_RATCHET_H
#define N2Q_RATCHET_H

#include <stddef.h>
#include <stdint.h>

#define N2Q_RATCHET_OVERHEAD 24 /* 8-byte seq + 16-byte tag */
#define N2Q_RATCHET_SKIP     64 /* max packets the receiver may skip ahead */

enum {
    N2Q_R_OK      =  0, /* accepted; plaintext written        */
    N2Q_R_AUTH    = -1, /* authentication failed  -> drop     */
    N2Q_R_OLD     = -2, /* older than the window / replay/FS-erased -> drop */
    N2Q_R_SHORT   = -3, /* malformed packet       -> drop     */
    N2Q_R_ARG     = -4
};

/* Sender state: just the current chain key and the next sequence number. */
typedef struct {
    uint8_t  ck[16];
    uint64_t seq;
} n2q_ratchet_tx;

/* Receiver state: chain key for the next expected index, plus a small ring of
 * skipped one-time keys so out-of-order packets within the window still open. */
typedef struct {
    uint8_t  ck[16];       /* chain key for index `next`                 */
    uint64_t next;         /* next index the chain is positioned at      */
    uint8_t  skip_k[N2Q_RATCHET_SKIP][16];
    uint64_t skip_i[N2Q_RATCHET_SKIP];
    uint8_t  skip_used[N2Q_RATCHET_SKIP]; /* 1 = slot holds an unconsumed key */
} n2q_ratchet_rx;

/* Initialise both ends from a shared 16-byte root key (e.g. a handshake output). */
void n2q_ratchet_tx_init(n2q_ratchet_tx *s, const uint8_t root[16]);
void n2q_ratchet_rx_init(n2q_ratchet_rx *s, const uint8_t root[16]);

/* Seal one packet (out needs inlen + N2Q_RATCHET_OVERHEAD bytes). Advances and
 * erases the sender chain. Returns packet length or a negative error. */
long n2q_ratchet_seal(n2q_ratchet_tx *s, const uint8_t *aad, size_t aadlen,
                      const uint8_t *in, size_t inlen, uint8_t *out);

/* Open one received packet. On N2Q_R_OK, *outlen holds the plaintext length and
 * that packet's one-time key is erased (so a replay is dropped and the past
 * stays secret). Any negative code -> drop the packet, stream state unchanged. */
int  n2q_ratchet_open(n2q_ratchet_rx *s, const uint8_t *aad, size_t aadlen,
                      const uint8_t *pkt, size_t pktlen, uint8_t *out, size_t *outlen);

#endif /* N2Q_RATCHET_H */
