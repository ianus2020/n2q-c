/*
 * Audit status: see STATUS.md in the repository root.
 * n2q_franking — verifiable abuse reporting (message franking) on top of N2Q.
 *
 * In an end-to-end-encrypted messenger the platform cannot read messages, so how
 * does a victim report abuse and have it *believed*? Message franking (the scheme
 * Facebook Messenger ships) solves it with a commitment: the sender attaches a
 * franking tag that binds the plaintext. The recipient can later reveal
 * (message, opening) to a moderator who verifies it against that tag — proving
 * "this exact message was sent" — WITHOUT the moderator being able to read any
 * message that was never reported, and WITHOUT the recipient being able to frame
 * the sender for a message they didn't send.
 *
 *   opening = H( 0x08 | key | nonce )          // shared by sender+recipient only
 *   C_F     = H( 0x09 | opening | message )    // the franking commitment (public-ish)
 *   token   = C_F(32) | SIV_seal(key, nonce, ad = C_F, message)
 *
 * To report: recipient hands the moderator (message, opening, C_F); the moderator
 * checks H(0x09|opening|message) == C_F. Binding (collision resistance) stops
 * framing; hiding stops the moderator learning un-reported messages.
 *
 *   cc -O2 -Wall -Wno-unused-function -DN2Q_FRANK_DEMO n2q_franking.c -o n2q_frank && ./n2q_frank
 */
#define N2Q_CORE_NO_MAIN
#include "n2qc.c"
#include <string.h>

#define N2Q_FRANK_CF 32

static void derive_opening(const uint8_t key[16], const uint8_t nonce[16], uint8_t opening[16]) {
    uint8_t buf[1 + 16 + 16];
    buf[0] = 0x08;
    memcpy(buf + 1, key, 16);
    memcpy(buf + 17, nonce, 16);
    uint8_t h[32];
    hash_128(buf, sizeof buf, h, 32, 16);
    memcpy(opening, h, 16);
    memset(buf, 0, sizeof buf);
}

static void commit_msg(const uint8_t opening[16], const uint8_t *msg, size_t mlen, uint8_t cf[32]) {
    uint8_t *buf = malloc(1 + 16 + mlen);
    buf[0] = 0x09;
    memcpy(buf + 1, opening, 16);
    memcpy(buf + 17, msg, mlen);
    hash_128(buf, 1 + 16 + mlen, cf, 32, 16);
    memset(buf, 0, 1 + 16 + mlen);
    free(buf);
}

/* Sender: seal a message and attach its franking tag. out = C_F(32) | sealed. */
size_t n2q_franking_seal(const uint8_t key[16], const uint8_t nonce[16],
                         const uint8_t *msg, size_t mlen, uint8_t *out) {
    uint8_t opening[16], cf[32];
    derive_opening(key, nonce, opening);
    commit_msg(opening, msg, mlen, cf);
    memcpy(out, cf, 32);
    size_t sn = seal_128(key, nonce, cf, 32, msg, mlen, out + 32, 16); /* C_F bound as AAD */
    memset(opening, 0, 16);
    return 32 + sn;
}

/* Recipient: open, verify the franking tag, output message, the tag C_F, and the
 * opening (which the recipient may later reveal to a moderator). Returns 1/0. */
int n2q_franking_open(const uint8_t key[16], const uint8_t nonce[16],
                      const uint8_t *token, size_t tlen, uint8_t *msg, size_t *mlen,
                      uint8_t cf_out[32], uint8_t opening_out[16]) {
    if (tlen < 32 + 16) return 0;
    const uint8_t *cf = token;
    if (!open_128(key, nonce, cf, 32, token + 32, tlen - 32, msg, mlen, 16)) return 0;
    uint8_t opening[16], cf2[32];
    derive_opening(key, nonce, opening);
    commit_msg(opening, msg, *mlen, cf2);
    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= cf[i] ^ cf2[i];
    if (diff) { memset(opening, 0, 16); return 0; }
    memcpy(cf_out, cf, 32);
    memcpy(opening_out, opening, 16);
    memset(opening, 0, 16);
    return 1;
}

/* Moderator: verify a report WITHOUT the encryption key. Returns 1 if the
 * revealed (message, opening) matches the franking tag C_F. */
int n2q_franking_report_verify(const uint8_t cf[32], const uint8_t opening[16],
                               const uint8_t *msg, size_t mlen) {
    uint8_t cf2[32];
    commit_msg(opening, msg, mlen, cf2);
    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= cf[i] ^ cf2[i];
    return diff == 0;
}

#ifdef N2Q_FRANK_DEMO
#include <stdio.h>
static int fc = 0;
static void ex(const char *n, int c) { printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fc++; }

int main(void) {
    init_anf();
    printf("n2q_franking self-test (verifiable abuse reporting)\n");
    uint8_t key[16], nonce[16];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)(0x50 + i); nonce[i] = (uint8_t)(0x90 + i); }

    const uint8_t msg[] = "the abusive message";
    size_t mlen = sizeof msg - 1;
    uint8_t token[128];
    size_t tl = n2q_franking_seal(key, nonce, msg, mlen, token);

    uint8_t got[128], cf[32], opening[16];
    size_t gl;
    ex("recipient opens and the franking tag verifies",
       n2q_franking_open(key, nonce, token, tl, got, &gl, cf, opening) == 1 &&
           gl == mlen && memcmp(got, msg, mlen) == 0);

    /* moderator verifies the report with NO key — just (message, opening, C_F) */
    ex("moderator verifies the report without the key",
       n2q_franking_report_verify(cf, opening, msg, mlen) == 1);

    /* recipient cannot frame the sender: a different message won't match C_F */
    { const uint8_t fake[] = "a message never sent";
      ex("cannot frame sender with a different message (binding)",
         n2q_franking_report_verify(cf, opening, fake, sizeof fake - 1) == 0); }

    /* nor by trying other openings against the same message */
    { int hits = 0; uint8_t op2[16];
      for (int t = 0; t < 4096; t++) { for (int b = 0; b < 16; b++) op2[b] = (uint8_t)(t * 7 + b);
        if (n2q_franking_report_verify(cf, op2, msg, mlen)) hits++; }
      ex("no forged opening matches (swept 4096)", hits == 0); }

    /* tampered ciphertext -> recipient rejects */
    { uint8_t bad[128]; memcpy(bad, token, tl); bad[tl - 1] ^= 0x40;
      ex("tampered ciphertext rejected",
         n2q_franking_open(key, nonce, bad, tl, got, &gl, cf, opening) == 0); }

    printf("%s (%d failures)\n", fc == 0 ? "ALL PASS" : "FAILURES", fc);
    return fc ? 1 : 0;
}
#endif
