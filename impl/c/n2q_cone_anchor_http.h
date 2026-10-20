#ifndef N2Q_CONE_ANCHOR_HTTP_H
#define N2Q_CONE_ANCHOR_HTTP_H
#include "n2q_cone_state.h"
/* libcurl HTTPS/mTLS provider. URL must include /v1/reserve. The service's
 * durable database MUST be outside the signer's rollback domain. A local
 * stand cannot prove this deployment property. No redirects or retry on
 * uncertainty; caller's reservation stays burned. PEM key file: owner-only. */
typedef struct {
    const char *url, *ca_file, *certificate_file, *private_key_file;
    long connect_timeout_ms, total_timeout_ms; /* 1..30000, total >= connect */
} n2q_cone_http_anchor;
int n2q_cone_anchor_https(void *context, const uint8_t key_id[32], uint32_t index);
#endif
