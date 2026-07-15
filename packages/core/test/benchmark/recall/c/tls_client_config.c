/* tls_client_config.c
 *
 * Classic (pre-quantum) TLS client hardening: an explicit ECDHE-RSA/ECDSA
 * cipher list, a curve/group preference list, and a floor of TLS 1.2. All of
 * the key-agreement and authentication choices live in configuration strings
 * and setter calls rather than in keygen APIs.
 */
#include <openssl/ssl.h>
#include "pinned_keys.h"

SSL_CTX *build_client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return NULL;

    /* Only classical ECDHE key exchange with RSA/ECDSA auth. */
    SSL_CTX_set_cipher_list(
        ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384");

    /* Offer X25519 first, then the NIST P-256/P-384 groups. */
    SSL_CTX_set1_groups_list(ctx, "X25519:secp256r1:secp384r1");

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    return ctx;
}
