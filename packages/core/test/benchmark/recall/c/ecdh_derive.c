/* ecdh_derive.c
 *
 * Ephemeral ECDH shared-secret derivation. The derive call is reached through
 * a function-pointer dispatch table and the context is built across several
 * statements, so the primitive is not obvious from any single line.
 */
#include <openssl/evp.h>
#include <stddef.h>

typedef int (*kdf_stage)(EVP_PKEY_CTX *, unsigned char *, size_t *);

static int run_derive(EVP_PKEY_CTX *c, unsigned char *out, size_t *outlen)
{
    return EVP_PKEY_derive(c, out, outlen);
}

/* Dispatch table indexed by negotiated suite id. */
static const kdf_stage STAGES[] = {
    run_derive,
};

int compute_shared_secret(EVP_PKEY *my_key, EVP_PKEY *peer_key,
                          unsigned char *secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (ctx == NULL)
        return -1;

    kdf_stage stage = STAGES[0];

    int ok = EVP_PKEY_derive_init(ctx);
    ok = ok > 0 && EVP_PKEY_derive_set_peer(ctx, peer_key) > 0;
    if (ok)
        ok = stage(ctx, secret, secret_len) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}
