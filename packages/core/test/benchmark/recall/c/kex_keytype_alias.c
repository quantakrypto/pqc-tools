/* kex_keytype_alias.c
 *
 * Key-exchange keypair provisioning where the concrete algorithm is selected
 * indirectly -- the primary key type comes from a build-time constant and the
 * fallback from a macro -- rather than passed as a literal to
 * EVP_PKEY_CTX_new_id(). Both still resolve to a fixed curve.
 */
#include <openssl/evp.h>
#include <stddef.h>

/* Preferred key-agreement primitive for this build. */
static const int KEX_PRIMARY = EVP_PKEY_X25519;

/* Fallback used on peers that negotiate the larger group. */
#define KEX_FALLBACK EVP_PKEY_X448

static EVP_PKEY *gen_by_type(int key_type)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *provision_kex_key(int use_fallback)
{
    int alg = use_fallback ? KEX_FALLBACK : KEX_PRIMARY;
    return gen_by_type(alg);
}
