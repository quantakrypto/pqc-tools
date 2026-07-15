/* rsa_evp_keygen.c
 *
 * Provision a fresh RSA-3072 signing key using the OpenSSL 3.x EVP
 * high-level interface. This is the recommended modern form; the legacy
 * RSA_generate_key_ex() path is deprecated in 3.0.
 */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stddef.h>

EVP_PKEY *provision_signing_key(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto done;

    /* 3072-bit modulus ~= 128-bit classical security. */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0)
        goto done;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        pkey = NULL;

done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
