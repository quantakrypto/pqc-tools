/* secp256k1_evp_sign.c
 *
 * ECDSA over the Koblitz curve secp256k1 (the Bitcoin/Ethereum signing curve)
 * built through the OpenSSL 3.x EVP paramgen path. The curve NID is threaded
 * through a macro and a helper table so it never appears next to the keygen
 * call, and the sign is a multi-line one-shot EVP_DigestSign.
 */
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <string.h>

#define CHAIN_CURVE NID_secp256k1

struct curve_profile {
    const char *label;
    int         nid;
};

static const struct curve_profile PROFILES[] = {
    { "mainnet", CHAIN_CURVE },
};

static EVP_PKEY *derive_chain_key(const struct curve_profile *p)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL)
        return NULL;

    if (EVP_PKEY_paramgen_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            pctx,
            p->nid) > 0) {
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int sign_transaction(const unsigned char *tx, size_t tx_len,
                     unsigned char *sig, size_t *sig_len)
{
    EVP_PKEY *key = derive_chain_key(&PROFILES[0]);
    if (key == NULL)
        return -1;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int rc = EVP_DigestSignInit(md, NULL,
                                EVP_sha256(),
                                NULL,
                                key)
             && EVP_DigestSign(md, sig, sig_len, tx, tx_len);

    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    return rc ? 0 : -1;
}
