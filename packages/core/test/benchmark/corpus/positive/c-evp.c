#include <openssl/evp.h>
#include <sodium.h>

/* Modern OpenSSL 3.x uses the EVP interface exclusively; the legacy
   RSA_generate_key / EC_KEY_* forms are deprecated. */
void modern_openssl(EVP_PKEY_CTX *ctx, EVP_PKEY_CTX *dctx, EVP_PKEY_CTX *ectx,
                    unsigned char *secret, size_t *secret_len,
                    unsigned char *out, size_t *out_len,
                    const unsigned char *in, size_t in_len, EVP_MD_CTX *md) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_derive(dctx, secret, secret_len);
    EVP_PKEY_encrypt(ectx, out, out_len, in, in_len);
    EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, pkey);
}

void modern_sodium(void) {
    unsigned char box_pk[32], box_sk[32];
    crypto_box_keypair(box_pk, box_sk);
    unsigned char sig_pk[32], sig_sk[64];
    crypto_sign_keypair(sig_pk, sig_sk);
}
