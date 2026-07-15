#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>

/* Legacy OpenSSL verify / raw-decrypt paths + insecure TLS setup.
   Deliberately avoids the EVP_* / *_generate_key / crypto_* call forms so it
   only exercises the new legacy-verify and C-TLS rules. */
void legacy_verify(RSA *rsa, EC_KEY *ec,
                   const unsigned char *dgst, int dlen,
                   const unsigned char *sig, unsigned int slen,
                   const unsigned char *in, unsigned char *out,
                   SSL *ssl) {
    ECDSA_verify(0, dgst, dlen, sig, slen, ec);
    RSA_verify(NID_sha256, dgst, dlen, sig, slen, rsa);
    RSA_public_encrypt(dlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_private_decrypt(dlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);

    SSL_CTX *legacy = SSL_CTX_new(TLSv1_method());
    SSL_CTX *ancient = SSL_CTX_new(SSLv3_method());
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
}
