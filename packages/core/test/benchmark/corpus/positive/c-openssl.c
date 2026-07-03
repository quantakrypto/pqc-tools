#include <openssl/rsa.h>
#include <openssl/ec.h>

void keys(void) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    ECDSA_sign(0, dgst, dlen, sig, &siglen, ec);
    DH_generate_key(dhp);
}
