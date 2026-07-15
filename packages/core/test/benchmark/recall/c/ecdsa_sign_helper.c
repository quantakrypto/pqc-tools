/* ecdsa_sign_helper.c
 *
 * Detached ECDSA signature helper. The caller owns the EC_KEY (typically a
 * P-256 key loaded from a hardware token), so no curve appears here -- the
 * signing primitive alone determines the algorithm family.
 */
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <string.h>

int ecdsa_sign_digest(EC_KEY *key,
                      const unsigned char *digest, int digest_len,
                      unsigned char *sig, unsigned int *sig_len)
{
    if (key == NULL || digest == NULL)
        return -1;

    /* type is ignored for ECDSA_sign(); pass 0 per the man page. */
    if (ECDSA_sign(0, digest, digest_len, sig, sig_len, key) != 1) {
        memset(sig, 0, *sig_len);
        return -1;
    }
    return 0;
}
