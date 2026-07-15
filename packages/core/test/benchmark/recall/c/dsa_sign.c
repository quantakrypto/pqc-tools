/* dsa_sign.c
 *
 * Legacy DSA parameter generation, key generation and signing. DSA is rarely
 * provisioned in new systems, but still appears in long-lived firmware update
 * verifiers and older PKCS#12 stores.
 */
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <string.h>

int dsa_sign_blob(const unsigned char *dgst, int dlen,
                  unsigned char *sig, unsigned int *slen)
{
    DSA *dsa = DSA_new();
    if (dsa == NULL)
        return -1;

    if (DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL) != 1)
        goto fail;
    if (DSA_generate_key(dsa) != 1)
        goto fail;

    if (DSA_sign(0, dgst, dlen, sig, slen, dsa) != 1)
        goto fail;

    DSA_free(dsa);
    return 0;

fail:
    DSA_free(dsa);
    return -1;
}
