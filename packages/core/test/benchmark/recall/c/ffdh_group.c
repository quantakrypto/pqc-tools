/* ffdh_group.c
 *
 * Finite-field Diffie-Hellman over the RFC 5114 2048-bit MODP group with a
 * 256-bit subgroup, using the (less common) built-in named-group getter
 * instead of DH_generate_parameters_ex().
 */
#include <openssl/dh.h>
#include <openssl/bn.h>

int ffdh_local_share(unsigned char **pub_out, int *pub_len)
{
    DH *dh = DH_get_2048_256();
    if (dh == NULL)
        return -1;

    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return -1;
    }

    const BIGNUM *pub = NULL;
    DH_get0_key(dh, &pub, NULL);

    *pub_len = BN_num_bytes(pub);
    *pub_out = OPENSSL_malloc(*pub_len);
    if (*pub_out != NULL)
        BN_bn2bin(pub, *pub_out);

    DH_free(dh);
    return *pub_out ? 0 : -1;
}
