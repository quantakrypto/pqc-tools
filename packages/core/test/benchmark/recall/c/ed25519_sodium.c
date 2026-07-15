/* ed25519_sodium.c
 *
 * Generate an Ed25519 identity keypair with libsodium. Used to bootstrap a
 * node's long-term signing identity before it joins the gossip mesh.
 */
#include <sodium.h>
#include <stdio.h>

int bootstrap_identity(unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES],
                       unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES])
{
    if (sodium_init() < 0)
        return -1;

    if (crypto_sign_ed25519_keypair(pk, sk) != 0)
        return -1;

    /* Secret key stays resident; lock the page so it is never swapped out. */
    sodium_mlock(sk, crypto_sign_ed25519_SECRETKEYBYTES);
    return 0;
}
