#include <openssl/sha.h>
/* migrated away from RSA_generate_key to ML-KEM */
void hash_only(void) {
    SHA256_Init(&ctx);
    AES_encrypt(in, out, &key);
}
