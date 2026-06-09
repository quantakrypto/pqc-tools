// Positive: JOSE ECDH-ES key agreement for JWE (key exchange, HNDL).
// Expected: jose-ecdh-es (ECDH).
import { CompactEncrypt } from "jose";

export async function encryptForRecipient(plaintext: Uint8Array, key: CryptoKey): Promise<string> {
  return new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256GCM" })
    .encrypt(key);
}
