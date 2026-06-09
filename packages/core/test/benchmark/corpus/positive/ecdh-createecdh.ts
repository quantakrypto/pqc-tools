// Positive: elliptic-curve Diffie-Hellman key exchange (HNDL exposed).
// Expected: node-crypto-ecdh.
import crypto from "node:crypto";

export function deriveSharedSecret(theirPublicKey: Buffer): Buffer {
  const alice = crypto.createECDH("prime256v1");
  alice.generateKeys();
  return alice.computeSecret(theirPublicKey);
}
