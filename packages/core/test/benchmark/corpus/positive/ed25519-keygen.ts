// Positive: Ed25519 key pair generation (modern but classical EdDSA).
// Expected: node-crypto-keygen (EdDSA).
import crypto from "node:crypto";

export function makeEd25519KeyPair() {
  return crypto.generateKeyPairSync("ed25519");
}
