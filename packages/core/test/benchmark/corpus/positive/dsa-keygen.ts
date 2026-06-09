// Positive: DSA key pair generation (classical signature scheme).
// Expected: node-crypto-keygen (DSA).
import crypto from "node:crypto";

export function makeDsaKeyPair() {
  return crypto.generateKeyPairSync("dsa", { modulusLength: 2048 });
}
