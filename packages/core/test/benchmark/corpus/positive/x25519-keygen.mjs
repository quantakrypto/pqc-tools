// Positive: X25519 key pair generation (modern but classical key agreement, HNDL).
// Expected: node-crypto-keygen (X25519).
import crypto from "node:crypto";

export function makeX25519KeyPair() {
  return crypto.generateKeyPairSync("x25519");
}
