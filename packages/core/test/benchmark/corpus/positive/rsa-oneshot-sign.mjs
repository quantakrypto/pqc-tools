// Positive: one-shot crypto.sign(algorithm, data, key) (Node >= 12).
// Expected: node-crypto-sign-oneshot.
import crypto from "node:crypto";

export function signOneShot(privateKey, data) {
  return crypto.sign("sha256", data, privateKey);
}

export function verifyOneShot(publicKey, data, signature) {
  return crypto.verify("sha256", data, publicKey, signature);
}
