// Positive: RSA key generation + classical signature via Node `crypto`.
// Expected: node-crypto-keygen (RSA) + node-crypto-sign.
import crypto from "node:crypto";

export function makeRsaKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function signWithRsa(privateKey: string, data: Buffer): Buffer {
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(data);
  return signer.sign(privateKey);
}
