// Negative bait: AES-256-GCM and ChaCha20-Poly1305 symmetric AEAD. Symmetric
// ciphers are not broken by Shor's algorithm. Expected: no findings.
import crypto from "node:crypto";

export function encryptAesGcm(key: Buffer, iv: Buffer, plaintext: Buffer) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function encryptChaCha(key: Buffer, nonce: Buffer, plaintext: Buffer) {
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}
