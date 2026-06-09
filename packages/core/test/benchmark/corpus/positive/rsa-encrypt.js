// Positive: RSA public-key encryption (KEM-like confidentiality, HNDL).
// Expected: node-crypto-rsa-encrypt.
const crypto = require("node:crypto");

function sealForRecipient(publicKey, plaintext) {
  return crypto.publicEncrypt(publicKey, Buffer.from(plaintext));
}

module.exports = { sealForRecipient };
