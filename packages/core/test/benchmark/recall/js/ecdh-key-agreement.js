"use strict";

const { createECDH, createHash, randomBytes } = require("node:crypto");

/**
 * Ephemeral ECDH handshake over NIST P-256 for the device-pairing flow.
 * The raw shared secret is never used directly; we run it through SHA-256
 * to derive the AEAD session key.
 */
function deriveSessionKey(peerPublicKeyHex) {
  const ecdh = createECDH("prime256v1");
  const ourPublicKey = ecdh.generateKeys();

  const shared = ecdh.computeSecret(Buffer.from(peerPublicKeyHex, "hex"));
  const sessionKey = createHash("sha256").update(shared).digest();

  return {
    ourPublicKey: ourPublicKey.toString("hex"),
    sessionKey,
    nonce: randomBytes(12),
  };
}

module.exports = { deriveSessionKey };
