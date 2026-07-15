"use strict";

const { getDiffieHellman, createDiffieHellman } = require("node:crypto");

/**
 * Classic finite-field Diffie-Hellman using the well-known RFC 3526
 * 2048-bit MODP group ("modp14"). Both peers share the group parameters.
 */
function agreeWithNamedGroup(peerPublicKeyHex) {
  const dh = getDiffieHellman("modp14");
  dh.generateKeys();

  const shared = dh.computeSecret(Buffer.from(peerPublicKeyHex, "hex"));
  return {
    publicKey: dh.getPublicKey("hex"),
    sharedSecret: shared.toString("hex"),
  };
}

/**
 * Legacy peers that cannot agree on a named group get freshly generated
 * 2048-bit parameters instead.
 */
function agreeWithGeneratedParams() {
  const dh = createDiffieHellman(2048);
  dh.generateKeys();
  return {
    prime: dh.getPrime("hex"),
    generator: dh.getGenerator("hex"),
    publicKey: dh.getPublicKey("hex"),
  };
}

module.exports = { agreeWithNamedGroup, agreeWithGeneratedParams };
