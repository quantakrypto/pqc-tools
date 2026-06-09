// Positive: finite-field Diffie-Hellman key exchange (HNDL exposed).
// Expected: node-crypto-dh.
const crypto = require("node:crypto");

function newDhParams() {
  const dh = crypto.createDiffieHellman(2048);
  dh.generateKeys();
  return dh;
}

module.exports = { newDhParams };
