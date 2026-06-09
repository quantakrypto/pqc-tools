// Positive: node-forge RSA key generation (pure-JS classical RSA).
// Expected: forge-rsa-keygen (RSA).
const forge = require("node-forge");

function generate() {
  return forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
}

module.exports = { generate };
