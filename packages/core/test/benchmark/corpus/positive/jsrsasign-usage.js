// Positive: jsrsasign key generation + signature.
// Expected: jsrsasign-keygen + jsrsasign-sign.
const { KEYUTIL, KJUR } = require("jsrsasign");

function makeAndSign(data) {
  const kp = KEYUTIL.generateKeypair("RSA", 2048);
  const sig = new KJUR.crypto.Signature({ alg: "SHA256withRSA" });
  sig.init(kp.prvKeyObj);
  sig.updateString(data);
  return sig.sign();
}

module.exports = { makeAndSign };
