// Negative bait: SHA-256 hashing and HMAC. Hashes/MACs are not asymmetric and
// not quantum-broken (only mildly weakened by Grover). Expected: no findings.
const crypto = require("node:crypto");

function digest(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function mac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

module.exports = { digest, mac };
