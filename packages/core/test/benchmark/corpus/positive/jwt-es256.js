// Positive: JWT verification restricted to ES256 (classical ECDSA signature).
// Expected: jwt-classical-alg (ECDSA).
const jwt = require("jsonwebtoken");

function checkToken(token, key) {
  return jwt.verify(token, key, { algorithms: ["ES256"] });
}

module.exports = { checkToken };
