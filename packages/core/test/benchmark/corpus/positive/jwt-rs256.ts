// Positive: JWT signed with RS256 (classical RSA signature).
// The `jwt.sign(...)` call does NOT trigger the one-shot rule (dotted call), so
// the only finding is the algorithm string.
// Expected: jwt-classical-alg (RSA).
import jwt from "jsonwebtoken";

export function issueToken(payload: object, key: string): string {
  return jwt.sign(payload, key, { algorithm: "RS256", expiresIn: "1h" });
}
