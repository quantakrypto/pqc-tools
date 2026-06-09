// Positive: named finite-field DH MODP group via getDiffieHellman (HNDL).
// Expected: node-crypto-dh-modp.
import crypto from "node:crypto";

export function modpGroup() {
  return crypto.getDiffieHellman("modp14");
}
