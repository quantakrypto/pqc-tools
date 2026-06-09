// Positive: EC key pair generation. EC keys feed BOTH ECDSA and ECDH, so the
// detector classifies this conservatively as key-exchange (ECDH, HNDL).
// Expected: node-crypto-keygen (ECDH).
import crypto from "node:crypto";

export function makeEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}
