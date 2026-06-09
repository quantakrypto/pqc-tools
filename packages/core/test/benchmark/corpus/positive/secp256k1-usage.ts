// Positive: direct @noble/secp256k1 ECDSA signing (blockchain keys).
// Expected: secp256k1-usage (ECDSA).
import * as secp from "@noble/secp256k1";

export function signHash(messageHash: Uint8Array, privateKey: Uint8Array) {
  return secp.sign(messageHash, privateKey);
}
