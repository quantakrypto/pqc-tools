// Negative bait: @noble/hashes (pure hashing library, no asymmetric crypto).
// Distinct from @noble/curves / @noble/secp256k1, which ARE flagged.
// Expected: no findings.
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";

export function fingerprint(data) {
  return sha256(data);
}

export function tag(key, data) {
  return hmac(sha256, key, data);
}
