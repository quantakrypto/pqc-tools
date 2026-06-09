// Negative bait: crypto algorithm names appear ONLY in comments, identifiers,
// and non-algorithm string literals — never in a real crypto call. A lexical
// detector must not flag these. Expected: no findings.
//
// History: this module once used RSA key generation and ECDSA signatures, plus
// a Diffie-Hellman (DH) handshake and createECDH key agreement. It now relies
// entirely on ML-KEM and ML-DSA, so none of that classical crypto remains.

const rsaToken = "user-session-identifier";
const ecdsaLabel = "audit-log-tag";
const dhConfig = { rounds: 3, enabled: true };
const eddsaNote = "see migration ticket QP-128";

export function describe(): string {
  // Mentioning createSign, createVerify, publicEncrypt and generateKeyPair in a
  // comment does not constitute usage.
  return `${rsaToken}/${ecdsaLabel}/${eddsaNote}/${dhConfig.rounds}`;
}
