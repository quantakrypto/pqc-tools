/**
 * Source detector for classical asymmetric cryptography in smart-contract /
 * blockchain source languages: Solidity (`.sol`), Move (`.move`), and Cairo
 * (`.cairo`). On-chain signature verification is pure classical elliptic-curve
 * cryptography — secp256k1 ECDSA on the EVM, Ed25519 / secp256k1 on Sui & Aptos
 * (Move), and STARK-curve ECDSA on Starknet (Cairo). A cryptographically-relevant
 * quantum computer (CRQC) could forge any of these on-chain authorizations.
 *
 * HNDL: unlike a KEM or key-agreement finding, an on-chain signature check has no
 * confidentiality to harvest — there is nothing to decrypt later — so every rule
 * here is `hndl: false`. The exposure is nonetheless SEVERE: on-chain keys often
 * ARE the custody of the asset (an account's authorization to move funds), so a
 * forged signature is a direct loss, not a downgraded confidentiality guarantee.
 * That is why the findings are `severity: high` despite `hndl: false`.
 *
 * There is no `secp256k1` value in {@link AlgorithmFamily}; secp256k1 usage is
 * mapped to `ECDSA` (the scheme), and the specific curve is named in the message.
 * The STARK-curve check is likewise `ECDSA` (ECDSA over the STARK-friendly curve).
 *
 * Patterns (verified against OpenZeppelin, Solady, Sui/Aptos Move, Starknet docs):
 *  - Solidity / EVM (secp256k1 ECDSA → `sol-ecrecover`):
 *      `ecrecover(` (the secp256k1 precompile), OpenZeppelin/Solady
 *      `ECDSA.recover(` / `ECDSA.tryRecover(`,
 *      `SignatureChecker.isValidSignatureNow(`, and imports of the
 *      `.../cryptography/ECDSA.sol` / `SignatureChecker.sol` (OZ) or Solady
 *      `utils/ECDSA.sol` libraries. Consolidated under one rule; each distinct
 *      token/import is its own finding (evidence), but they cannot double-fire on
 *      the same span.
 *  - Move / Sui & Aptos:
 *      `ed25519::signature_verify_strict(` / `ed25519_verify(` → EdDSA
 *      (`sol-ed25519`); `ecdsa_k1::secp256k1_verify(` /
 *      `ecdsa_k1::secp256k1_ecrecover(` → ECDSA secp256k1
 *      (`sol-secp256k1-verify`).
 *  - Cairo / Starknet:
 *      `check_ecdsa_signature(` (also the `ecdsa::check_ecdsa_signature(`
 *      qualified form) → ECDSA over the STARK curve (`cairo-ecdsa`).
 *
 * Comment suppression is done in-detector (Solidity/Move/Cairo all use C-style
 * `//` line comments and `/* … *\/` block comments), so a commented-out
 * verification call cannot fire. Offsets are preserved by the maskers, so finding
 * line/column stay exact.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
  SMART_CONTRACT_EXTENSIONS,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// Shared remediation: no PQC on-chain signature scheme is standardized on these
// chains yet, so the actionable step today is to inventory the exposure and track
// each chain's roadmap for an alternative (quantum-safe) signature scheme.
const REMEDIATION_ONCHAIN =
  "No PQC on-chain signature scheme is standardized on these chains yet; inventory this on-chain " +
  "signature verification now and track chain roadmaps (e.g. account abstraction enabling " +
  "alternative signature schemes) for a quantum-safe migration path.";

// --- Solidity / EVM: secp256k1 ECDSA. ---
// The secp256k1 recovery precompile. `\b` before `ecrecover` keeps it off the
// Move `secp256k1_ecrecover` token (preceded by `_`, a word char → no boundary).
const RE_SOL_ECRECOVER = /\becrecover\s*\(/g;
// OpenZeppelin / Solady library calls: `ECDSA.recover(` / `ECDSA.tryRecover(`
// and `SignatureChecker.isValidSignatureNow(`.
const RE_SOL_ECDSA_LIB =
  /\bECDSA\.(?:recover|tryRecover)\s*\(|\bSignatureChecker\.isValidSignatureNow\s*\(/g;
// Import of the classical-signature libraries: OZ `.../cryptography/ECDSA.sol` /
// `.../cryptography/SignatureChecker.sol`, and Solady `.../utils/ECDSA.sol`.
const RE_SOL_ECDSA_IMPORT = /(?:cryptography|utils)\/(?:ECDSA|SignatureChecker)\.sol\b/g;

// --- Move / Sui & Aptos. ---
// Ed25519 verification: Aptos `ed25519::signature_verify_strict(`, Sui
// `ed25519::ed25519_verify(` (matched via the bare `ed25519_verify(` token).
const RE_MOVE_ED25519 = /\bed25519::signature_verify_strict\s*\(|\bed25519_verify\s*\(/g;
// secp256k1 ECDSA verification / recovery via the Sui `ecdsa_k1` module.
const RE_MOVE_SECP256K1 = /\becdsa_k1::secp256k1_(?:verify|ecrecover)\s*\(/g;

// --- Cairo / Starknet: STARK-curve ECDSA. ---
// `check_ecdsa_signature(` — also matches the qualified `ecdsa::check_ecdsa_signature(`
// (the preceding `:` is a non-word char, so the `\b` boundary still holds).
const RE_CAIRO_ECDSA = /\bcheck_ecdsa_signature\s*\(/g;

const RULE_SOL_ECRECOVER: RuleMeta = {
  id: "sol-ecrecover",
  title: "EVM on-chain ECDSA signature verification (secp256k1)",
  description:
    "Solidity ecrecover / OpenZeppelin-Solady ECDSA.recover / SignatureChecker (secp256k1)",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "On-chain ECDSA over secp256k1 (Solidity/EVM: ecrecover, OpenZeppelin/Solady ECDSA / SignatureChecker) is forgeable by a quantum attacker; on-chain keys often ARE asset custody.",
  remediation: REMEDIATION_ONCHAIN,
};
const RULE_MOVE_ED25519: RuleMeta = {
  id: "sol-ed25519",
  title: "Move on-chain Ed25519 signature verification",
  description: "Move (Sui/Aptos) ed25519::signature_verify_strict / ed25519_verify",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "On-chain Ed25519 signature verification (Move / Sui / Aptos) is classical and forgeable by a quantum attacker; on-chain keys often ARE asset custody.",
  remediation: REMEDIATION_ONCHAIN,
};
const RULE_MOVE_SECP256K1: RuleMeta = {
  id: "sol-secp256k1-verify",
  title: "Move on-chain ECDSA signature verification (secp256k1)",
  description: "Move (Sui) ecdsa_k1::secp256k1_verify / secp256k1_ecrecover",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "On-chain ECDSA over secp256k1 (Move / Sui ecdsa_k1) is forgeable by a quantum attacker; on-chain keys often ARE asset custody.",
  remediation: REMEDIATION_ONCHAIN,
};
const RULE_CAIRO_ECDSA: RuleMeta = {
  id: "cairo-ecdsa",
  title: "Cairo/Starknet on-chain ECDSA signature verification (STARK curve)",
  description: "Cairo check_ecdsa_signature (STARK-curve ECDSA)",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "On-chain ECDSA over the STARK curve (Cairo/Starknet check_ecdsa_signature) is forgeable by a quantum attacker; on-chain keys often ARE asset custody.",
  remediation: REMEDIATION_ONCHAIN,
};

/**
 * Detects classical (quantum-vulnerable) on-chain signature verification in
 * smart-contract source: Solidity/EVM secp256k1 ECDSA, Move Ed25519 & secp256k1,
 * and Cairo/Starknet STARK-curve ECDSA.
 */
export const solidityDetector: Detector = {
  id: "solidity-crypto",
  description:
    "Classical on-chain signature verification in smart-contract source (Solidity, Move, Cairo)",
  scope: "source",
  language: "solidity",
  rules: [RULE_SOL_ECRECOVER, RULE_MOVE_ED25519, RULE_MOVE_SECP256K1, RULE_CAIRO_ECDSA],
  appliesTo: (f) => hasExtension(f, SMART_CONTRACT_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Mask C-style comments (line `//` + block `/* */`) so commented-out
    // verification calls can't fire; the maskers preserve byte offsets.
    const scan = maskCommentLines(maskBlockComments(content), ["//"]);
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_SOL_ECRECOVER, RULE_SOL_ECRECOVER);
    add(RE_SOL_ECDSA_LIB, RULE_SOL_ECRECOVER);
    add(RE_SOL_ECDSA_IMPORT, RULE_SOL_ECRECOVER);
    add(RE_MOVE_ED25519, RULE_MOVE_ED25519);
    add(RE_MOVE_SECP256K1, RULE_MOVE_SECP256K1);
    add(RE_CAIRO_ECDSA, RULE_CAIRO_ECDSA);
    return findings;
  },
};
