/**
 * Config detector: classical asymmetric signature algorithms pinned by
 * WebAuthn / FIDO2 / passkey attestation & assertion, expressed as COSE
 * algorithm identifiers in relying-party code and config
 * (@simplewebauthn/server, py_webauthn, go-webauthn, webauthn4j).
 *
 * WHY WebAuthn is PQC-relevant: a WebAuthn credential is an asymmetric key
 * pair whose PUBLIC key the authenticator returns (COSE-encoded) at
 * registration; every subsequent assertion is a classical signature over the
 * authentication challenge, and attestation statements are classical
 * signatures over the credential. These are AUTHENTICATION signatures, not
 * confidentiality — there is nothing to "harvest now" — but the moment a
 * cryptographically-relevant quantum computer (CRQC) exists, an attacker who
 * has a user's registered public key (or an attestation CA's key) can FORGE
 * assertions/attestations and impersonate the user or a genuine authenticator.
 * So every finding here is `category: "signature"`, `hndl: false`.
 *
 * The relying party pins which algorithms it will accept: `pubKeyCredParams`
 * (registration) and `supportedAlgorithmIDs` (verification) enumerate COSE
 * `alg` values, and the classical ones — ES256 (COSE -7, ECDSA P-256),
 * RS256 (-257, RSA), EdDSA (-8) and their P-384/P-521/RSA-2048+ siblings — are
 * exactly the ones a PQC migration must inventory and replace once FIDO/COSE
 * standardise post-quantum algorithm identifiers.
 *
 * WHY numeric COSE ids need their own detector: the existing JWT/JOSE rule
 * only matches QUOTED alg strings (`"ES256"`, `"RS256"`). WebAuthn libraries
 * almost never write those strings — they use the NUMERIC COSE ids
 * (`alg: -7`, `supportedAlgorithmIDs: [-7, -257]`) and language-level enum
 * identifiers (`COSEAlgorithmIdentifier.ES256`, `webauthncose.AlgES256`,
 * `COSEAlgorithmIdentifier.EDDSA`). None of those carry the quote characters
 * the JWT rule keys off, so the entire WebAuthn surface is invisible today.
 *
 * Two independent match shapes per family, both gated by a file-level WebAuthn
 * marker (see `hasWebauthnMarker`) so the generic numeric `alg: -7` form can't
 * fire on unrelated code that happens to assign a small negative number:
 *
 *  1. NUMERIC form — the COSE `alg` value as an integer, either as an object
 *     member (`alg: -7`, `alg = -257`) or inside a `supportedAlgorithmIDs`
 *     array (`supportedAlgorithmIDs: [-7, -257]`). Restricted to the classical
 *     COSE numbers only; symmetric / KDF / "direct" ids (e.g. -6, HS*) are
 *     never in the alternation, so they cannot match.
 *  2. ENUM form — the COSE algorithm's identifier as written in each library:
 *     `COSEAlgorithmIdentifier.ES256|RS256|EdDSA|ECDSA_SHA_256` (webauthn4j,
 *     py_webauthn) and Go's `webauthncose.AlgES256` / `AlgRS256` / `AlgEdDSA`
 *     constants.
 *
 * COSE algorithm numbers → {@link AlgorithmFamily} (per the COSE registry, using
 * the mapping this detector is specified against):
 *  - ES256 (-7), ES384 (-35), ES512 (-36)      → ECDSA
 *  - RS256 (-257), RS384 (-258), RS512 (-259)  → RSA
 *  - EdDSA (-8)                                 → EdDSA
 *
 * Fast reject: `detect()` bails unless the file carries a distinctive WebAuthn
 * API token (`pubKeyCredParams`, `PublicKeyCredential`, `webauthn`,
 * `COSEAlgorithm`, `supportedAlgorithmIDs`, `navigator.credentials`). Those
 * tokens are the marker gate ONLY — they never produce a standalone finding.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// Classical COSE algorithm numbers, grouped by family (see module docstring).
const NUM_ECDSA = "7|35|36"; // ES256, ES384, ES512
const NUM_RSA = "257|258|259"; // RS256, RS384, RS512
const NUM_EDDSA = "8"; // EdDSA

// --- NUMERIC form: a COSE `alg` value written as an integer. ---
// (a) object member: `alg: -7`, `alg = -257` (JS/JSON, Python `alg=-7`).
// `["']?alg["']?` tolerates the JSON/serialized form `"alg": -7` (the WebAuthn
// options object is JSON-serializable and often stored/transmitted/tested as JSON
// with a quoted key), as well as the unquoted `alg: -7` / `alg = -7` (audit M2).
const RE_NUM_ECDSA = new RegExp(`["']?\\balg\\b["']?\\s*[:=]\\s*-(?:${NUM_ECDSA})\\b`, "g");
const RE_NUM_RSA = new RegExp(`["']?\\balg\\b["']?\\s*[:=]\\s*-(?:${NUM_RSA})\\b`, "g");
const RE_NUM_EDDSA = new RegExp(`["']?\\balg\\b["']?\\s*[:=]\\s*-(?:${NUM_EDDSA})\\b`, "g");
// (b) `supportedAlgorithmIDs: [-7, -257]` array (@simplewebauthn verify option).
// `[^\]]*` stays inside a single array literal; one match per family even when
// the array lists several ids of that family.
const RE_IDS_ECDSA = new RegExp(
  `supportedAlgorithmIDs\\s*[:=]\\s*\\[[^\\]]*-(?:${NUM_ECDSA})\\b`,
  "g",
);
const RE_IDS_RSA = new RegExp(`supportedAlgorithmIDs\\s*[:=]\\s*\\[[^\\]]*-(?:${NUM_RSA})\\b`, "g");
const RE_IDS_EDDSA = new RegExp(
  `supportedAlgorithmIDs\\s*[:=]\\s*\\[[^\\]]*-(?:${NUM_EDDSA})\\b`,
  "g",
);

// --- ENUM form: the COSE algorithm's language-level identifier. ---
// webauthn4j / py_webauthn: `COSEAlgorithmIdentifier.<name>`; go-webauthn:
// `webauthncose.Alg<name>` (matched bare as `Alg<name>`).
const RE_ENUM_ECDSA =
  /\bCOSEAlgorithmIdentifier\.(?:ES(?:256|384|512)|ECDSA_SHA_(?:256|384|512))\b|\bAlgES(?:256|384|512)\b/g;
const RE_ENUM_RSA =
  /\bCOSEAlgorithmIdentifier\.(?:RS(?:256|384|512)|RSASSA_[A-Za-z0-9_]+)\b|\bAlgRS(?:256|384|512)\b/g;
const RE_ENUM_EDDSA = /\bCOSEAlgorithmIdentifier\.(?:EdDSA|EDDSA)\b|\bAlgEdDSA\b/g;

const REMEDIATION =
  "WebAuthn/FIDO2 is standardizing PQC COSE algorithms; inventory the classical attestation/assertion algs now and plan migration.";

const RULE_WEBAUTHN_ECDSA: RuleMeta = {
  id: "webauthn-ecdsa",
  title: "WebAuthn ECDSA COSE algorithm",
  description:
    "WebAuthn/FIDO2 credential pins a classical ECDSA COSE algorithm (ES256/ES384/ES512)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "WebAuthn/FIDO2 relying party accepts a classical ECDSA COSE algorithm (ES256/ES384/ES512); attestation/assertion signatures become forgeable once a CRQC exists.",
  remediation: REMEDIATION,
};
const RULE_WEBAUTHN_RSA: RuleMeta = {
  id: "webauthn-rsa",
  title: "WebAuthn RSA COSE algorithm",
  description: "WebAuthn/FIDO2 credential pins a classical RSA COSE algorithm (RS256/RS384/RS512)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "WebAuthn/FIDO2 relying party accepts a classical RSA COSE algorithm (RS256/RS384/RS512); attestation/assertion signatures become forgeable once a CRQC exists.",
  remediation: REMEDIATION,
};
const RULE_WEBAUTHN_EDDSA: RuleMeta = {
  id: "webauthn-eddsa",
  title: "WebAuthn EdDSA COSE algorithm",
  description: "WebAuthn/FIDO2 credential pins the classical EdDSA COSE algorithm (COSE -8)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "WebAuthn/FIDO2 relying party accepts the classical EdDSA COSE algorithm (Ed25519); modern but still classical — attestation/assertion signatures become forgeable once a CRQC exists.",
  remediation: REMEDIATION,
};

interface WebauthnRule {
  meta: RuleMeta;
  res: readonly RegExp[];
}

const WEBAUTHN_RULES: readonly WebauthnRule[] = [
  { meta: RULE_WEBAUTHN_ECDSA, res: [RE_NUM_ECDSA, RE_IDS_ECDSA, RE_ENUM_ECDSA] },
  { meta: RULE_WEBAUTHN_RSA, res: [RE_NUM_RSA, RE_IDS_RSA, RE_ENUM_RSA] },
  { meta: RULE_WEBAUTHN_EDDSA, res: [RE_NUM_EDDSA, RE_IDS_EDDSA, RE_ENUM_EDDSA] },
];

/**
 * True when `content` carries a distinctive WebAuthn API token. Used ONLY as
 * the fast-reject marker gate — none of these tokens produce a finding — so the
 * generic numeric `alg: -7` form can't fire on unrelated code.
 */
function hasWebauthnMarker(content: string): boolean {
  return (
    content.includes("pubKeyCredParams") ||
    content.includes("PublicKeyCredential") ||
    content.includes("COSEAlgorithm") ||
    content.includes("supportedAlgorithmIDs") ||
    content.includes("navigator.credentials") ||
    /webauthn/i.test(content)
  );
}

/** Detects classical COSE signature algorithms pinned by WebAuthn/FIDO2 relying parties. */
export const webauthnDetector: Detector = {
  id: "webauthn-crypto",
  description: "Classical COSE signature algorithms in WebAuthn/FIDO2/passkey relying-party code",
  scope: "config",
  language: "any",
  rules: WEBAUTHN_RULES.map((r) => r.meta),
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!hasWebauthnMarker(content)) return [];

    // Mask C-style (`//`, `/* */`) and hash (`#`) comments so a commented-out
    // options object can't fire. Offsets are preserved so finding locations stay
    // exact.
    const scan = maskCommentLines(maskBlockComments(content), ["//", "#"]);
    const findings: Finding[] = [];
    for (const { meta, res } of WEBAUTHN_RULES) {
      for (const re of res) {
        eachMatch(re, scan, (m) =>
          findings.push(
            findingFromRule(meta, { file, content, index: m.index, matchLength: m[0].length }),
          ),
        );
      }
    }
    return findings;
  },
};
