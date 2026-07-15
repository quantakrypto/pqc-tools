/**
 * Source-code detector for classical, non-quantum-safe asymmetric cryptography
 * in Python. Same lexical (regex-over-source) strategy as the JS/TS detectors:
 * robust to formatting, dependency-free, and confidence-tagged per pattern.
 *
 * Covers the three libraries that carry ~all real-world Python asymmetric
 * crypto:
 *   - `cryptography` (hazmat): rsa/ec/dh/x25519/x448/ed25519/ed448 + OAEP padding
 *   - PyCryptodome (`Crypto.PublicKey`): RSA/ECC/DSA generate + PKCS1_OAEP
 *   - paramiko (SSH): RSAKey / ECDSAKey / Ed25519Key / DSSKey
 *
 * JWT/JOSE algorithm strings (`algorithm="RS256"`) are NOT handled here — the
 * language-agnostic `jwt-jose` detector now applies to Python too (a quoted
 * `"RS256"` is the same evidence in any language).
 *
 * HNDL policy mirrors the JS detectors: key agreement / KEM (RSA-OAEP, ECDH, DH,
 * X25519/X448) is harvest-now-decrypt-later exposed (hndl:true); signatures
 * (ECDSA, DSA, Ed25519/Ed448) are hndl:false but still high/low severity because
 * a quantum attacker can forge them. EC key generation is ambiguous (an EC key
 * feeds both ECDSA and ECDH), so it is classified conservatively as
 * key-exchange-capable (hndl:true), exactly as the Node `ec` keygen rule is.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { PYTHON_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Precompiled regexes (module scope)                                         */
/* -------------------------------------------------------------------------- */

// RSA key generation: cryptography `rsa.generate_private_key(`, PyCryptodome
// `RSA.generate(`, paramiko `paramiko.RSAKey` / `RSAKey.generate(`.
const RE_PY_RSA_KEYGEN =
  /\brsa\.generate_private_key\s*\(|\bRSA\.generate\s*\(|\bparamiko\.RSAKey\b|\bRSAKey\.generate\s*\(/g;
// RSA public-key encryption padding (RSA-OAEP): confidentiality → HNDL.
const RE_PY_RSA_ENCRYPT = /\bpadding\.OAEP\s*\(|\bPKCS1_OAEP\.new\s*\(/g;
// EC key generation (ambiguous ECDSA/ECDH): cryptography + PyCryptodome.
const RE_PY_EC_KEYGEN = /\bec\.generate_private_key\s*\(|\bECC\.generate\s*\(/g;
// ECDSA signatures: cryptography `ec.ECDSA(`, paramiko ECDSAKey.
const RE_PY_ECDSA = /\bec\.ECDSA\s*\(|\bparamiko\.ECDSAKey\b|\bECDSAKey\.generate\s*\(/g;
// ECDH key agreement: cryptography `ec.ECDH(` — the actual harvest-now event in
// `private_key.exchange(ec.ECDH(), peer)`; previously missed entirely (audit F3).
const RE_PY_ECDH = /\bec\.ECDH\s*\(/g;
// DSA: PyCryptodome `DSA.generate(`, paramiko DSSKey.
const RE_PY_DSA = /\bDSA\.generate\s*\(|\bparamiko\.DSSKey\b|\bDSSKey\.generate\s*\(/g;
// Finite-field Diffie-Hellman (cryptography `dh`).
const RE_PY_DH = /\bdh\.generate_parameters\s*\(|\bdh\.DHParameterNumbers\s*\(/g;
// Modern-but-classical curve primitives (cryptography). `.generate(` anchors so
// a bare import of the class name does not fire.
const RE_PY_X25519 = /\bX25519PrivateKey\.generate\s*\(/g;
const RE_PY_X448 = /\bX448PrivateKey\.generate\s*\(/g;
const RE_PY_EDDSA = /\b(?:Ed25519|Ed448)PrivateKey\.generate\s*\(|\bparamiko\.Ed25519Key\b/g;

/* -------------------------------------------------------------------------- */
/* Rule catalog                                                               */
/* -------------------------------------------------------------------------- */

const RULE_PY_RSA_KEYGEN: RuleMeta = {
  id: "python-rsa-keygen",
  title: "Python RSA key generation",
  description:
    "cryptography rsa.generate_private_key / PyCryptodome RSA.generate / paramiko RSAKey",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (Python), which is not quantum-safe.",
};
const RULE_PY_RSA_ENCRYPT: RuleMeta = {
  id: "python-rsa-encrypt",
  title: "Python RSA public-key encryption",
  description: "RSA-OAEP / PKCS1_OAEP encryption padding",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption (OAEP) is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
};
const RULE_PY_EC_KEYGEN: RuleMeta = {
  id: "python-ec-keygen",
  title: "Python EC key generation",
  description: "cryptography ec.generate_private_key / PyCryptodome ECC.generate",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical EC key pair (Python). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_PY_ECDSA: RuleMeta = {
  id: "python-ecdsa",
  title: "Python ECDSA signature",
  description: "cryptography ec.ECDSA / paramiko ECDSAKey",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Python) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_PY_ECDH: RuleMeta = {
  id: "python-ecdh",
  title: "Python ECDH key agreement",
  description: "cryptography ec.ECDH() exchange",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman key agreement (Python) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_PY_DSA: RuleMeta = {
  id: "python-dsa",
  title: "Python DSA key/usage",
  description: "PyCryptodome DSA.generate / paramiko DSSKey",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Python) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_PY_DH: RuleMeta = {
  id: "python-dh",
  title: "Python Diffie-Hellman key exchange",
  description: "cryptography dh.generate_parameters / DHParameterNumbers",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman (Python) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_PY_X25519: RuleMeta = {
  id: "python-x25519",
  title: "Python X25519 key exchange",
  description: "cryptography X25519PrivateKey.generate",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 (Python) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_PY_X448: RuleMeta = {
  id: "python-x448",
  title: "Python X448 key exchange",
  description: "cryptography X448PrivateKey.generate",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X448",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X448 (Python) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_PY_EDDSA: RuleMeta = {
  id: "python-eddsa",
  title: "Python Ed25519/Ed448 signature",
  description: "cryptography Ed25519/Ed448 PrivateKey.generate / paramiko Ed25519Key",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519/Ed448 (Python) is a modern but still classical signature scheme.",
};

/** Detects classical asymmetric crypto in Python source. */
export const pythonDetector: Detector = {
  id: "python-crypto",
  description: "Classical asymmetric crypto in Python (cryptography, PyCryptodome, paramiko)",
  scope: "source",
  language: "python",
  rules: [
    RULE_PY_RSA_KEYGEN,
    RULE_PY_RSA_ENCRYPT,
    RULE_PY_EC_KEYGEN,
    RULE_PY_ECDSA,
    RULE_PY_ECDH,
    RULE_PY_DSA,
    RULE_PY_DH,
    RULE_PY_X25519,
    RULE_PY_X448,
    RULE_PY_EDDSA,
  ],
  appliesTo: (f) => hasExtension(f, PYTHON_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );

    add(RE_PY_RSA_KEYGEN, RULE_PY_RSA_KEYGEN);
    add(RE_PY_RSA_ENCRYPT, RULE_PY_RSA_ENCRYPT);
    add(RE_PY_EC_KEYGEN, RULE_PY_EC_KEYGEN);
    add(RE_PY_ECDSA, RULE_PY_ECDSA);
    add(RE_PY_ECDH, RULE_PY_ECDH);
    add(RE_PY_DSA, RULE_PY_DSA);
    add(RE_PY_DH, RULE_PY_DH);
    add(RE_PY_X25519, RULE_PY_X25519);
    add(RE_PY_X448, RULE_PY_X448);
    add(RE_PY_EDDSA, RULE_PY_EDDSA);

    return findings;
  },
};
