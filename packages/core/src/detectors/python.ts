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
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION, CWE_WEAK_STRENGTH } from "../cwe.js";

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
// hazmat DSA: cryptography `dsa.generate_private_key(` — the `cryptography` DSA
// keygen path (lowercase module) that RE_PY_DSA's uppercase `DSA.generate` misses
// (audit F9-python).
const RE_PY_HAZMAT_DSA = /\bdsa\.generate_private_key\s*\(/g;
// Finite-field Diffie-Hellman (cryptography `dh`).
const RE_PY_DH = /\bdh\.generate_parameters\s*\(|\bdh\.DHParameterNumbers\s*\(/g;
// Modern-but-classical curve primitives (cryptography). `.generate(` anchors so
// a bare import of the class name does not fire.
const RE_PY_X25519 = /\bX25519PrivateKey\.generate\s*\(/g;
const RE_PY_X448 = /\bX448PrivateKey\.generate\s*\(/g;
const RE_PY_EDDSA = /\b(?:Ed25519|Ed448)PrivateKey\.generate\s*\(|\bparamiko\.Ed25519Key\b/g;

// Python TLS misconfiguration. Mirrors the JS `tlsDetector` split of source.ts:
// certificate-verification bypass (requests `verify=False`, `ssl.CERT_NONE`,
// `check_hostname=False`, `ssl._create_unverified_context(`) is the high-severity
// MITM surface (CWE-295); a pinned legacy protocol (`ssl.PROTOCOL_TLSv1`) is the
// medium-severity weak-strength surface (CWE-326).
const RE_PY_TLS_REJECT =
  /\bverify\s*=\s*False\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b|\bssl\._create_unverified_context\s*\(/g;
const RE_PY_TLS_LEGACY = /\bPROTOCOL_TLSv1\b/g;

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
const RULE_PY_HAZMAT_DSA: RuleMeta = {
  id: "python-hazmat-dsa",
  title: "Python DSA key generation (cryptography)",
  description: "cryptography dsa.generate_private_key",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "cryptography dsa.generate_private_key (Python) creates a classical DSA key; DSA is deprecated and forgeable by a quantum attacker.",
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
  severity: "medium",
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
  severity: "medium",
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
const RULE_PY_TLS_REJECT: RuleMeta = {
  id: "python-tls-reject",
  title: "Python TLS certificate verification disabled",
  description:
    "requests verify=False / ssl.CERT_NONE / check_hostname=False / _create_unverified_context",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message:
    "TLS certificate verification is disabled (verify=False / CERT_NONE / check_hostname=False / _create_unverified_context), which allows man-in-the-middle attacks.",
  remediation:
    "Enable certificate verification (verify=True, ssl.CERT_REQUIRED, check_hostname=True) and verify certificates properly.",
};
const RULE_PY_TLS_LEGACY: RuleMeta = {
  id: "python-tls-legacy-version",
  title: "Python legacy TLS version pinned",
  description: "ssl.PROTOCOL_TLSv1 (TLS 1.0)",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "TLS 1.0 (ssl.PROTOCOL_TLSv1) is deprecated and insecure; require TLS 1.3.",
  remediation:
    "Use ssl.PROTOCOL_TLS_CLIENT with minimum_version = ssl.TLSVersion.TLSv1_3 and prefer PQC-hybrid key exchange.",
};

/**
 * Aliasable `cryptography` / PyCryptodome modules → the (method, rule) pairs
 * reachable through them. Lets an aliased module import
 * (`from ... import rsa as _rsa` → `_rsa.generate_private_key(`) resolve back to
 * the same rule the direct `rsa.generate_private_key(` would fire, since the
 * detector's regexes are module-qualified and miss a renamed prefix.
 */
const PY_MODULE_RULES: Record<string, ReadonlyArray<{ method: string; rule: RuleMeta }>> = {
  rsa: [{ method: "generate_private_key", rule: RULE_PY_RSA_KEYGEN }],
  ec: [
    { method: "generate_private_key", rule: RULE_PY_EC_KEYGEN },
    { method: "ECDSA", rule: RULE_PY_ECDSA },
    { method: "ECDH", rule: RULE_PY_ECDH },
  ],
  dsa: [{ method: "generate_private_key", rule: RULE_PY_HAZMAT_DSA }],
  dh: [{ method: "generate_parameters", rule: RULE_PY_DH }],
  padding: [{ method: "OAEP", rule: RULE_PY_RSA_ENCRYPT }],
  // PyCryptodome factory modules (`.generate(`).
  RSA: [{ method: "generate", rule: RULE_PY_RSA_KEYGEN }],
  ECC: [{ method: "generate", rule: RULE_PY_EC_KEYGEN }],
  DSA: [{ method: "generate", rule: RULE_PY_DSA }],
};

/** Escape a string for interpolation into a dynamically-built RegExp. */
function escapePyRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Collect module aliases for the aliasable crypto modules, so a later
 * `<alias>.<method>(` call still resolves. Handles both `from <path> import
 * <mod> as <alias>` (including comma-separated specifiers) and the bare
 * `import <path.mod> as <alias>`. Returns Map<module, alias[]>; an alias equal to
 * its own module name is skipped (matched directly already).
 */
function collectPyModuleAliases(content: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (mod: string, alias: string): void => {
    if (!alias || alias === mod || !(mod in PY_MODULE_RULES)) return;
    const list = out.get(mod) ?? [];
    if (!list.includes(alias)) list.push(alias);
    out.set(mod, list);
  };
  // `from <path> import a as b, c as d` — scan the import list for `X as Y`.
  const fromRe = /(?:^|\n)[ \t]*from\s+[\w.]+\s+import\s+([^\n#]+)/g;
  for (let m = fromRe.exec(content); m; m = fromRe.exec(content)) {
    const specRe = /([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)/g;
    for (let s = specRe.exec(m[1]); s; s = specRe.exec(m[1])) add(s[1], s[2]);
  }
  // `import <path.mod> as <alias>` — the aliased module is the last dotted segment.
  const impRe = /(?:^|\n)[ \t]*import\s+([\w.]+)\s+as\s+([A-Za-z_]\w*)/g;
  for (let m = impRe.exec(content); m; m = impRe.exec(content)) {
    add(m[1].split(".").pop() ?? m[1], m[2]);
  }
  return out;
}

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
    RULE_PY_HAZMAT_DSA,
    RULE_PY_DH,
    RULE_PY_X25519,
    RULE_PY_X448,
    RULE_PY_EDDSA,
    RULE_PY_TLS_REJECT,
    RULE_PY_TLS_LEGACY,
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
    add(RE_PY_HAZMAT_DSA, RULE_PY_HAZMAT_DSA);
    add(RE_PY_DH, RULE_PY_DH);
    add(RE_PY_X25519, RULE_PY_X25519);
    add(RE_PY_X448, RULE_PY_X448);
    add(RE_PY_EDDSA, RULE_PY_EDDSA);
    add(RE_PY_TLS_REJECT, RULE_PY_TLS_REJECT);
    add(RE_PY_TLS_LEGACY, RULE_PY_TLS_LEGACY);

    // Module-alias resolution: `from ... import rsa as _rsa` then
    // `_rsa.generate_private_key(` — the direct regexes are module-qualified
    // (`\brsa\.`) and miss a renamed prefix. Runs on the ORIGINAL content so
    // locations stay exact; fires only for an alias explicitly bound to a known
    // crypto module, so precision is unaffected.
    for (const [mod, aliasList] of collectPyModuleAliases(content)) {
      for (const alias of aliasList) {
        const a = escapePyRe(alias);
        for (const { method, rule } of PY_MODULE_RULES[mod]) {
          add(new RegExp(`\\b${a}\\.${method}\\s*\\(`, "g"), rule);
        }
      }
    }

    return findings;
  },
};
