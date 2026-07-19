/**
 * Source-code detector for classical asymmetric cryptography in Elixir (the BEAM
 * / Phoenix ecosystem), previously uncovered. Handles the three common surfaces:
 *
 *  - **Erlang `:crypto`** — `:crypto.generate_key(:rsa|:ecdh|:dh|:eddsa, …)`
 *    (the curve atom disambiguates X25519/X448 from a generic ECDH curve) and
 *    `:crypto.sign/:crypto.verify(:rsa|:ecdsa|:eddsa, …)`.
 *  - **`X509`** (the `x509` hex package) — `X509.PrivateKey.new_rsa` / `new_ec`.
 *  - **`JOSE`** (erlang-jose) — `JOSE.JWK.generate_key({:rsa|:ec|:okp, …})`.
 *
 * Lexical, like the other packs; the `:crypto.` atom-module syntax and the
 * `X509.` / `JOSE.` module paths are distinctive, so the false-positive rate is low.
 *
 * HNDL: RSA and (EC/X)DH key agreement are harvest-now-decrypt-later exposed
 * (hndl:true); ECDSA / EdDSA signatures are hndl:false but forgeable.
 */
import type { AlgorithmFamily, Detector, Finding, RuleMeta } from "../types.js";
import { ELIXIR_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const RE_EX_GEN = /:crypto\.generate_key\s*\(\s*:(\w+)/g;
const RE_EX_SIGN = /:crypto\.(?:sign|verify)\s*\(\s*:(\w+)/g;
const RE_EX_X509_RSA = /\bX509\.PrivateKey\.new_rsa\s*\(/g;
const RE_EX_X509_EC = /\bX509\.PrivateKey\.new_ec\s*\(/g;
const RE_EX_JOSE = /\bJOSE\.JWK\.generate_key\s*\(\s*\{\s*:(\w+)/g;

interface Cls {
  algo: AlgorithmFamily;
  cat: Finding["category"];
  sev: Finding["severity"];
  hndl: boolean;
  label: string;
  remediation?: string;
}
const SIG_REM = "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)";
const KEX_REM = "hybrid X25519MLKEM768 (ML-KEM-768)";

const RULE_EX_KEYGEN: RuleMeta = {
  id: "elixir-crypto-keygen",
  title: "Elixir :crypto key generation",
  description: ":crypto.generate_key (rsa/ecdh/dh/eddsa)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical key pair via Erlang :crypto (Elixir) — not quantum-safe.",
};
const RULE_EX_SIGN: RuleMeta = {
  id: "elixir-crypto-sign",
  title: "Elixir :crypto signature",
  description: ":crypto.sign / :crypto.verify (rsa/ecdsa/eddsa)",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical signature via Erlang :crypto (Elixir) is forgeable by a quantum attacker.",
  remediation: SIG_REM,
};
const RULE_EX_X509: RuleMeta = {
  id: "elixir-x509-keygen",
  title: "Elixir X509 key generation",
  description: "X509.PrivateKey.new_rsa / new_ec",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical key pair via the X509 library (Elixir) — not quantum-safe.",
};
const RULE_EX_JOSE: RuleMeta = {
  id: "elixir-jose-jwk",
  title: "Elixir JOSE JWK generation",
  description: "JOSE.JWK.generate_key ({:rsa|:ec|:okp})",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical JWK via JOSE (Elixir) — not quantum-safe.",
};

const RSA_CLS: Cls = { algo: "RSA", cat: "kem", sev: "high", hndl: true, label: "RSA" };
const DH_CLS: Cls = { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "DH" };
const ECDH_CLS: Cls = {
  algo: "ECDH",
  cat: "key-exchange",
  sev: "high",
  hndl: true,
  label: "ECDH",
  remediation: KEX_REM,
};
const X25519_CLS: Cls = {
  algo: "X25519",
  cat: "key-exchange",
  sev: "medium",
  hndl: true,
  label: "X25519",
  remediation: KEX_REM,
};
const X448_CLS: Cls = { ...X25519_CLS, algo: "X448", label: "X448" };
const EDDSA_CLS: Cls = {
  algo: "EdDSA",
  cat: "signature",
  sev: "low",
  hndl: false,
  label: "EdDSA",
  remediation: SIG_REM,
};
const EC_CLS: Cls = {
  algo: "ECDH",
  cat: "key-exchange",
  sev: "high",
  hndl: true,
  label: "EC (ECDSA/ECDH)",
  remediation: KEX_REM,
};

/** Classify a `:crypto.generate_key(:<type>, …)` by its type atom (+ the curve
 * atom in a short window for the ecdh X25519/X448 case). */
function classifyGen(type: string, window: string): Cls | null {
  switch (type) {
    case "rsa":
      return RSA_CLS;
    case "dh":
      return DH_CLS;
    case "eddsa":
    case "ed25519":
      return EDDSA_CLS;
    case "ecdh":
      if (/:x25519\b/i.test(window)) return X25519_CLS;
      if (/:x448\b/i.test(window)) return X448_CLS;
      return ECDH_CLS;
    default:
      return null; // srp / other non-broken-in-this-model types
  }
}

/** Signature algorithm classification for `:crypto.sign(:<type>, …)`. */
function classifySign(type: string): AlgorithmFamily | null {
  if (type === "rsa") return "RSA";
  if (type === "ecdsa") return "ECDSA";
  if (type === "eddsa" || type === "ed25519") return "EdDSA";
  if (type === "dss") return "DSA"; // Erlang's algorithm atom for DSA signatures
  return null;
}

/** Detects classical asymmetric crypto in Elixir (:crypto, X509, JOSE). */
export const elixirDetector: Detector = {
  id: "elixir-crypto",
  description: "Classical asymmetric crypto in Elixir (:crypto, X509, JOSE)",
  scope: "source",
  language: "elixir",
  rules: [RULE_EX_KEYGEN, RULE_EX_SIGN, RULE_EX_X509, RULE_EX_JOSE],
  appliesTo: (f) => hasExtension(f, ELIXIR_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const at = (m: RegExpExecArray) => ({
      file,
      content,
      index: m.index,
      matchLength: m[0].length,
    });

    // :crypto.generate_key(:type, …) — classify by the type atom (+ curve window).
    eachMatch(RE_EX_GEN, content, (m) => {
      const cls = classifyGen(m[1], content.slice(m.index, m.index + 80));
      if (!cls) return;
      findings.push(
        findingFromRule(RULE_EX_KEYGEN, at(m), {
          title: `Elixir :crypto ${cls.label} key generation`,
          category: cls.cat,
          severity: cls.sev,
          algorithm: cls.algo,
          hndl: cls.hndl,
          message: `Generates a classical ${cls.label} key pair via Erlang :crypto (Elixir) — not quantum-safe.`,
          ...(cls.remediation ? { remediation: cls.remediation } : {}),
        }),
      );
    });

    // :crypto.sign / :crypto.verify(:type, …).
    eachMatch(RE_EX_SIGN, content, (m) => {
      const algo = classifySign(m[1]);
      if (!algo) return;
      findings.push(
        findingFromRule(RULE_EX_SIGN, at(m), {
          algorithm: algo,
          message: `Classical ${algo} signature via Erlang :crypto (Elixir) is forgeable by a quantum attacker.`,
        }),
      );
    });

    // X509.PrivateKey.new_rsa / new_ec.
    eachMatch(RE_EX_X509_RSA, content, (m) =>
      findings.push(findingFromRule(RULE_EX_X509, at(m), { algorithm: "RSA" })),
    );
    eachMatch(RE_EX_X509_EC, content, (m) =>
      findings.push(
        findingFromRule(RULE_EX_X509, at(m), {
          title: "Elixir X509 EC key generation",
          category: EC_CLS.cat,
          algorithm: EC_CLS.algo,
          hndl: EC_CLS.hndl,
          message:
            "Generates a classical EC key pair via the X509 library (Elixir); EC keys feed BOTH ECDSA and ECDH.",
          remediation: KEX_REM,
        }),
      ),
    );

    // JOSE.JWK.generate_key({:rsa|:ec|:okp, …}).
    eachMatch(RE_EX_JOSE, content, (m) => {
      const kind = m[1];
      const cls =
        kind === "rsa" ? RSA_CLS : kind === "ec" ? EC_CLS : kind === "okp" ? EDDSA_CLS : null;
      if (!cls) return;
      findings.push(
        findingFromRule(RULE_EX_JOSE, at(m), {
          title: `Elixir JOSE ${cls.label} JWK`,
          category: cls.cat,
          severity: cls.sev,
          algorithm: cls.algo,
          hndl: cls.hndl,
          message: `Generates a classical ${cls.label} JWK via JOSE (Elixir) — not quantum-safe.`,
          ...(cls.remediation ? { remediation: cls.remediation } : {}),
        }),
      );
    });

    return findings;
  },
};
