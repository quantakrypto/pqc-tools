/**
 * IaC detector: classical asymmetric cryptography and legacy TLS declared in Azure
 * Bicep (`.bicep`) — Azure's native IaC DSL, distinct from the ARM/CloudFormation
 * JSON the cloudformation detector already covers (Bicep is the *source*; ARM JSON is
 * its compiled output). Bicep provisions the same Key Vault keys and TLS floors, but
 * in its own single-quoted-string syntax that the JSON detector never sees.
 *
 * Covered (gated to `.bicep` files):
 *  - `Microsoft.KeyVault/vaults/keys` `kty: 'RSA' | 'RSA-HSM' | 'EC' | 'EC-HSM'` — a
 *    classical Key Vault key. RSA is KEM (HNDL); EC feeds ECDSA + ECDH (the ECDH path
 *    is HNDL). Gated to a `Microsoft.KeyVault` marker so a stray `kty` elsewhere in a
 *    template does not fire.
 *  - `minimumTlsVersion: 'TLS1_0' | 'TLS1_1'` — a deprecated TLS floor on storage /
 *    app-service / other resources (RFC 8996). Not HNDL (a config weakness), category
 *    "tls".
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension, maskCommentLines } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_WEAK_STRENGTH } from "../cwe.js";

const BICEP_EXTENSIONS: readonly string[] = [".bicep"];

// Bicep string values are single-quoted. `kty: 'RSA'` / `'RSA-HSM'` (KEM) and
// `kty: 'EC'` / `'EC-HSM'` (EC). The `(?<![\w-])` lookbehind stops a longer key name
// from matching on a `kty` suffix; the value bound keeps `'EC'` from matching `'ECX'`.
const RE_BICEP_KTY_RSA = /(?<![\w-])kty\s*:\s*'RSA(?:-HSM)?'/g;
const RE_BICEP_KTY_EC = /(?<![\w-])kty\s*:\s*'EC(?:-HSM)?'/g;
// Legacy TLS floor. `TLS1_0` / `TLS1_1` are deprecated; `TLS1_2` / `TLS1_3` are fine,
// and the closing quote keeps this from matching them.
const RE_BICEP_MIN_TLS = /(?<![\w])minimumTlsVersion\s*:\s*'TLS1_[01]'/g;

const RULE_BICEP_KTY_RSA: RuleMeta = {
  id: "bicep-keyvault-rsa",
  title: "Bicep Azure Key Vault RSA key",
  description: "Azure Bicep Microsoft.KeyVault key with kty: 'RSA'",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Bicep provisions a classical RSA Azure Key Vault key, which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
};
const RULE_BICEP_KTY_EC: RuleMeta = {
  id: "bicep-keyvault-ec",
  title: "Bicep Azure Key Vault EC key",
  description: "Azure Bicep Microsoft.KeyVault key with kty: 'EC'",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Bicep provisions a classical EC Azure Key Vault key; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_BICEP_MIN_TLS: RuleMeta = {
  id: "bicep-min-tls-legacy",
  title: "Bicep legacy minimum TLS version",
  description: "Azure Bicep resource pins minimumTlsVersion to TLS 1.0/1.1",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "Bicep resource pins a deprecated TLS floor (TLS 1.0/1.1); require TLS 1.2+ (1.3).",
  remediation: "Set minimumTlsVersion: 'TLS1_2' and prefer PQC-hybrid key exchange as it lands.",
};

/** Detects classical asymmetric crypto and legacy TLS declared in Azure Bicep. */
export const bicepDetector: Detector = {
  id: "bicep-crypto",
  description: "Classical asymmetric crypto and legacy TLS declared in Azure Bicep (IaC)",
  scope: "config",
  language: "any",
  rules: [RULE_BICEP_KTY_RSA, RULE_BICEP_KTY_EC, RULE_BICEP_MIN_TLS],
  appliesTo: (f) => hasExtension(f, BICEP_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Bicep comments are `//` and `/* */`; mask whole comment lines so a commented-out
    // resource can't fire. Offsets preserved.
    const scan = maskCommentLines(content, ["//", "/*"]);
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    // The bare `kty` field is generic; only treat it as a Key Vault key when the
    // resource type is actually present, mirroring the cloudformation ARM gate.
    if (content.includes("Microsoft.KeyVault")) {
      add(RE_BICEP_KTY_RSA, RULE_BICEP_KTY_RSA);
      add(RE_BICEP_KTY_EC, RULE_BICEP_KTY_EC);
    }
    add(RE_BICEP_MIN_TLS, RULE_BICEP_MIN_TLS);
    return findings;
  },
};
