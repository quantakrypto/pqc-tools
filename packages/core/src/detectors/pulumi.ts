/**
 * IaC detector: classical asymmetric keys provisioned by Pulumi's `tls` provider
 * (`@pulumi/tls` / `pulumi_tls` / `pulumi-tls`), across the languages Pulumi programs
 * are written in (TS/JS, Python, Go). A `tls.PrivateKey` resource mints real key
 * material at deploy time — the IaC surface, like Terraform's `tls_private_key`, but
 * expressed as SDK calls in a general-purpose source file rather than HCL.
 *
 * Detection is gated to files that actually use the pulumi-tls provider (a
 * `@pulumi/tls` / `pulumi_tls` / `pulumi-tls` import or a `tls.PrivateKey` /
 * `tls.NewPrivateKey` construction), then classifies each `algorithm` value:
 *  - `"RSA"`     → RSA key (kem, HNDL)
 *  - `"ECDSA"`   → EC signing key (signature)
 *  - `"ED25519"` → Ed25519 signing key (signature)
 * Comment/string suppression is handled centrally for the host languages.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const PULUMI_EXTENSIONS: readonly string[] = [".ts", ".js", ".mjs", ".cjs", ".py", ".go"];

// The `algorithm` value of a pulumi-tls PrivateKey, in the TS/Python (`algorithm:
// "RSA"` / `algorithm="RSA"`) and Go (`Algorithm: pulumi.String("RSA")`) spellings.
const RE_PULUMI_TLS_ALG =
  /\b[Aa]lgorithm\s*[:=]\s*(?:pulumi\.String\(\s*)?["'](RSA|ECDSA|ED25519)["']/g;

/** True when the file actually uses the pulumi-tls provider (gate against FPs). */
function usesPulumiTls(content: string): boolean {
  return (
    content.includes("@pulumi/tls") ||
    content.includes("pulumi_tls") ||
    content.includes("pulumi-tls") ||
    content.includes("tls.PrivateKey") ||
    content.includes("tls.NewPrivateKey")
  );
}

const RULE_PULUMI_RSA: RuleMeta = {
  id: "pulumi-tls-rsa",
  title: "Pulumi tls.PrivateKey RSA key",
  description: 'Pulumi tls.PrivateKey with algorithm "RSA"',
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Pulumi provisions a classical RSA key (tls.PrivateKey), which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
};
const RULE_PULUMI_ECDSA: RuleMeta = {
  id: "pulumi-tls-ecdsa",
  title: "Pulumi tls.PrivateKey ECDSA key",
  description: 'Pulumi tls.PrivateKey with algorithm "ECDSA"',
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Pulumi provisions a classical ECDSA key (tls.PrivateKey), forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_PULUMI_ED25519: RuleMeta = {
  id: "pulumi-tls-ed25519",
  title: "Pulumi tls.PrivateKey Ed25519 key",
  description: 'Pulumi tls.PrivateKey with algorithm "ED25519"',
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Pulumi provisions a classical Ed25519 key (tls.PrivateKey), forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};

const RULE_BY_ALG: Record<string, RuleMeta> = {
  RSA: RULE_PULUMI_RSA,
  ECDSA: RULE_PULUMI_ECDSA,
  ED25519: RULE_PULUMI_ED25519,
};

/** Detects classical asymmetric keys provisioned by Pulumi's tls provider. */
export const pulumiDetector: Detector = {
  id: "pulumi-crypto",
  description: "Classical asymmetric keys provisioned by Pulumi's tls provider (IaC)",
  scope: "config",
  language: "any",
  rules: [RULE_PULUMI_RSA, RULE_PULUMI_ECDSA, RULE_PULUMI_ED25519],
  appliesTo: (f) => hasExtension(f, PULUMI_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!usesPulumiTls(content)) return [];
    const findings: Finding[] = [];
    eachMatch(RE_PULUMI_TLS_ALG, content, (m) => {
      const rule = RULE_BY_ALG[m[1]];
      if (!rule) return;
      findings.push(
        findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
      );
    });
    return findings;
  },
};
