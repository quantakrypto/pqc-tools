/**
 * Config detector: classical supply-chain / artifact signing beyond the cosign +
 * GPG cases the `cicd` detector covers — Docker Content Trust (Notary v1 / TUF),
 * CNCF Notation, and in-toto. These sign container images, OCI artifacts, and
 * build provenance with classical keys (ECDSA / RSA / Ed25519). Like all signing,
 * this is the signature-side analogue of harvest-now-decrypt-later: a signature
 * produced today is forgeable once a CRQC exists, and the signed artifact keeps
 * verifying against that classical key for years — so these are `hndl:false` but
 * real quantum-migration debt.
 *
 * Gated to CI pipeline files, Dockerfiles, and shell scripts, over comment-masked
 * content, and keyed on distinctive command/env tokens to keep false positives low.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, maskCommentLines } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/** CI pipeline files, Dockerfiles, and shell scripts — where signing runs. */
function isSigningContext(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  const base = lower.split("/").pop() ?? lower;
  return (
    (lower.includes(".github/workflows/") && (lower.endsWith(".yml") || lower.endsWith(".yaml"))) ||
    base === ".gitlab-ci.yml" ||
    lower.endsWith(".gitlab-ci.yml") ||
    base === "jenkinsfile" ||
    lower.endsWith(".jenkinsfile") ||
    base === "dockerfile" ||
    base.startsWith("dockerfile.") ||
    lower.endsWith(".dockerfile") ||
    lower.endsWith(".sh") ||
    lower.endsWith(".bash")
  );
}

interface ScRule {
  re: RegExp;
  meta: RuleMeta;
}

const SC_RULES: ScRule[] = [
  {
    re: /\bDOCKER_CONTENT_TRUST\s*[:=]\s*["']?1\b|\bdocker\s+trust\s+sign\b/g,
    meta: {
      id: "sc-docker-content-trust",
      title: "Docker Content Trust signing (Notary v1)",
      description: "Docker Content Trust / docker trust sign — Notary v1 (TUF) classical keys",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Docker Content Trust signs images with Notary v1 (TUF) classical keys (ECDSA/Ed25519); signatures are forgeable once a CRQC exists.",
      remediation: "Track sigstore/Notary v2 (Notation) PQC roadmap; plan hybrid image signing.",
    },
  },
  {
    re: /\bnotation\s+(?:sign|key\s+generate|cert\s+generate)\b/g,
    meta: {
      id: "sc-notation-sign",
      title: "Notation artifact signing",
      description: "CNCF Notation signing of OCI artifacts with classical keys",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Notation signs OCI artifacts with a classical key (RSA/ECDSA); signatures are forgeable once a CRQC exists.",
      remediation: "Track Notation's PQC signature support (ML-DSA) and plan migration.",
    },
  },
  {
    re: /\bin[-_]toto[-_]?run\b|\bin-toto\b/g,
    meta: {
      id: "sc-in-toto",
      title: "in-toto supply-chain signing",
      description: "in-toto build provenance signed with classical keys",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "in-toto signs build provenance with a classical key (RSA/Ed25519); the attestation is forgeable once a CRQC exists.",
      remediation: "Track in-toto/DSSE PQC signature support and plan migration.",
    },
  },
];

/** Detects classical Docker Content Trust / Notation / in-toto signing. */
export const supplyChainDetector: Detector = {
  id: "supply-chain-signing",
  description: "Classical container/artifact signing (Docker Content Trust, Notation, in-toto)",
  scope: "config",
  language: "any",
  rules: SC_RULES.map((r) => r.meta),
  appliesTo: isSigningContext,
  detect({ file, content }): Finding[] {
    // `#` covers YAML/Dockerfile/shell; `//` covers Jenkinsfile (Groovy), which has no
    // extension so it is never centrally comment-stripped.
    const scan = maskCommentLines(content, ["#", "//"]);
    const findings: Finding[] = [];
    for (const rule of SC_RULES) {
      eachMatch(rule.re, scan, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
