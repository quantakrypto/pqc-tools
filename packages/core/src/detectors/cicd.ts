/**
 * Config detector: classical signing of build artifacts and code in CI/CD
 * pipelines (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI).
 *
 * Artifact and code signatures are the signature-side analogue of "harvest now,
 * decrypt later": a release signed today with a classical key is *forgeable* once
 * a CRQC exists, and long-lived artifacts (container images, released binaries,
 * SBOM attestations) keep verifying against that classical public key for years.
 * So these are flagged `hndl:false` (a signature is not confidentiality — nothing
 * to harvest) but remain real quantum-migration debt.
 *
 * Covered command invocations (distinctive enough inside a CI file that the
 * false-positive risk is low):
 *  - `cosign sign|attest|generate-key-pair`  → sigstore/cosign uses ECDSA P-256
 *    (both key-based and keyless/Fulcio).
 *  - `gpg --detach-sign|--clearsign|--sign`   → GnuPG, classically RSA.
 *  - `jarsigner`                              → Java JAR signing (RSA/DSA/EC).
 *  - `codesign --sign|-s`                     → Apple code signing (RSA).
 *  - `minisign`                               → Ed25519 signatures.
 *
 * Gated to CI/CD pipeline files so `gpg`/`cosign` mentioned in a shell script or
 * doc does not fire; the surface here is specifically the release pipeline.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, maskCommentLines } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/** True for the CI/CD pipeline definition files this detector inspects. */
function isCiPipelineFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  const base = lower.split("/").pop() ?? lower;
  return (
    (lower.includes(".github/workflows/") && (lower.endsWith(".yml") || lower.endsWith(".yaml"))) ||
    base === ".gitlab-ci.yml" ||
    lower.endsWith(".gitlab-ci.yml") ||
    base === "jenkinsfile" ||
    lower.endsWith(".jenkinsfile") ||
    base === "azure-pipelines.yml" ||
    base === "azure-pipelines.yaml" ||
    (lower.includes(".circleci/") && (lower.endsWith(".yml") || lower.endsWith(".yaml")))
  );
}

interface CiRule {
  re: RegExp;
  meta: RuleMeta;
}

const CI_RULES: CiRule[] = [
  {
    // `sign-blob` precedes `sign` so the longer subcommand wins — otherwise `sign`
    // matches first and the trailing `\b` succeeds at the `-`, never reaching `sign-blob`.
    re: /\bcosign\s+(?:sign-blob|sign|attest|generate-key-pair)\b/g,
    meta: {
      id: "ci-cosign-ecdsa",
      title: "cosign artifact signing (ECDSA)",
      description: "sigstore/cosign signing in a CI pipeline",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "CI pipeline signs artifacts with cosign (ECDSA P-256, key-based or keyless/Fulcio); classical signatures are forgeable once a CRQC exists.",
      remediation:
        "Track sigstore's post-quantum signing roadmap (ML-DSA); plan hybrid signing for long-lived release artifacts.",
    },
  },
  {
    // Bound the span to the gpg invocation ([^\n&|;] stops it crossing `&&`/`|`/`;`
    // into another command's flag), and `(?![\w-])` stops `--sign` matching the
    // `--sign` prefix of an unrelated flag like `--sign-artifacts`. The short forms
    // `-s` (sign) / `-b` (detach-sign) are safe inside the bounded gpg span.
    re: /\bgpg\b[^\n&|;]{0,120}?\s(?:-[sb]\b|--(?:detach-sign|clearsign|sign)(?![\w-]))/g,
    meta: {
      id: "ci-gpg-sign",
      title: "GPG signing (RSA)",
      description: "GnuPG detached/clear signing in a CI pipeline",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "CI pipeline signs with GPG, classically an RSA signing key; forgeable once a CRQC exists.",
      remediation: "Plan migration to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) signatures.",
    },
  },
  {
    re: /\bjarsigner\b/g,
    meta: {
      id: "ci-jarsigner",
      title: "Java jarsigner (classical)",
      description: "JDK jarsigner code signing in a CI pipeline",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "CI pipeline signs JARs with jarsigner (classical RSA/DSA/EC signing key); forgeable once a CRQC exists.",
      remediation:
        "Plan migration to a PQC signature scheme (ML-DSA-65 / SLH-DSA) as the JDK adds support.",
    },
  },
  {
    // Allow intervening flags (the common `codesign --force --options runtime --sign`
    // form), bounded to the codesign invocation so it can't latch onto a later
    // command's `--sign` across `&&`/`|`/`;`.
    re: /\bcodesign\b[^\n&|;]{0,120}?\s(?:-s\b|--sign\b)/g,
    meta: {
      id: "ci-codesign",
      title: "Apple codesign (RSA)",
      description: "Apple codesign in a CI pipeline",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "CI pipeline signs with Apple codesign (classical RSA signing identity); forgeable once a CRQC exists.",
      remediation: "Classical only today; track Apple's PQC signing support and plan migration.",
    },
  },
  {
    re: /\bminisign\b/g,
    meta: {
      id: "ci-minisign",
      title: "minisign (Ed25519)",
      description: "minisign signing in a CI pipeline",
      category: "signature",
      severity: "low",
      confidence: "high",
      algorithm: "EdDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "CI pipeline signs with minisign (Ed25519); modern but classical and forgeable once a CRQC exists.",
      remediation: "Plan migration to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
    },
  },
];

/** Detects classical artifact / code signing in CI/CD pipeline definitions. */
export const cicdDetector: Detector = {
  id: "cicd-signing",
  description: "Classical artifact / code signing in CI/CD pipelines",
  scope: "config",
  language: "any",
  rules: CI_RULES.map((r) => r.meta),
  appliesTo: isCiPipelineFile,
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    // A commented-out CI step (`# - run: cosign sign …`, or a `//` line in a
    // Jenkinsfile) is not an active signing step. Mask comment lines first; offsets
    // are preserved so the snippet from the original `content` stays correct.
    const scan = maskCommentLines(content, ["#", "//"]);
    for (const rule of CI_RULES) {
      eachMatch(rule.re, scan, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
