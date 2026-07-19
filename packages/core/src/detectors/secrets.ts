/**
 * Config detector: secrets encrypted at rest with classical asymmetric key
 * wrapping. This is the purest "harvest now, decrypt later" surface — the
 * ciphertext is often committed to a git repository, which means it is already
 * replicated, effectively immortal, and retroactively un-fixable (you can
 * re-encrypt HEAD, not history). Every recipient key here is classical.
 *
 * Covered:
 *  - Mozilla SOPS / age recipients: `age1…` bech32 public keys (X25519 key
 *    agreement wrapping the data key).
 *  - PGP-encrypted payloads: `-----BEGIN PGP MESSAGE-----` (RSA/ElGamal ESK).
 *  - Bitnami Sealed Secrets: `kind: SealedSecret` (controller wraps with RSA-OAEP).
 *
 * Symmetric-only schemes (ansible-vault AES, age with a scrypt passphrase) are
 * intentionally NOT flagged: a strong symmetric key is only Grover-weakened, not
 * broken, so it is out of scope for a *classical-asymmetric* readiness signal.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

interface SecretRule {
  re: RegExp;
  meta: RuleMeta;
}

const SECRET_RULES: SecretRule[] = [
  {
    // age/SOPS recipient: `age1` + 58 bech32 chars. Distinctive enough for any file.
    re: /\bage1[0-9a-z]{58}\b/g,
    meta: {
      id: "secrets-age-recipient",
      title: "age / SOPS recipient (X25519)",
      description: "An age (SOPS) recipient public key wraps secrets with classical X25519",
      category: "key-exchange",
      severity: "high",
      confidence: "high",
      algorithm: "X25519",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Secrets are wrapped to an age/SOPS X25519 recipient (classical key agreement); harvest-now-decrypt-later exposed, and if committed to git the ciphertext is retroactively un-fixable.",
      remediation:
        "Track a post-quantum age recipient / KMS (ML-KEM) and re-encrypt; rotate any secret whose ciphertext has left your control.",
    },
  },
  {
    re: /-----BEGIN PGP MESSAGE-----/g,
    meta: {
      id: "secrets-pgp-message",
      title: "PGP-encrypted secret (RSA/ElGamal)",
      description: "A PGP MESSAGE block: the session key is wrapped with classical RSA/ElGamal",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "A PGP-encrypted secret whose session key is wrapped with classical RSA/ElGamal; harvest-now-decrypt-later exposed.",
      remediation:
        "Re-encrypt with a post-quantum KEM (ML-KEM-768) once available; rotate the underlying secret.",
    },
  },
  {
    re: /\bkind:\s*["']?SealedSecret\b/g,
    meta: {
      id: "secrets-sealed-secret",
      title: "Bitnami Sealed Secret (RSA-OAEP)",
      description: "A SealedSecret is wrapped by the controller's classical RSA-OAEP key",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "A Bitnami SealedSecret is wrapped with the controller's classical RSA-OAEP key; harvest-now-decrypt-later exposed, and typically committed to git.",
      remediation:
        "Plan migration as sealed-secrets adds PQC support; rotate the sealing key and secrets when it does.",
    },
  },
];

/** Detects secrets encrypted at rest with classical asymmetric key wrapping. */
export const secretsDetector: Detector = {
  id: "secrets-at-rest",
  description:
    "Secrets wrapped at rest with classical asymmetric crypto (SOPS/age, PGP, Sealed Secrets)",
  scope: "config",
  language: "any",
  rules: SECRET_RULES.map((r) => r.meta),
  // Skip prose/docs: a tutorial showing an example age recipient is not a secret store.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast reject: none of the distinctive markers present.
    if (
      !content.includes("age1") &&
      !content.includes("BEGIN PGP MESSAGE") &&
      !content.includes("SealedSecret")
    ) {
      return [];
    }
    // A commented `# kind: SealedSecret` / `# age1…` is not an active setting.
    const scan = maskCommentLines(content, ["#"]);
    const findings: Finding[] = [];
    for (const rule of SECRET_RULES) {
      eachMatch(rule.re, scan, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
