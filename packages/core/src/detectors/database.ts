/**
 * Config detector: classical crypto in database usage — public-key encryption of
 * stored data (pgcrypto) and weak client TLS posture. Data-at-rest is the sharpest
 * harvest-now-decrypt-later target: a column encrypted to an RSA key today is a
 * time capsule an adversary can hold until key recovery is cheap.
 *
 * Covered:
 *  - pgcrypto `pgp_pub_encrypt` / `pgp_pub_decrypt` in `.sql` (RSA/ElGamal public-key
 *    encryption of column data) → `hndl:true`.
 *  - libpq `sslmode = allow | prefer | require` in any config/connection file — a
 *    mode that does NOT verify the server certificate, so the classical TLS session
 *    it negotiates is both MITM-able and harvestable. `disable` is excluded: it
 *    negotiates no TLS at all, so there is no key exchange to harvest (a plaintext
 *    concern, out of scope for a PQC-readiness scanner).
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION } from "../cwe.js";

const RE_PGCRYPTO = /\bpgp_pub_(?:encrypt|decrypt)\b/g;
const RE_WEAK_SSLMODE = /\bsslmode\s*=\s*["']?(?:allow|prefer|require)\b/gi;

const RULE_PGCRYPTO: RuleMeta = {
  id: "db-pgcrypto-pubkey",
  title: "pgcrypto public-key encryption",
  description: "Postgres pgcrypto pgp_pub_encrypt / pgp_pub_decrypt (RSA/ElGamal) on stored data",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Column data is encrypted with pgcrypto public-key crypto (classical RSA/ElGamal); stored ciphertext is harvest-now-decrypt-later exposed.",
  remediation:
    "Plan migration to a post-quantum KEM (ML-KEM-768) envelope for at-rest data; re-encrypt long-lived rows.",
};
const RULE_WEAK_SSLMODE: RuleMeta = {
  id: "db-weak-sslmode",
  title: "Database sslmode without verification",
  description: "libpq sslmode is allow/prefer/require (no certificate verification)",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message:
    "Database sslmode does not verify the server certificate; the classical TLS session is MITM-able and its key exchange is harvestable.",
  remediation:
    "Use sslmode=verify-full and TLS 1.3; track PQC-hybrid KEX (X25519MLKEM768) for database transport.",
};

/** Detects classical database at-rest / transport crypto. */
export const databaseDetector: Detector = {
  id: "database-crypto",
  description: "Classical crypto in database usage (pgcrypto public-key, weak client sslmode)",
  scope: "config",
  language: "any",
  rules: [RULE_PGCRYPTO, RULE_WEAK_SSLMODE],
  // Skip prose/docs: a README showing `sslmode=require` is not a live connection string.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    // Mask SQL (`--`) and shell/ini (`#`) line comments: a commented
    // `-- pgp_pub_encrypt` or `# …sslmode=require` is not an active setting.
    const scan = maskCommentLines(content, ["#", "--"]);
    if (file.toLowerCase().endsWith(".sql") && content.includes("pgp_pub_")) {
      eachMatch(RE_PGCRYPTO, scan, (m) =>
        findings.push(
          findingFromRule(RULE_PGCRYPTO, {
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        ),
      );
    }
    if (content.includes("sslmode")) {
      eachMatch(RE_WEAK_SSLMODE, scan, (m) =>
        findings.push(
          findingFromRule(RULE_WEAK_SSLMODE, {
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        ),
      );
    }
    return findings;
  },
};
