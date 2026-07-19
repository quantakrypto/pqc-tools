/**
 * Config detector: age IDENTITY (private) keys committed to disk. The secrets
 * detector flags age *recipients* (`age1…` public keys); this flags the far worse
 * case — an `AGE-SECRET-KEY-1…` private identity checked into a repo or config.
 * age identities are X25519 secret keys: a classical key-agreement secret that,
 * once leaked or committed, lets an attacker decrypt every age-wrapped payload
 * addressed to it (harvest-now-decrypt-later, and retroactively un-fixable if the
 * ciphertext is already in git history).
 *
 * The matched value IS the private key, so it is marked sensitive and reporters
 * drop the snippet.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_HARDCODED_KEY } from "../cwe.js";

// age secret keys are Bech32 in uppercase: `AGE-SECRET-KEY-1` + data part.
const RE_AGE_SECRET = /\bAGE-SECRET-KEY-1[0-9A-Z]{50,}\b/g;

const RULE_AGE_SECRET: RuleMeta = {
  id: "age-secret-key",
  title: "age identity (X25519 private key)",
  description: "An age AGE-SECRET-KEY-1 private identity key committed to disk",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_HARDCODED_KEY,
  sensitive: true,
  message:
    "An age identity (X25519 private key) is committed to disk; every age-wrapped payload addressed to it is decryptable by anyone with this key, and the exposure is retroactive if the ciphertext is already in git history.",
  remediation:
    "Rotate the age identity and re-encrypt affected data; move the private key to a secret manager. Plan for a post-quantum KEM (ML-KEM) recipient when available.",
};

/** Detects committed age identity (private) keys. */
export const ageDetector: Detector = {
  id: "age-identity",
  description: "Committed age identity (X25519 private) keys",
  scope: "config",
  language: "any",
  rules: [RULE_AGE_SECRET],
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    if (!content.includes("AGE-SECRET-KEY-1")) return [];
    const findings: Finding[] = [];
    eachMatch(RE_AGE_SECRET, content, (m) =>
      findings.push(
        findingFromRule(RULE_AGE_SECRET, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      ),
    );
    return findings;
  },
};
