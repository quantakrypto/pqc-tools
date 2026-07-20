/**
 * Config detector: classical DKIM email-signing keys and algorithms in DNS
 * zone files, mail-server signer config (OpenDKIM), and captured
 * `DKIM-Signature:` header fields (RFC 6376 + RFC 8463).
 *
 * DKIM (DomainKeys Identified Mail) authenticates the *origin* of email: the
 * sending MTA signs selected header/body content with a private key, publishes
 * the matching public key as a DNS TXT record at
 * `<selector>._domainkey.<domain>`, and receivers verify the `DKIM-Signature`
 * header against that published key. Like DNSSEC (see `dnssec.ts`), this is a
 * pure *signature* surface: there is no confidentiality to harvest, so a DKIM
 * key is NOT harvest-now-decrypt-later exposed (`hndl: false`). What breaks
 * once a cryptographically-relevant quantum computer (CRQC) exists is
 * unforgeability — an attacker who can derive the private key from the
 * published public key can mint valid `DKIM-Signature` headers and spoof mail
 * that passes DKIM/DMARC. So these findings are `category: "signature"`.
 *
 * Crypto surface, mapped to {@link AlgorithmFamily}:
 *  - `k=rsa` DNS key-type tag / `a=rsa-sha256` / `a=rsa-sha1` (DKIM-Signature
 *    algorithm tag) / OpenDKIM `SigningAlgorithm rsa-sha256|rsa-sha1`   → RSA
 *  - `k=ed25519` DNS key-type tag / `a=ed25519-sha256` / OpenDKIM
 *    `SigningAlgorithm ed25519-sha256` (RFC 8463)                        → EdDSA
 *
 * Ed25519 DKIM (RFC 8463) is MODERN but still CLASSICAL: rotating an RSA DKIM
 * key to Ed25519 shrinks the DNS record and is good hygiene, but it is NOT a
 * post-quantum fix — an Ed25519 signature is just as forgeable under a CRQC.
 * The remediation text says so honestly: there is no standardized PQC DKIM yet;
 * the only real action is to track IETF work.
 *
 * Two match shapes are covered per family, both gated to a small config
 * extension set AND to a file-level DKIM marker (see `hasDkimMarker`) so the
 * short tag tokens (`k=rsa`, `a=rsa-sha256`) can't fire on unrelated config:
 *
 *  1. DNS KEY-TYPE tag — `k=rsa` / `k=ed25519` inside a published DKIM TXT
 *     record (`v=DKIM1; k=rsa; p=MIGf...`). Whitespace around `=` is tolerated.
 *  2. SIGNING-ALGORITHM tag — the `a=` tag of a `DKIM-Signature` header
 *     (`a=rsa-sha256`, `a=ed25519-sha256`) and the OpenDKIM `SigningAlgorithm`
 *     directive (`SigningAlgorithm rsa-sha256`). The RSA variant deliberately
 *     also matches the legacy `rsa-sha1`.
 *
 * Fast reject: `detect()` bails unless the file carries a DKIM-specific marker
 * (`v=DKIM1`, `_domainkey`, a `DKIM-Signature` field, an OpenDKIM
 * `SigningAlgorithm` directive, or a bare `k=rsa`/`k=ed25519` key-type tag).
 * This stops the generic-looking `k=rsa` / `a=rsa-sha256` tokens from firing on
 * an unrelated `.conf` that happens to contain an `a=`/`k=` assignment for its
 * own reasons. Prose is excluded twice over: `appliesTo` restricts to config
 * extensions (README/`.md` never applies), and `detect()` re-guards against
 * {@link DOC_EXTENSIONS} defensively so a docs file that slipped through a
 * broader gate could never be flagged for mentioning `k=rsa` in a sentence.
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

// DKIM records live in DNS zone files (`.zone`/`.db`), mail-server signer config
// (`.conf`), and captured header/TXT fixtures (`.txt`). Gated further by
// `hasDkimMarker` so the short tag tokens can't fire on unrelated config.
const DKIM_EXTENSIONS: readonly string[] = [".zone", ".db", ".conf", ".txt"];

// --- RSA (k=rsa / rsa-sha256 / rsa-sha1) ---
// DNS key-type tag: `k=rsa` in a published DKIM TXT record. Whitespace tolerated
// around `=`; case-insensitive since tags are conventionally lowercase but not
// required to be. `\b` after `rsa` keeps it from matching `rsa-...` substrings.
const RE_RSA_KEYTAG = /\bk\s*=\s*rsa\b/gi;
// DKIM-Signature `a=` tag: `a=rsa-sha256` / `a=rsa-sha1`.
const RE_RSA_ALGTAG = /\ba\s*=\s*rsa-sha(?:256|1)\b/gi;
// OpenDKIM signer directive: `SigningAlgorithm rsa-sha256` / `rsa-sha1`.
const RE_RSA_OPENDKIM = /\bSigningAlgorithm\s+rsa-sha(?:256|1)\b/gi;

// --- EdDSA (k=ed25519 / ed25519-sha256, RFC 8463) ---
const RE_EDDSA_KEYTAG = /\bk\s*=\s*ed25519\b/gi;
const RE_EDDSA_ALGTAG = /\ba\s*=\s*ed25519-sha256\b/gi;
const RE_EDDSA_OPENDKIM = /\bSigningAlgorithm\s+ed25519-sha256\b/gi;

const RULE_DKIM_RSA: RuleMeta = {
  id: "dkim-rsa-key",
  title: "DKIM RSA signing key/algorithm",
  description:
    "DKIM email signing configured with a classical RSA key/algorithm (k=rsa, a=rsa-sha256/rsa-sha1)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DKIM email signing uses a classical RSA key/algorithm (k=rsa / rsa-sha256 / rsa-sha1); DKIM-Signature headers become forgeable once a CRQC exists, allowing DKIM/DMARC-passing spoofed mail.",
  remediation:
    "There is no standardized post-quantum DKIM algorithm yet — track IETF work; note that rotating RSA to Ed25519 (RFC 8463) is good hygiene but NOT a PQC fix, since Ed25519 is still classical and equally forgeable under a CRQC.",
};

const RULE_DKIM_EDDSA: RuleMeta = {
  id: "dkim-ed25519-key",
  title: "DKIM Ed25519 signing key/algorithm",
  description:
    "DKIM email signing configured with a classical Ed25519 key/algorithm (k=ed25519, a=ed25519-sha256, RFC 8463)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DKIM email signing uses an Ed25519 key/algorithm (k=ed25519 / ed25519-sha256, RFC 8463) — modern but still classical; DKIM-Signature headers become forgeable once a CRQC exists.",
  remediation:
    "There is no standardized post-quantum DKIM algorithm yet — track IETF work. Ed25519 is already the smaller/modern DKIM choice but is NOT post-quantum: it stays forgeable under a CRQC, so no rotation today resolves the quantum exposure.",
};

/** True when `content` carries a DKIM-specific marker (not just a bare tag token). */
function hasDkimMarker(content: string): boolean {
  return (
    /\bDKIM1\b/i.test(content) ||
    content.includes("_domainkey") ||
    /DKIM-Signature/i.test(content) ||
    /\bSigningAlgorithm\b/i.test(content) ||
    /\bk\s*=\s*(?:rsa|ed25519)\b/i.test(content)
  );
}

interface DkimRule {
  meta: RuleMeta;
  res: readonly RegExp[];
}

const DKIM_RULES: readonly DkimRule[] = [
  { meta: RULE_DKIM_RSA, res: [RE_RSA_KEYTAG, RE_RSA_ALGTAG, RE_RSA_OPENDKIM] },
  { meta: RULE_DKIM_EDDSA, res: [RE_EDDSA_KEYTAG, RE_EDDSA_ALGTAG, RE_EDDSA_OPENDKIM] },
];

/** Detects classical DKIM signing keys/algorithms in zone files and mail signer config. */
export const dkimDetector: Detector = {
  id: "dkim-crypto",
  description: "Classical DKIM email signing keys/algorithms in zone files / mail signer config",
  scope: "config",
  language: "any",
  rules: DKIM_RULES.map((r) => r.meta),
  appliesTo: (f) => hasExtension(f, DKIM_EXTENSIONS) && !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Defensive doc guard: even if a broader gate ever let a prose file through,
    // a README mentioning `k=rsa` in a sentence must never be flagged.
    if (hasExtension(file, DOC_EXTENSIONS)) return [];
    if (!hasDkimMarker(content)) return [];

    // Mask whole comment lines so a commented-out record can't fire: zone files
    // use `;`, mail/OpenDKIM config uses `#` and `//`. Offsets are preserved so
    // finding line/column/snippet stay exact for the live lines that remain.
    const scan = maskCommentLines(content, [";", "#", "//"]);
    const findings: Finding[] = [];
    for (const { meta, res } of DKIM_RULES) {
      for (const re of res) {
        eachMatch(re, scan, (m) =>
          findings.push(
            findingFromRule(meta, { file, content, index: m.index, matchLength: m[0].length }),
          ),
        );
      }
    }
    return findings;
  },
};
