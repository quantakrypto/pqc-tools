/**
 * Config detector: classical SSH **certificate-authority** cryptography — the
 * OpenSSH certificate mechanism, in which a CA key signs host/user certificates
 * (`*-cert-v01@openssh.com`) that servers and clients then trust in place of
 * bare public keys.
 *
 * This is DIFFERENT from the `ssh-kex-classical` rule in `source.ts`, and from
 * the `ssh-public-key` rule there — deliberately non-overlapping:
 *  - `ssh-kex-classical` is about the SSH *key-exchange* (finite-field DH, ECDH,
 *    curve25519): session-key *agreement*, `category: "key-exchange"`,
 *    `hndl: true` — a passively-recorded handshake is decryptable once a CRQC
 *    exists (harvest-now-decrypt-later confidentiality loss).
 *  - `ssh-public-key` flags bare `ssh-rsa AAAA…` / `ecdsa-sha2-* …` key lines.
 *  - THIS detector flags the SSH **certificate / CA signing** surface: the
 *    `*-cert-v01@openssh.com` cert key types, the `@cert-authority` known_hosts
 *    marker, the `TrustedUserCAKeys` / `HostCertificate` sshd directives, and
 *    `ssh-keygen -s` (the command that signs a certificate with a CA key).
 *
 * WHY it matters for PQC: an SSH certificate is a *signature* made by a CA key
 * over a principal's public key + validity constraints. There is no
 * confidentiality to harvest (so `hndl: false`), but every such signature
 * becomes FORGEABLE the moment a cryptographically-relevant quantum computer
 * (CRQC) can recover the classical CA private key from its public key. Forging a
 * CA signature lets an attacker mint host or user certificates that every relying
 * party accepts — a full trust-root compromise. SSH CA keys are also unusually
 * long-lived (they are the anchor an entire fleet trusts and are rotated
 * rarely), so the exposure window is large. Hence `category: "signature"`,
 * `severity: "medium"`, `confidence: "high"`.
 *
 * Two match shapes:
 *  1. The cert key type, which NAMES the signing algorithm → an accurate
 *     {@link AlgorithmFamily}:
 *      - `ssh-rsa-cert-v01@openssh.com`, `rsa-sha2-256/512-cert-v01@openssh.com` → RSA
 *      - `ecdsa-sha2-nistp256/384/521-cert-v01@openssh.com`                      → ECDSA
 *      - `ssh-ed25519-cert-v01@openssh.com`                                      → EdDSA
 *  2. The CA *deployment* directives — `TrustedUserCAKeys` / `HostCertificate`
 *     (sshd_config) and `ssh-keygen -s` (the CA signing command). These are the
 *     MOST COMMON way an SSH CA is configured, but they don't name the algorithm
 *     (that lives in the referenced key file), so they emit the `ssh-ca-config`
 *     rule with `algorithm: "unknown"` and `confidence: "medium"`.
 *
 * Precision:
 *  - Fast reject: `detect()` bails unless the file carries an SSH-CA marker
 *    (`cert-v01@openssh.com`, `@cert-authority`, `TrustedUserCAKeys`,
 *    `HostCertificate`, or `ssh-keygen -s`) — so the algorithm tokens can't be
 *    reached on unrelated config.
 *  - The cert-type tokens are the full `*-cert-v01@openssh.com` strings. The
 *    trailing `-cert-v01@openssh.com` suffix distinguishes a CA certificate type
 *    from the plain `ssh-rsa` / `ssh-ed25519` public-key tokens handled by
 *    `ssh-public-key`, so a non-cert `ssh-ed25519 AAAA…` line NEVER fires a cert
 *    rule here.
 *  - Comment lines (`#`) are masked with {@link maskCommentLines} (offsets
 *    preserved) so a commented-out cert line can't fire. Known_hosts
 *    `@cert-authority` lines start with `@`, not `#`, so masking leaves them
 *    live — exactly what we want.
 *  - Doc/prose files are excluded ({@link DOC_EXTENSIONS}), and so are program
 *    SOURCE files ({@link ANALYZABLE_SOURCE_EXTENSIONS}) — a vendored SSH library
 *    or constants table that spells a cert type as a string literal is not live
 *    CA config. SSH CA config lives in extensionless / `.conf` / `.pub` files.
 *
 * The matched line frequently carries the CA public key's base64 blob (a
 * `@cert-authority` known_hosts entry), so findings are marked `sensitive` and
 * reporters drop the snippet, consistent with `ssh-public-key`.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskCommentLines,
  DOC_EXTENSIONS,
  ANALYZABLE_SOURCE_EXTENSIONS,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// --- OpenSSH certificate key types (`*-cert-v01@openssh.com`), by signing family. ---
// The `\b` after `.com` is a real boundary (`m` is a word char); the leading `\b`
// keeps `ssh-rsa-cert-v01@…` from matching inside a longer token. RSA covers the
// legacy `ssh-rsa` cert type plus the SHA-2 RSA cert types (`rsa-sha2-256/512`)
// OpenSSH emits for RSA CA/host certificates.
const RE_CERT_RSA = /\b(?:ssh-rsa|rsa-sha2-(?:256|512))-cert-v01@openssh\.com\b/g;
const RE_CERT_ECDSA = /\becdsa-sha2-nistp(?:256|384|521)-cert-v01@openssh\.com\b/g;
const RE_CERT_EDDSA = /\bssh-ed25519-cert-v01@openssh\.com\b/g;
// The canonical CA *deployment* directives — the most common way an SSH CA is
// configured (sshd_config `TrustedUserCAKeys` / `HostCertificate`, and the CA
// signing command `ssh-keygen -s`). These name the CA usage but not the algorithm
// (that lives in the referenced key file), so the finding is `algorithm: "unknown"`.
const RE_CA_DIRECTIVE = /\bTrustedUserCAKeys\b|\bHostCertificate\b|\bssh-keygen\s+-s\b/g;

const REMEDIATION =
  "No post-quantum SSH certificate format is standardized yet — track OpenSSH release notes and IETF work on PQC signatures for SSH. SSH CA keys are long-lived trust roots, so plan for their rotation to a PQC signing algorithm (e.g. ML-DSA) as soon as a cert format lands, and keep validity periods short in the interim.";

const RULE_CA_RSA: RuleMeta = {
  id: "ssh-ca-rsa-cert",
  title: "SSH certificate authority — RSA signing",
  description: "OpenSSH RSA certificate key type (ssh-rsa/rsa-sha2-*-cert-v01@openssh.com)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  sensitive: true,
  message:
    "SSH certificate uses a classical RSA key type (ssh-rsa/rsa-sha2-*-cert-v01@openssh.com); the CA signature is forgeable once a CRQC can recover the RSA CA key.",
  remediation: REMEDIATION,
};
const RULE_CA_ECDSA: RuleMeta = {
  id: "ssh-ca-ecdsa-cert",
  title: "SSH certificate authority — ECDSA signing",
  description: "OpenSSH ECDSA certificate key type (ecdsa-sha2-nistp*-cert-v01@openssh.com)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  sensitive: true,
  message:
    "SSH certificate uses a classical ECDSA key type (ecdsa-sha2-nistp*-cert-v01@openssh.com); the CA signature is forgeable once a CRQC can recover the ECDSA CA key.",
  remediation: REMEDIATION,
};
const RULE_CA_EDDSA: RuleMeta = {
  id: "ssh-ca-ed25519-cert",
  title: "SSH certificate authority — EdDSA signing",
  description: "OpenSSH Ed25519 certificate key type (ssh-ed25519-cert-v01@openssh.com)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  sensitive: true,
  message:
    "SSH certificate uses a classical Ed25519 key type (ssh-ed25519-cert-v01@openssh.com); modern but still classical — the CA signature is forgeable once a CRQC can recover the Ed25519 CA key.",
  remediation: REMEDIATION,
};

const RULE_CA_CONFIG: RuleMeta = {
  id: "ssh-ca-config",
  title: "SSH certificate authority configured",
  description:
    "OpenSSH CA deployment directive (TrustedUserCAKeys / HostCertificate / ssh-keygen -s)",
  category: "signature",
  severity: "medium",
  // The directive names CA usage, not the algorithm — hence a lower confidence and
  // an unknown family; the CA key file itself carries the specific algorithm.
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "SSH certificate authority is configured (TrustedUserCAKeys / HostCertificate / ssh-keygen -s); the CA signing key is a long-lived classical trust root whose signatures become forgeable once a CRQC exists — verify the CA key's algorithm.",
  remediation: REMEDIATION,
};

interface SshCaRule {
  meta: RuleMeta;
  re: RegExp;
}

const SSH_CA_RULES: readonly SshCaRule[] = [
  { meta: RULE_CA_RSA, re: RE_CERT_RSA },
  { meta: RULE_CA_ECDSA, re: RE_CERT_ECDSA },
  { meta: RULE_CA_EDDSA, re: RE_CERT_EDDSA },
  { meta: RULE_CA_CONFIG, re: RE_CA_DIRECTIVE },
];

/** True when `content` carries some SSH-CA-specific marker (not just a bare token). */
function hasSshCaMarker(content: string): boolean {
  return (
    content.includes("cert-v01@openssh.com") ||
    content.includes("@cert-authority") ||
    content.includes("TrustedUserCAKeys") ||
    content.includes("HostCertificate") ||
    content.includes("ssh-keygen -s")
  );
}

/**
 * Detects classical SSH certificate-authority signing (OpenSSH cert key types)
 * in SSH config, sshd_config, and known_hosts files. Distinct from SSH
 * key-exchange (`ssh-kex-classical`): this is the certificate SIGNATURE surface.
 */
export const sshCaDetector: Detector = {
  id: "ssh-ca",
  description: "Classical SSH certificate-authority signing (OpenSSH *-cert-v01@openssh.com)",
  scope: "config",
  language: "any",
  rules: SSH_CA_RULES.map((r) => r.meta),
  // Apply broadly (SSH CA config lives in many differently-named / extensionless
  // files: sshd_config, known_hosts, *.pub) but never on prose/docs OR on program
  // SOURCE files — a vendored SSH library or a constants table that spells out
  // `ssh-ed25519-cert-v01@openssh.com` as a string literal is not a live CA config.
  // The strict fast-reject in detect() is the remaining gate.
  appliesTo: (f) =>
    !hasExtension(f, DOC_EXTENSIONS) && !hasExtension(f, ANALYZABLE_SOURCE_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!hasSshCaMarker(content)) return [];

    // Mask `#` comment lines so a commented-out cert line can't fire; offsets are
    // preserved. `@cert-authority` known_hosts lines start with `@`, not `#`, so
    // they are intentionally left live.
    const scan = maskCommentLines(content, ["#"]);
    const findings: Finding[] = [];
    for (const { meta, re } of SSH_CA_RULES) {
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(meta, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    }
    return findings;
  },
};
