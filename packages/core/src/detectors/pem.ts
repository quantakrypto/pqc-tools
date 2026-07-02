/**
 * Config / certificate detector: finds PEM-encoded cryptographic material in
 * any text file (source, config, .pem, .key, .crt, .env, …). This catches
 * embedded private keys and X.509 certificates regardless of language.
 *
 * Every rule's metadata lives in the {@link RuleMeta} declaration below (the
 * catalog entry); `detect()` builds findings straight from it via
 * `findingFromRule`. All PEM findings are high-confidence exact-marker matches.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_HARDCODED_KEY } from "../cwe.js";

/** A PEM rule: its catalog metadata plus the begin-marker regex that triggers it. */
interface PemRule {
  /** Regex matching the PEM begin marker. */
  re: RegExp;
  meta: RuleMeta;
}

const PEM_RULES: PemRule[] = [
  {
    re: /-----BEGIN RSA PRIVATE KEY-----/g,
    meta: {
      id: "pem-rsa-private-key",
      title: "RSA private key (PEM)",
      description: "PKCS#1 RSA private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded RSA private key (PKCS#1 PEM); classical and not quantum-safe.",
      remediation: "Migrate to ML-DSA / ML-KEM keys and remove embedded private keys from source.",
    },
  },
  {
    re: /-----BEGIN EC PRIVATE KEY-----/g,
    meta: {
      id: "pem-ec-private-key",
      title: "EC private key (PEM)",
      description: "SEC1 EC private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded EC private key (SEC1 PEM); classical ECDSA/ECDH key, not quantum-safe.",
      remediation:
        "Migrate to ML-DSA (FIPS 204) keys and remove embedded private keys from source.",
    },
  },
  {
    re: /-----BEGIN DSA PRIVATE KEY-----/g,
    meta: {
      id: "pem-dsa-private-key",
      title: "DSA private key (PEM)",
      description: "DSA private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "DSA",
      hndl: false,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message:
        "Embedded DSA private key (PEM); classical, already deprecated, and not quantum-safe.",
      remediation: "Rotate immediately (DSA is deprecated) and migrate to ML-DSA-65 (FIPS 204).",
    },
  },
  {
    re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    meta: {
      id: "pem-openssh-private-key",
      title: "OpenSSH private key",
      description: "OpenSSH private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded OpenSSH private key (RSA/ECDSA/Ed25519); classical and not quantum-safe.",
      remediation: "Rotate the key; plan migration to PQC-capable SSH (e.g. sntrup761x25519).",
    },
  },
  {
    re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    meta: {
      id: "pem-pgp-private-key",
      title: "PGP/GPG private key block",
      description: "OpenPGP private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message:
        "Embedded PGP/GPG private key block (RSA/ECDSA/EdDSA/ElGamal); classical and not quantum-safe.",
      remediation: "Rotate the key; track OpenPGP PQC drafts for migration.",
    },
  },
  {
    re: /-----BEGIN PGP MESSAGE-----/g,
    meta: {
      id: "pem-pgp-message",
      title: "PGP/GPG encrypted message",
      description: "OpenPGP encrypted message block",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Embedded PGP/GPG message; likely encrypted with classical RSA/ElGamal (harvest-now-decrypt-later).",
      remediation: "Re-encrypt with PQC-capable tooling as OpenPGP PQC profiles mature.",
    },
  },
  {
    re: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/g,
    meta: {
      id: "pem-pkcs8-private-key",
      title: "Private key (PKCS#8 PEM)",
      description: "PKCS#8 private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded PKCS#8 private key; likely classical RSA/EC, not quantum-safe.",
      remediation: "Migrate to PQC keys and remove embedded private keys from source.",
    },
  },
  {
    re: /-----BEGIN CERTIFICATE-----/g,
    meta: {
      id: "pem-certificate",
      title: "X.509 certificate (PEM)",
      description: "X.509 certificate block",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "Embedded X.509 certificate; almost certainly signed with classical RSA/ECDSA.",
      remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature.",
    },
  },
];

/** Detects PEM key/certificate material in arbitrary files. */
export const pemDetector: Detector = {
  id: "pem-material",
  description: "PEM-encoded private keys and X.509 certificates in any file",
  scope: "config",
  language: "any",
  rules: PEM_RULES.map((r) => r.meta),
  // Applies to every text file; the walker already filters out binaries.
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    // Fast reject: only proceed if a PEM header is present at all.
    if (!content.includes("-----BEGIN ")) return [];

    const findings: Finding[] = [];
    for (const rule of PEM_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(
          findingFromRule(rule.meta, {
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        );
      });
    }
    return findings;
  },
};
