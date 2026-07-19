/**
 * Config detector: BINARY OpenPGP key material and encrypted messages committed to
 * a repository — `secring.gpg` / `pubring.gpg` / `.gpg` / `.pgp` / `.kbx`. Armored
 * blocks (`-----BEGIN PGP …-----`, base64 text) are handled by the PEM/secrets
 * detectors; this covers the BINARY packet form, which the scan pipeline now reads
 * byte-preserving (latin1; see {@link ../walk.ts isKeystorePath}) so we can read
 * packet tags and the public-key algorithm id.
 *
 * A committed OpenPGP SECRET key is the sharp finding: a classical private key
 * (RSA/DSA/ElGamal/ECDSA/EdDSA/ECDH) in version control is exposed and
 * retroactively un-fixable. A binary PGP-encrypted message (PKESK) is
 * harvest-now-decrypt-later exposed. Secret-key matches are sensitive material, so
 * reporters drop the (binary) snippet.
 *
 * Packet framing per RFC 4880/9580. The parser is pure and bounds-checked (fuzzed).
 */
import type { AlgorithmFamily, Detector, Finding, RuleMeta } from "../types.js";
import { findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_HARDCODED_KEY, CWE_BROKEN_CRYPTO } from "../cwe.js";

const OPENPGP_EXTENSIONS: readonly string[] = [".gpg", ".pgp"];

// Packet tags we care about.
const TAG_PKESK = 1; // public-key encrypted session key (an encrypted message)
const TAG_SECRET_KEY = 5;
const TAG_PUBLIC_KEY = 6;
const TAG_SECRET_SUBKEY = 7;
const TAG_PUBLIC_SUBKEY = 14;

interface Packet {
  tag: number;
  /** Offset where the packet body begins (after the length octets). */
  bodyOffset: number;
}

/** Parse the FIRST OpenPGP packet header; return its tag and body offset. */
export function firstPacket(content: string): Packet | undefined {
  if (content.length < 2) return undefined;
  const b0 = content.charCodeAt(0);
  if ((b0 & 0x80) === 0) return undefined; // high bit always set on a packet tag
  if (b0 & 0x40) {
    // New-format packet: tag is the low 6 bits; length octet(s) follow.
    const tag = b0 & 0x3f;
    const l = content.charCodeAt(1);
    let bodyOffset: number;
    if (l < 192) bodyOffset = 2;
    else if (l < 224) bodyOffset = 3;
    else if (l === 255) bodyOffset = 6;
    else bodyOffset = 2; // partial-body length
    return { tag, bodyOffset };
  }
  // Old-format packet: tag in bits 5-2; length-type in the low 2 bits.
  const tag = (b0 >> 2) & 0x0f;
  const lt = b0 & 0x03;
  const bodyOffset = lt === 0 ? 2 : lt === 1 ? 3 : lt === 2 ? 5 : 1;
  return { tag, bodyOffset };
}

/** Map an OpenPGP public-key algorithm id to a family + HNDL (confidentiality) flag. */
function algo(id: number): { family: AlgorithmFamily; hndl: boolean } | undefined {
  switch (id) {
    case 1:
    case 2:
    case 3:
      return { family: "RSA", hndl: true }; // RSA (encrypt-capable)
    case 16:
    case 20:
      return { family: "unknown", hndl: true }; // ElGamal (encrypt)
    case 17:
      return { family: "DSA", hndl: false }; // DSA (sign only)
    case 18:
      return { family: "ECDH", hndl: true }; // ECDH (encrypt)
    case 19:
      return { family: "ECDSA", hndl: false }; // ECDSA (sign only)
    case 22:
      return { family: "EdDSA", hndl: false }; // EdDSA (sign only)
    default:
      return undefined;
  }
}

/** Read the public-key algorithm id from a key packet body, or undefined. */
function keyPacketAlgo(content: string, bodyOffset: number): number | undefined {
  if (bodyOffset >= content.length) return undefined;
  const version = content.charCodeAt(bodyOffset);
  // v2/v3: version(1) created(4) validity(2) algo; v4/v5/v6: version(1) created(4) algo.
  const algoOffset = version === 2 || version === 3 ? bodyOffset + 7 : bodyOffset + 5;
  if (algoOffset >= content.length) return undefined;
  return content.charCodeAt(algoOffset);
}

/** Read the wrapping algorithm from a PKESK (encrypted-message) packet body. */
function pkeskAlgo(content: string, bodyOffset: number): number | undefined {
  if (bodyOffset >= content.length) return undefined;
  const version = content.charCodeAt(bodyOffset);
  // v3: version(1) keyid(8) algo. (v6 differs; v3 dominates on-disk.)
  if (version !== 3) return undefined;
  const algoOffset = bodyOffset + 9;
  if (algoOffset >= content.length) return undefined;
  return content.charCodeAt(algoOffset);
}

function rule(id: string, title: string, message: string, opts: Partial<RuleMeta>): RuleMeta {
  return {
    id,
    title,
    description: message,
    category: "certificate",
    severity: "high",
    confidence: "high",
    hndl: false,
    cwe: CWE_HARDCODED_KEY,
    message,
    remediation:
      "Remove key material from version control and rotate it; store keys in a secret manager / HSM. Plan re-issuance with PQC keys (ML-DSA-65 / ML-KEM-768) as OpenPGP tooling supports them.",
    ...opts,
  };
}

const RULE_SECRET = rule(
  "openpgp-secret-key",
  "OpenPGP secret key (binary)",
  "A binary OpenPGP SECRET key is committed to version control — a classical private key that is exposed and retroactively un-fixable.",
  { sensitive: true },
);
const RULE_PUBLIC = rule(
  "openpgp-public-key",
  "OpenPGP public key (binary)",
  "A binary OpenPGP public key uses classical asymmetric crypto (RSA/DSA/EC); plan a PQC migration path.",
  { severity: "medium" },
);
const RULE_PKESK = rule(
  "openpgp-encrypted-message",
  "OpenPGP-encrypted message (binary)",
  "A binary OpenPGP-encrypted message wraps its session key with classical asymmetric crypto (RSA/ElGamal/ECDH); harvest-now-decrypt-later exposed.",
  { category: "kem", hndl: true, cwe: CWE_BROKEN_CRYPTO },
);
const RULE_KEYBOX = rule(
  "openpgp-keybox",
  "GnuPG keybox (.kbx)",
  "A GnuPG keybox (.kbx) is a database of classical OpenPGP/X.509 keys and certificates.",
  { severity: "medium", cwe: CWE_BROKEN_CRYPTO },
);

/** Detects binary OpenPGP key material / messages and GnuPG keyboxes. */
export const openpgpDetector: Detector = {
  id: "openpgp-material",
  description: "Binary OpenPGP key material / encrypted messages and GnuPG keyboxes",
  scope: "config",
  language: "any",
  rules: [RULE_SECRET, RULE_PUBLIC, RULE_PKESK, RULE_KEYBOX],
  appliesTo: (f) => hasExtension(f, OPENPGP_EXTENSIONS) || f.toLowerCase().endsWith(".kbx"),
  detect({ file, content }): Finding[] {
    const at = { file, content, index: 0, matchLength: Math.min(4, content.length) };

    // GnuPG keybox: a key/cert database, identified by the "KBXf" magic in its
    // first blob header (so a garbage/empty .kbx does not fire).
    if (file.toLowerCase().endsWith(".kbx")) {
      return content.includes("KBXf") ? [findingFromRule(RULE_KEYBOX, at)] : [];
    }

    const pkt = firstPacket(content);
    if (!pkt) return [];
    const { tag, bodyOffset } = pkt;

    if (tag === TAG_SECRET_KEY || tag === TAG_SECRET_SUBKEY) {
      const id = keyPacketAlgo(content, bodyOffset);
      const a = id !== undefined ? algo(id) : undefined;
      return [
        findingFromRule(RULE_SECRET, at, a ? { algorithm: a.family, hndl: a.hndl } : undefined),
      ];
    }
    if (tag === TAG_PUBLIC_KEY || tag === TAG_PUBLIC_SUBKEY) {
      const id = keyPacketAlgo(content, bodyOffset);
      const a = id !== undefined ? algo(id) : undefined;
      return [findingFromRule(RULE_PUBLIC, at, a ? { algorithm: a.family } : undefined)];
    }
    if (tag === TAG_PKESK) {
      const id = pkeskAlgo(content, bodyOffset);
      const a = id !== undefined ? algo(id) : undefined;
      return [findingFromRule(RULE_PKESK, at, a ? { algorithm: a.family } : undefined)];
    }
    return [];
  },
};
