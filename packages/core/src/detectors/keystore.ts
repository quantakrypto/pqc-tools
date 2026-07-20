/**
 * Config detector: classical cryptographic KEYSTORES committed to a repository —
 * Java KeyStore (JKS), JCEKS, PKCS#12 (.p12/.pfx), and BouncyCastle (.bks). These
 * binary containers hold private keys and certificate chains, essentially always
 * classical (RSA / EC / DSA). A keystore in version control is committed key
 * material: harvest-now-decrypt-later exposed and retroactively un-fixable.
 *
 * The scan pipeline reads these extensions byte-preserving (latin1; see
 * {@link ../walk.ts isKeystorePath} and scan.ts), so `content.charCodeAt(i)` is the
 * i-th file byte and we can identify the container by its magic number. We do NOT
 * parse the enclosed key algorithm (that needs full ASN.1 / proprietary parsing);
 * flagging the presence of a classical keystore is the actionable signal.
 *
 * The match is sensitive key material, so reporters drop the (binary) snippet.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_HARDCODED_KEY } from "../cwe.js";

const KEYSTORE_EXTENSIONS: readonly string[] = [
  ".jks",
  ".keystore",
  ".jceks",
  ".bks",
  ".p12",
  ".pfx",
];

function baseRule(id: string, title: string, message: string): RuleMeta {
  return {
    id,
    title,
    description: message,
    category: "certificate",
    severity: "high",
    confidence: "high",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    sensitive: true,
    message,
    remediation:
      "Remove key material from version control and rotate it; store keys in a secret manager / HSM. Plan re-issuance with PQC keys (ML-DSA-65 / ML-KEM-768) as tooling supports it.",
  };
}

const RULE_JKS = baseRule(
  "keystore-jks",
  "Java KeyStore (JKS)",
  "A Java KeyStore (JKS) holds classical private keys / certificates (RSA/EC/DSA); a keystore in version control is committed, harvest-now-decrypt-later exposed key material.",
);
const RULE_JCEKS = baseRule(
  "keystore-jceks",
  "Java JCEKS keystore",
  "A JCEKS keystore holds classical key material (RSA/EC/DSA); committed to version control it is harvest-now-decrypt-later exposed.",
);
const RULE_PKCS12 = baseRule(
  "keystore-pkcs12",
  "PKCS#12 keystore",
  "A PKCS#12 container (a `.p12`/`.pfx`, or a modern `.jks`/`.keystore` — keytool writes PKCS#12 by default since Java 9) holds classical private keys / certificate chains (RSA/EC); committed to version control it is harvest-now-decrypt-later exposed.",
);
const RULE_BKS = baseRule(
  "keystore-bks",
  "BouncyCastle keystore (.bks)",
  "A BouncyCastle (.bks) keystore holds classical key material; committed to version control it is harvest-now-decrypt-later exposed.",
);

/** Bytes-equal check against `content` read as latin1 (charCodeAt == file byte). */
function magic(content: string, ...bytes: number[]): boolean {
  if (content.length < bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (content.charCodeAt(i) !== bytes[i]) return false;
  }
  return true;
}

/** Detects committed classical keystores by magic number / extension. */
export const keystoreDetector: Detector = {
  id: "keystore-material",
  description: "Committed classical cryptographic keystores (JKS, JCEKS, PKCS#12, BKS)",
  scope: "config",
  language: "any",
  rules: [RULE_JKS, RULE_JCEKS, RULE_PKCS12, RULE_BKS],
  appliesTo: (f) => hasExtension(f, KEYSTORE_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const at = { file, content, index: 0, matchLength: 4 };
    // JKS: 0xFEEDFEED. JCEKS: 0xCECECECE.
    if (magic(content, 0xfe, 0xed, 0xfe, 0xed)) return [findingFromRule(RULE_JKS, at)];
    if (magic(content, 0xce, 0xce, 0xce, 0xce)) return [findingFromRule(RULE_JCEKS, at)];
    // PKCS#12 is a DER SEQUENCE. Since Java 9, `keytool` writes PKCS#12 BY DEFAULT
    // even for files named `.jks`/`.keystore` (and Android release keystores are
    // PKCS#12), so this runs for ANY keystore extension once the JKS/JCEKS magics
    // fail. Accept the long-form length octets 0x81/0x82/0x83 (real PKCS#12 is
    // always >127 bytes, so short-form would be a false positive).
    if (content.length >= 2 && content.charCodeAt(0) === 0x30) {
      const lenOctet = content.charCodeAt(1);
      // Long-form DER length (0x81/0x82/0x83) or BER indefinite length (0x80, emitted
      // by NSS/Firefox .p12 exports). Short-form is excluded (real PKCS#12 is >127 B).
      if (lenOctet === 0x80 || lenOctet === 0x81 || lenOctet === 0x82 || lenOctet === 0x83) {
        return [findingFromRule(RULE_PKCS12, { ...at, matchLength: 2 })];
      }
    }
    // BouncyCastle keystores have no stable magic; key off the extension, but
    // require some content so an empty `.bks` placeholder does not fire.
    if (file.toLowerCase().endsWith(".bks") && content.length > 0) {
      return [findingFromRule(RULE_BKS, { ...at, matchLength: 1 })];
    }
    return [];
  },
};
