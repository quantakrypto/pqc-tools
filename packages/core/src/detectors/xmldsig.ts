/**
 * Config detector: classical crypto in XML Digital Signature / XML Encryption
 * (W3C XML-DSig / XML-Enc), the algorithm layer under SAML SSO, WS-Security /
 * SOAP, and signed XML documents. Enterprise identity is ubiquitous and its IdP
 * signing keys are long-lived, so a forged SAML assertion is a prime quantum
 * forgery surface; an encrypted SAML assertion (RSA key transport) is
 * harvest-now-decrypt-later exposed.
 *
 * Detection keys off the W3C algorithm URIs, which are globally-unique constant
 * strings (RFC-precise, so a lexical match is exact):
 *  - `…xmldsig#rsa-sha1` / `…xmldsig-more#rsa-sha256` …  → RSA signature (forgeable)
 *  - `…xmldsig11#dsa-sha256` / `…xmldsig#dsa-sha1`       → DSA signature
 *  - `…xmldsig-more#ecdsa-sha256` …                      → ECDSA signature
 *  - `…xmlenc#rsa-oaep(-mgf1p)` / `…xmlenc#rsa-1_5`      → RSA key transport (HNDL)
 *
 * These URIs appear both in XML config (`.xml`) and as string constants in SAML
 * library code (python3-saml, xml-crypto, OpenSAML), so the detector runs on any
 * non-doc file.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { DOC_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// The `#fragment` of the W3C XML-DSig / XML-Enc algorithm URIs. Anchored on the
// namespace fragment (`xmldsig…#` / `xmlenc#`) so a bare `rsa-sha256` elsewhere
// doesn't misfire.
const RE_XMLDSIG_RSA = /\bxmldsig(?:-more|11)?#rsa-sha(?:1|224|256|384|512)\b/g;
const RE_XMLDSIG_DSA = /\bxmldsig(?:11)?#dsa-sha(?:1|256)\b/g;
const RE_XMLDSIG_ECDSA = /\bxmldsig-more#ecdsa-sha(?:1|224|256|384|512)\b/g;
const RE_XMLENC_RSA = /\bxmlenc#rsa-(?:oaep(?:-mgf1p)?|1_5)\b/g;

const RULE_XMLDSIG_RSA: RuleMeta = {
  id: "xmldsig-rsa-sign",
  title: "XML-DSig RSA signature",
  description: "XML Digital Signature with an RSA-SHA* algorithm (SAML/WS-Security)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "XML signatures (SAML / WS-Security) use classical RSA (rsa-sha*); a quantum attacker could forge assertions signed with this key.",
  remediation:
    "Track PQC XML-DSig / SAML profiles (ML-DSA); rotate to a PQC signing key as tooling and IdPs add support.",
};
const RULE_XMLDSIG_DSA: RuleMeta = {
  id: "xmldsig-dsa-sign",
  title: "XML-DSig DSA signature",
  description: "XML Digital Signature with a DSA-SHA* algorithm",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "XML signatures use classical DSA (dsa-sha*) — deprecated and quantum-forgeable.",
  remediation: "Migrate off DSA now; track PQC XML-DSig profiles (ML-DSA).",
};
const RULE_XMLDSIG_ECDSA: RuleMeta = {
  id: "xmldsig-ecdsa-sign",
  title: "XML-DSig ECDSA signature",
  description: "XML Digital Signature with an ECDSA-SHA* algorithm",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "XML signatures use classical ECDSA (ecdsa-sha*); forgeable by a quantum attacker.",
  remediation:
    "Track PQC XML-DSig / SAML profiles (ML-DSA); rotate the signing key when supported.",
};
const RULE_XMLENC_RSA: RuleMeta = {
  id: "xmlenc-rsa-keytransport",
  title: "XML-Enc RSA key transport",
  description: "XML Encryption with RSA-OAEP / RSA-1_5 key transport (encrypted SAML assertions)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "XML Encryption wraps the content key with classical RSA (rsa-oaep / rsa-1_5); encrypted XML (e.g. SAML assertions) is harvest-now-decrypt-later exposed.",
  remediation:
    "Plan migration to a post-quantum KEM (ML-KEM-768) for key transport as XML-Enc / SAML PQC profiles mature.",
};

/** Detects classical XML-DSig / XML-Enc algorithms (SAML, WS-Security, signed XML). */
export const xmldsigDetector: Detector = {
  id: "xmldsig-crypto",
  description: "Classical XML-DSig / XML-Enc algorithms (SAML, WS-Security, signed XML)",
  scope: "config",
  language: "any",
  // Skip prose/docs: a page explaining the SAML algorithm URIs is not live config.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  rules: [RULE_XMLDSIG_RSA, RULE_XMLDSIG_DSA, RULE_XMLDSIG_ECDSA, RULE_XMLENC_RSA],
  detect({ file, content }): Finding[] {
    // Fast reject: only proceed if an XML-DSig / XML-Enc namespace fragment is present.
    if (!content.includes("xmldsig") && !content.includes("xmlenc")) return [];
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta): void =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_XMLDSIG_RSA, RULE_XMLDSIG_RSA);
    add(RE_XMLDSIG_DSA, RULE_XMLDSIG_DSA);
    add(RE_XMLDSIG_ECDSA, RULE_XMLDSIG_ECDSA);
    add(RE_XMLENC_RSA, RULE_XMLENC_RSA);
    return findings;
  },
};
