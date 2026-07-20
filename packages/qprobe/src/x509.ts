/**
 * Minimal, hand-rolled DER/X.509 parsing to extract a certificate's SIGNATURE
 * algorithm — i.e. the algorithm the issuing CA used to sign it. `node:tls`
 * exposes the leaf's public-key type but not how it was signed, and the signature
 * is the forgeable-at-Q-day part, so we read it from the raw DER.
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate      SEQUENCE,           -- skipped
 *     signatureAlgorithm  AlgorithmIdentifier -- SEQUENCE { OID, params } -- read
 *     signatureValue      BIT STRING }
 *
 * Pure byte work over Buffers; unit-tested with crafted DER. No crypto performed.
 */
import type { AlgorithmFamily } from "@quantakrypto/core";

/** A DER TLV header: tag, content offset, content length. */
interface Tlv {
  tag: number;
  contentStart: number;
  contentEnd: number;
  next: number;
}

/** Read one DER TLV header starting at `off`. Throws on truncation. */
function readTlv(buf: Buffer, off: number): Tlv {
  if (off + 2 > buf.length) throw new RangeError("truncated DER");
  const tag = buf[off];
  let len = buf[off + 1];
  let contentStart = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || contentStart + n > buf.length) throw new RangeError("bad DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[contentStart + i];
    contentStart += n;
  }
  const contentEnd = contentStart + len;
  if (contentEnd > buf.length) throw new RangeError("DER length overruns buffer");
  return { tag, contentStart, contentEnd, next: contentEnd };
}

/** Decode a DER OID value (the bytes inside the OID TLV) to dotted-decimal. */
export function decodeOid(bytes: Buffer): string {
  if (bytes.length === 0) return "";
  const first = bytes[0];
  const arcs = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join(".");
}

/** Map a signature-algorithm OID to a classical family (or undefined). */
export function oidToSignatureFamily(oid: string): AlgorithmFamily | undefined {
  if (oid.startsWith("1.2.840.113549.1.1")) return "RSA"; // PKCS#1 *WithRSAEncryption + RSASSA-PSS
  if (oid.startsWith("1.2.840.10045.4")) return "ECDSA"; // ecdsa-with-SHA*
  if (oid === "1.3.101.112" || oid === "1.3.101.113") return "EdDSA"; // Ed25519 / Ed448
  if (oid.startsWith("1.2.840.10040.4.3")) return "DSA"; // dsa-with-sha1
  return undefined;
}

interface CertSignature {
  oid: string;
  family?: AlgorithmFamily;
}

/**
 * Extract the signatureAlgorithm OID (and mapped family) from a DER certificate.
 * Returns undefined if the DER can't be parsed.
 */
export function certSignatureAlgorithm(der: Buffer): CertSignature | undefined {
  try {
    const cert = readTlv(der, 0); // outer Certificate SEQUENCE
    if (cert.tag !== 0x30) return undefined;
    const tbs = readTlv(der, cert.contentStart); // tbsCertificate SEQUENCE (skip)
    const sigAlg = readTlv(der, tbs.next); // signatureAlgorithm SEQUENCE
    if (sigAlg.tag !== 0x30) return undefined;
    const oidTlv = readTlv(der, sigAlg.contentStart); // OID
    if (oidTlv.tag !== 0x06) return undefined;
    const oid = decodeOid(der.subarray(oidTlv.contentStart, oidTlv.contentEnd));
    return { oid, family: oidToSignatureFamily(oid) };
  } catch {
    return undefined;
  }
}
