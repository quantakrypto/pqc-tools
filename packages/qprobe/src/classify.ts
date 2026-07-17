/**
 * Map live-probe results onto `@quantakrypto/core` Findings, so qProbe output
 * scores and reports through the same engine as qScan (buildInventory, toSarif,
 * toJson, toCbom). A positive result (PQC-hybrid TLS selected, or PQC SSH KEX
 * offered) intentionally emits NO finding — good news keeps the readiness score
 * high; it is surfaced separately in the human summary.
 *
 * Findings are synthesised with `location.file = "host:port"` and line 1, since a
 * live endpoint has no source position.
 */
import type { AlgorithmFamily, Finding } from "@quantakrypto/core";
import { CWE_BROKEN_CRYPTO, CWE_RISKY_PRIMITIVE, CWE_WEAK_STRENGTH } from "@quantakrypto/core";
import type { Target } from "./target.js";
import type { TlsNegotiated, HybridSupport } from "./tls.js";
import type { SshProbeResult } from "./ssh.js";

function endpoint(t: Target): Finding["location"] {
  return { file: `${t.host}:${t.port}`, line: 1 };
}

/** Classify a TLS ephemeral group name into a classical algorithm family, or undefined if PQ/unknown. */
function classicalKexFamily(group?: string): AlgorithmFamily | undefined {
  if (!group) return undefined;
  const g = group.toLowerCase();
  if (g.includes("mlkem") || g.includes("kyber")) return undefined; // already PQ-hybrid
  if (g === "x25519") return "X25519";
  if (g === "x448") return "X448";
  if (g.startsWith("p-") || g.includes("prime256") || g.includes("secp")) return "ECDH";
  if (g === "dh" || g.includes("ffdhe") || g.includes("modp")) return "DH";
  return undefined;
}

/** Findings for a TLS endpoint from the negotiated params + the hybrid probe. */
export function classifyTls(target: Target, neg: TlsNegotiated, hybrid: HybridSupport): Finding[] {
  const out: Finding[] = [];
  const loc = endpoint(target);

  if (neg.protocol === "TLSv1" || neg.protocol === "TLSv1.1") {
    out.push({
      ruleId: "qprobe-tls-legacy-version",
      title: "Legacy TLS version negotiated",
      category: "tls",
      severity: "high",
      confidence: "high",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message: `Endpoint negotiated ${neg.protocol}; obsolete TLS with weak, harvestable key exchange.`,
      remediation: "Require TLS 1.3.",
      location: loc,
    });
  }

  // Flag classical KEX when the server did NOT select a PQC-hybrid group. The
  // negotiated group (from node:tls, which cannot do hybrid) is factual; only the
  // "did not select hybrid" claim depends on the raw probe, so soften it when the
  // hybrid probe was inconclusive (e.g. a firewall dropped the raw ClientHello).
  const fam = classicalKexFamily(neg.kexGroup);
  if (!hybrid.hybridSelected && fam) {
    const hybridNote = hybrid.error
      ? "the PQC-hybrid probe was inconclusive"
      : "the server did not select a PQC-hybrid group (X25519MLKEM768)";
    out.push({
      ruleId: "qprobe-tls-classical-kex",
      title: "Classical TLS key exchange (no PQC hybrid)",
      category: "key-exchange",
      severity: "medium",
      confidence: hybrid.error ? "medium" : "high",
      algorithm: fam,
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: `TLS key exchange is classical ${neg.kexGroup}; the session key is harvest-now-decrypt-later exposed and ${hybridNote}.`,
      remediation: "Enable a PQC-hybrid key-exchange group (X25519MLKEM768) on the TLS terminator.",
      location: loc,
    });
  }

  if (neg.certKeyType) {
    const isRsa = neg.certKeyType === "RSA";
    out.push({
      ruleId: "qprobe-tls-classical-cert",
      title: "Classical certificate key",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: isRsa ? "RSA" : "ECDSA",
      hndl: false,
      cwe: isRsa ? CWE_BROKEN_CRYPTO : CWE_WEAK_STRENGTH,
      message: `Leaf certificate uses a classical ${neg.certKeyType}${
        neg.certKeyBits ? `-${neg.certKeyBits}` : ""
      } key${
        neg.certSigFamily ? `, signed by the CA with ${neg.certSigFamily}` : ""
      }; its signature is forgeable once a CRQC exists.`,
      remediation:
        "Plan migration to ML-DSA-65 (FIPS 204) certificate keys as your CA adds support.",
      location: loc,
    });
  }

  return out;
}

/** Findings for an SSH endpoint from its KEXINIT. */
export function classifySsh(target: Target, ssh: SshProbeResult): Finding[] {
  const out: Finding[] = [];
  if (ssh.error || !ssh.kex) return out;
  if (!ssh.pqKexOffered) {
    out.push({
      ruleId: "qprobe-ssh-classical-kex",
      title: "SSH offers only classical key exchange",
      category: "key-exchange",
      severity: "medium",
      confidence: "high",
      algorithm: "ECDH",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: `SSH endpoint offers no post-quantum key exchange (${ssh.kex.kexAlgorithms
        .slice(0, 4)
        .join(", ")}…); session keys are harvest-now-decrypt-later exposed.`,
      remediation:
        "Enable a PQC hybrid SSH KEX (sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256).",
      location: endpoint(target),
    });
  }
  return out;
}
