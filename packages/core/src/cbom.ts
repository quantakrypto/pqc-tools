/**
 * CBOM (Cryptographic Bill of Materials) export — CycloneDX 1.6 with
 * `cryptographic-asset` components. Turns a {@link ScanResult} into a
 * machine-readable inventory of the classical cryptographic assets discovered,
 * for compliance / supply-chain tooling.
 *
 * Reference: CycloneDX 1.6 cryptography properties
 * (https://cyclonedx.org/capabilities/cbom/). Each finding is classified into
 * its CycloneDX `assetType` — `algorithm` (usage), `certificate` (X.509),
 * `related-crypto-material` (private/public key material), or `protocol` (TLS) —
 * and we emit one `cryptographic-asset` component per distinct
 * (assetType, algorithm, discriminator), with occurrence evidence pointing back
 * at the findings. Every asset carries the quantum posture flags.
 */
import { createHash } from "node:crypto";

import type { AlgorithmFamily, Finding, FindingCategory, ScanResult } from "./types.js";
import { VERSION } from "./version.js";

/** A CycloneDX 1.6 cryptographic bill of materials (kept permissive). */
export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: Record<string, unknown>;
  components: CbomComponent[];
}

/** A single CycloneDX `cryptographic-asset` component. */
export interface CbomComponent {
  type: "cryptographic-asset";
  "bom-ref": string;
  name: string;
  cryptoProperties: Record<string, unknown>;
  /** CycloneDX component name/value properties (carries the quantum posture flags). */
  properties?: { name: string; value: string }[];
  evidence?: Record<string, unknown>;
}

/** CycloneDX cryptographic primitive for a finding category (algorithm assets only). */
function primitiveFor(category: FindingCategory): string {
  switch (category) {
    case "kem":
      return "kem";
    case "key-exchange":
      return "key-agree";
    case "signature":
      return "signature";
    case "hash":
      return "hash";
    default:
      // `certificate` / `tls` no longer route here (they become their own
      // assetType — see {@link classifyAsset}); `dependency` / `rng` and any
      // future category fall back to the valid "other" primitive.
      return "other";
  }
}

/** The CycloneDX 1.6 `cryptoProperties.assetType` a finding maps to. */
type CbomAssetType = "algorithm" | "certificate" | "protocol" | "related-crypto-material";

/**
 * Classify a finding into its CycloneDX 1.6 asset type. Most findings are
 * algorithm USAGE (`kem` / `key-exchange` / `signature` / `hash` / …). The
 * `certificate` category is a mix of real X.509 certificates and raw key
 * material, disambiguated by rule id; `tls` findings are protocol configuration.
 *
 * `discriminator` keeps distinct kinds in separate components (it is the algorithm
 * primitive for `algorithm`, the material type for `related-crypto-material`, the
 * protocol type for `protocol`, and empty for `certificate`).
 */
function classifyAsset(f: Finding): {
  assetType: CbomAssetType;
  discriminator: string;
  materialType?: string;
  protocolType?: string;
} {
  if (f.category === "tls") {
    return { assetType: "protocol", discriminator: "tls", protocolType: "tls" };
  }
  if (f.category === "certificate") {
    const id = f.ruleId.toLowerCase();
    // Route the explicitly key-SHAPED material to related-crypto-material…
    if (id.includes("private-key") || id.includes("keystore")) {
      return {
        assetType: "related-crypto-material",
        discriminator: "private-key",
        materialType: "private-key",
      };
    }
    if (id.includes("public-key")) {
      return {
        assetType: "related-crypto-material",
        discriminator: "public-key",
        materialType: "public-key",
      };
    }
    if (id.includes("message")) {
      return {
        assetType: "related-crypto-material",
        discriminator: "ciphertext",
        materialType: "ciphertext",
      };
    }
    // …and DEFAULT the rest of the `certificate` category to assetType
    // "certificate" — the category's own meaning. This covers real X.509 certs
    // and CSRs (pem-certificate/pem-cert-request) plus PKI trust material whose
    // ids don't spell "cert": ACM certs (cfn-acm-*), Vault PKI (vault-pki-*),
    // mesh identity, and SPIFFE X.509-SVIDs (spire-*). Previously these fell
    // through to related-crypto-material "key", mislabelling certificates.
    return { assetType: "certificate", discriminator: "" };
  }
  return { assetType: "algorithm", discriminator: primitiveFor(f.category) };
}

/**
 * Every CBOM asset here is derived from a quantakrypto finding, and the detectors
 * only ever fire on classical (Shor-broken) public-key crypto — so an asset is
 * quantum-vulnerable by construction, even when the exact family couldn't be
 * pinned down (`unknown`). Reporting `false` for `unknown` mislabeled
 * definitionally-classical findings as safe (audit: crypto #6).
 */
function isQuantumVulnerable(_algorithm: AlgorithmFamily): boolean {
  return true;
}

/**
 * Approximate CLASSICAL security strength (bits) of the common parameterisation
 * of a classical family — RSA-2048 / DH-2048 ≈ 112-bit, 256-bit curves ≈ 128-bit,
 * X448 ≈ 224-bit. (The QUANTUM level is 0 for all of these: Shor breaks them.)
 * 0 when the family is unknown. Reported so a CBOM doesn't imply these primitives
 * have zero classical strength today.
 */
function classicalSecurityLevelFor(algorithm: AlgorithmFamily): number {
  switch (algorithm) {
    case "RSA":
    case "DH":
    case "DSA":
      return 112;
    case "ECDH":
    case "ECDSA":
    case "EdDSA":
    case "X25519":
    case "ECIES":
      return 128;
    case "X448":
      return 224;
    default:
      return 0;
  }
}

/** Deterministic bom-ref for a (algorithm, primitive) asset key. */
function bomRef(key: string): string {
  return `crypto:${createHash("sha256").update(key, "utf8").digest("hex").slice(0, 16)}`;
}

/**
 * Build a CycloneDX 1.6 CBOM from a scan result. One component per distinct
 * (algorithm + primitive) pair, with occurrence evidence (file:line) per
 * finding. Output is deterministic (components and occurrences are sorted).
 */
export function toCbom(result: ScanResult): CycloneDxBom {
  // Group findings by (assetType | algorithm | discriminator) so each distinct
  // cryptographic asset — an algorithm usage, a certificate, key material, or a
  // protocol — becomes its own component.
  const groups = new Map<
    string,
    {
      assetType: CbomAssetType;
      algorithm: AlgorithmFamily;
      discriminator: string;
      materialType?: string;
      protocolType?: string;
      findings: Finding[];
    }
  >();

  for (const f of result.findings) {
    const algorithm: AlgorithmFamily = f.algorithm ?? "unknown";
    const cls = classifyAsset(f);
    const key = `${cls.assetType}|${algorithm}|${cls.discriminator}`;
    let g = groups.get(key);
    if (!g) {
      g = { ...cls, algorithm, findings: [] };
      groups.set(key, g);
    }
    g.findings.push(f);
  }

  const components: CbomComponent[] = [...groups.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([key, g]) => {
      const occurrences = g.findings
        .map((f) => ({
          location: `${f.location.file}:${f.location.line}`,
          ...(f.cwe ? { additionalContext: f.cwe } : {}),
        }))
        .sort((a, b) => (a.location < b.location ? -1 : a.location > b.location ? 1 : 0));

      const anyHndl = g.findings.some((f) => f.hndl);

      // The type-specific CycloneDX properties block + a human label for the name.
      let typeProps: Record<string, unknown>;
      let label: string;
      switch (g.assetType) {
        case "certificate":
          // A certificate / CSR: we know the public-key family but not the X.509
          // fields (subject, validity, refs) from a lexical scan, so the block is
          // left minimal — all certificateProperties are optional in 1.6.
          typeProps = { certificateProperties: {} };
          label = "certificate";
          break;
        case "related-crypto-material":
          typeProps = {
            relatedCryptoMaterialProperties: { type: g.materialType ?? "key" },
          };
          label = g.materialType ?? "key";
          break;
        case "protocol":
          typeProps = { protocolProperties: { type: g.protocolType ?? "tls" } };
          label = g.protocolType ?? "tls";
          break;
        case "algorithm":
        default:
          typeProps = {
            algorithmProperties: {
              primitive: g.discriminator,
              parameterSetIdentifier: g.algorithm,
              executionEnvironment: "software-plain-ram",
              classicalSecurityLevel: classicalSecurityLevelFor(g.algorithm),
              nistQuantumSecurityLevel: 0,
              cryptoFunctions:
                g.discriminator === "signature"
                  ? ["sign", "verify"]
                  : g.discriminator === "kem"
                    ? ["encapsulate", "decapsulate"]
                    : // CycloneDX 1.6 has no "keyagree" cryptoFunction; "other" is
                      // the valid value for a key-agreement primitive.
                      ["other"],
            },
          };
          label = g.discriminator;
          break;
      }

      return {
        type: "cryptographic-asset" as const,
        "bom-ref": bomRef(key),
        name: `${g.algorithm} (${label})`,
        cryptoProperties: {
          assetType: g.assetType,
          ...typeProps,
        },
        // The quantum posture flags are carried as CycloneDX component `properties`
        // (an open name/value list) rather than inside `cryptoProperties`, whose
        // 1.6 schema is `additionalProperties: false` — so a strict validator
        // accepts the BOM. Namespaced to avoid clashing with other tools' keys.
        properties: [
          {
            name: "quantakrypto:quantumVulnerable",
            value: String(isQuantumVulnerable(g.algorithm)),
          },
          { name: "quantakrypto:harvestNowDecryptLater", value: String(anyHndl) },
        ],
        evidence: { occurrences },
      };
    });

  const serial = `urn:uuid:${stableUuid(result)}`;

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: result.finishedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "qScan",
            version: result.toolVersion || VERSION,
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": "root",
        name: result.root,
      },
    },
    components,
  };
}

/**
 * Derive a stable UUID-shaped serial from the scan result so re-exporting the
 * same result yields the same serial number (deterministic output). Hashed over the
 * actual finding set (ruleId + location per finding), NOT just the COUNT — two scans
 * with the same number of totally different findings must not collide, since a
 * CycloneDX serialNumber identifies a specific BOM instance. Findings are already in
 * a stable order (scan.ts sorts by file/line/ruleId).
 */
function stableUuid(result: ScanResult): string {
  const hash = createHash("sha256").update(`${result.root}|${result.toolVersion}`, "utf8");
  for (const f of result.findings) {
    hash.update(`\n${f.ruleId}@${f.location.file}:${f.location.line}:${f.location.column ?? 0}`);
  }
  const h = hash.digest("hex");
  // Shape as a v4-ish UUID (variant/version nibbles forced).
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
