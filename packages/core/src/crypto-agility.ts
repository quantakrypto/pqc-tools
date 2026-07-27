/**
 * Crypto-agility manifest: an agent-consumable crypto-posture document.
 *
 * A small, versioned JSON manifest a project publishes at a well-known URL
 * (`/.well-known/crypto-agility.json`, see docs/CRYPTO-AGILITY-MANIFEST.md) so any
 * agent, scanner, or CI bot can read the project's cryptographic posture the way it
 * reads `security.txt` or `robots.txt`. It is a compact, decision-oriented summary
 * DERIVED from a qScan result: the readiness score, the count of quantum-vulnerable
 * findings by severity, the CBOM's algorithm families, an optional attestation URL,
 * and the migration-policy deadlines.
 *
 * This module owns two pure operations and their shared schema:
 *   - {@link buildCryptoAgilityManifest}: derive a manifest from a {@link ScanResult}.
 *   - {@link validateCryptoAgilityManifest}: check an untrusted value against the
 *     schema, returning a list of problems (used by the local validator; a network
 *     fetch-and-validate lives on the website, never in this offline-boundary tool).
 *
 * Zero dependencies; hand-rolled JSON shape and validation so the package stays
 * runtime-dependency-free.
 */

import { toCbom } from "./cbom.js";
import { PQC_STANDARDS } from "./standards.js";
import { SEVERITY_ORDER } from "./severity.js";
import type { CryptoPolicy } from "./policy.js";
import type { ScanResult, Severity } from "./types.js";
import { VERSION } from "./version.js";

/**
 * Schema version of the manifest this module emits and validates. Bumped only on a
 * breaking change to the manifest shape; consumers key their parsing off it.
 */
export const CRYPTO_AGILITY_MANIFEST_VERSION = 1;

/** The conventional path a manifest is served from, relative to the site origin. */
export const CRYPTO_AGILITY_WELL_KNOWN_PATH = "/.well-known/crypto-agility.json";

/** A single algorithm family in use, mirroring the CBOM's grouping. */
export interface CryptoAgilityFamily {
  /** The algorithm family (e.g. `RSA`, `ECDH`, `ECDSA`), or `unknown`. */
  family: string;
  /** How many findings referenced this family. */
  count: number;
  /** Always true today: every detected family is classical (Shor-broken). */
  quantumVulnerable: boolean;
}

/** The project's cryptographic posture, distilled from the scan inventory. */
export interface CryptoAgilityPosture {
  /** qScan readiness score, 0–100 (100 = no classical asymmetric crypto found). */
  readinessScore: number;
  /**
   * Whether the project negotiates hybrid post-quantum key exchange. qScan is a
   * static scanner and cannot observe a negotiated TLS group, so this is `null`
   * ("not determined by this generator") unless the operator asserts it
   * (`--hybrid-kex` / `--no-hybrid-kex`). A live probe (qProbe) or the website can
   * fill it authoritatively.
   */
  hybridKexInUse: boolean | null;
  /** Count of quantum-vulnerable findings, total and broken down by severity. */
  quantumVulnerable: {
    total: number;
    bySeverity: Record<Severity, number>;
  };
  /** How many findings are exposed to harvest-now-decrypt-later. */
  hndlExposedCount: number;
}

/** A compact summary of the full CBOM, linking to it by serial number. */
export interface CryptoAgilityCbomSummary {
  /** The CycloneDX `serialNumber` of the full CBOM this summary was derived from. */
  serialNumber: string;
  /** Number of distinct cryptographic-asset components in the full CBOM. */
  assetCount: number;
  /** Algorithm families in use, most-referenced first. */
  algorithmFamilies: CryptoAgilityFamily[];
}

/** The migration policy the project declares it is measured against. */
export interface CryptoAgilityPolicy {
  /** Human label for the policy source (a standard name, or `operator-declared`). */
  source: string;
  /** Year after which classical public-key crypto is deprecated. */
  deprecateClassicalAfter: number;
  /** Year after which classical public-key crypto is disallowed. */
  disallowClassicalAfter: number;
  /** Operator-declared migration deadline (ISO date / year), or `null`. */
  transitionDeadline: string | null;
  /** Citation for the deadlines (spec / publication). */
  citation: string;
}

/** The full crypto-agility manifest. */
export interface CryptoAgilityManifest {
  /** Manifest schema version ({@link CRYPTO_AGILITY_MANIFEST_VERSION}). */
  version: number;
  /** Discriminator so a consumer can tell this document apart from other JSON. */
  manifestType: "crypto-agility";
  /** ISO 8601 timestamp the manifest was generated (caller-supplied). */
  generatedAt: string;
  /** What produced the manifest. */
  generator: { name: string; version: string };
  /** What the manifest describes. */
  subject: { root: string; repository: string | null; commit: string | null };
  /** The distilled cryptographic posture. */
  posture: CryptoAgilityPosture;
  /** A compact summary of the CBOM. */
  cbomSummary: CryptoAgilityCbomSummary;
  /** Optional link to a quantakrypto (or other) posture credential. */
  attestation?: { url: string };
  /** The declared migration policy / deadlines. */
  policy: CryptoAgilityPolicy;
}

/** Inputs the CLI/runtime supplies that are not derivable from the scan. */
export interface CryptoAgilityManifestOptions {
  /**
   * ISO 8601 generation timestamp. The caller supplies it (`Date.now()` is fine in
   * the CLI runtime) so the builder itself stays pure and deterministic.
   */
  generatedAt: string;
  /** Optional URL to a posture credential (recorded verbatim, never fetched here). */
  attestationUrl?: string;
  /**
   * Operator assertion of hybrid-KEX use. `undefined` leaves the manifest's
   * `hybridKexInUse` as `null` (not determined).
   */
  hybridKexInUse?: boolean;
  /** Optional org crypto policy; its `transitionDeadline` overlays the defaults. */
  policy?: CryptoPolicy;
  /** Repository URL (e.g. `GITHUB_REPOSITORY`); omitted → null. */
  repository?: string;
  /** Commit SHA (e.g. `GITHUB_SHA`); omitted → null. */
  commit?: string;
}

/**
 * Build a crypto-agility manifest from a scan result. Pure: every runtime input
 * (timestamp, attestation, hybrid-KEX assertion, policy) arrives via `opts`.
 *
 * The posture and CBOM summary are derived straight from the scan's inventory and
 * its CycloneDX CBOM, so the manifest can never disagree with the full `--cbom` /
 * `--format json` outputs of the same scan.
 */
export function buildCryptoAgilityManifest(
  result: ScanResult,
  opts: CryptoAgilityManifestOptions,
): CryptoAgilityManifest {
  const cbom = toCbom(result);
  const inv = result.inventory;

  const algorithmFamilies: CryptoAgilityFamily[] = Object.entries(inv.byAlgorithm)
    .filter(([, count]) => (count ?? 0) > 0)
    .map(([family, count]) => ({
      family,
      count: count as number,
      // Every family the detectors surface is classical, hence quantum-vulnerable
      // by construction (mirrors cbom.ts `isQuantumVulnerable`).
      quantumVulnerable: true,
    }))
    .sort((a, b) => b.count - a.count || a.family.localeCompare(b.family));

  const bySeverity = { ...inv.bySeverity };

  // Default policy: the NIST IR 8547 transition timeline. An operator crypto policy
  // (`--policy`) does not override the standards deadlines but layers its own
  // `transitionDeadline` on top and re-labels the source as operator-declared.
  const timeline = PQC_STANDARDS.transitionTimeline;
  const policy: CryptoAgilityPolicy = {
    source: opts.policy ? "operator-declared" : timeline.source,
    deprecateClassicalAfter: timeline.deprecateAfter,
    disallowClassicalAfter: timeline.disallowAfter,
    transitionDeadline: opts.policy?.transitionDeadline ?? null,
    citation: timeline.source,
  };

  const manifest: CryptoAgilityManifest = {
    version: CRYPTO_AGILITY_MANIFEST_VERSION,
    manifestType: "crypto-agility",
    generatedAt: opts.generatedAt,
    generator: { name: "qScan", version: result.toolVersion || VERSION },
    subject: {
      root: result.root,
      repository: opts.repository ?? null,
      commit: opts.commit ?? null,
    },
    posture: {
      readinessScore: inv.readinessScore,
      hybridKexInUse: opts.hybridKexInUse ?? null,
      quantumVulnerable: {
        total: result.findings.length,
        bySeverity,
      },
      hndlExposedCount: inv.hndlCount,
    },
    cbomSummary: {
      serialNumber: cbom.serialNumber,
      assetCount: cbom.components.length,
      algorithmFamilies,
    },
    ...(opts.attestationUrl ? { attestation: { url: opts.attestationUrl } } : {}),
    policy,
  };
  return manifest;
}

/** Outcome of {@link validateCryptoAgilityManifest}. */
export interface ManifestValidation {
  /** True when the value satisfies the manifest schema. */
  valid: boolean;
  /** One human-readable message per problem found (empty when `valid`). */
  errors: string[];
}

/** True for a plain (non-array, non-null) object. */
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate an untrusted value against the crypto-agility manifest schema.
 *
 * Checks structure, required fields, types, and the schema version. Purely local:
 * it parses an already-in-memory value and NEVER performs I/O or network fetches;
 * a fetch-and-validate of a remote manifest is a website-side concern, deliberately
 * kept out of this offline-boundary tool. Returns every problem it finds rather than
 * throwing on the first, so a caller can report them all at once.
 */
export function validateCryptoAgilityManifest(value: unknown): ManifestValidation {
  const errors: string[] = [];
  const err = (m: string): void => void errors.push(m);

  if (!isObject(value)) {
    return { valid: false, errors: ["manifest must be a JSON object"] };
  }

  // version
  if (value.version === undefined) {
    err("missing required field: version");
  } else if (typeof value.version !== "number" || !Number.isInteger(value.version)) {
    err("version must be an integer");
  } else if (value.version !== CRYPTO_AGILITY_MANIFEST_VERSION) {
    err(
      `unsupported version ${value.version} (this validator understands version ${CRYPTO_AGILITY_MANIFEST_VERSION})`,
    );
  }

  // manifestType
  if (value.manifestType === undefined) {
    err("missing required field: manifestType");
  } else if (value.manifestType !== "crypto-agility") {
    err('manifestType must be the string "crypto-agility"');
  }

  // generatedAt
  if (value.generatedAt === undefined) {
    err("missing required field: generatedAt");
  } else if (typeof value.generatedAt !== "string" || value.generatedAt.length === 0) {
    err("generatedAt must be a non-empty ISO 8601 string");
  } else if (Number.isNaN(Date.parse(value.generatedAt))) {
    err("generatedAt must be a parseable ISO 8601 timestamp");
  }

  // generator
  if (value.generator === undefined) {
    err("missing required field: generator");
  } else if (!isObject(value.generator)) {
    err("generator must be an object");
  } else {
    if (typeof value.generator.name !== "string") err("generator.name must be a string");
    if (typeof value.generator.version !== "string") err("generator.version must be a string");
  }

  // subject
  if (value.subject === undefined) {
    err("missing required field: subject");
  } else if (!isObject(value.subject)) {
    err("subject must be an object");
  } else {
    if (typeof value.subject.root !== "string") err("subject.root must be a string");
    if (value.subject.repository !== null && typeof value.subject.repository !== "string") {
      err("subject.repository must be a string or null");
    }
    if (value.subject.commit !== null && typeof value.subject.commit !== "string") {
      err("subject.commit must be a string or null");
    }
  }

  // posture
  validatePosture(value.posture, err);

  // cbomSummary
  validateCbomSummary(value.cbomSummary, err);

  // attestation (optional)
  if (value.attestation !== undefined) {
    if (!isObject(value.attestation)) {
      err("attestation must be an object when present");
    } else if (typeof value.attestation.url !== "string" || value.attestation.url.length === 0) {
      err("attestation.url must be a non-empty string");
    }
  }

  // policy
  validatePolicy(value.policy, err);

  return { valid: errors.length === 0, errors };
}

/** Validate the `posture` block. */
function validatePosture(posture: unknown, err: (m: string) => void): void {
  if (posture === undefined) {
    err("missing required field: posture");
    return;
  }
  if (!isObject(posture)) {
    err("posture must be an object");
    return;
  }
  if (
    typeof posture.readinessScore !== "number" ||
    posture.readinessScore < 0 ||
    posture.readinessScore > 100
  ) {
    err("posture.readinessScore must be a number between 0 and 100");
  }
  if (posture.hybridKexInUse !== null && typeof posture.hybridKexInUse !== "boolean") {
    err("posture.hybridKexInUse must be a boolean or null");
  }
  if (typeof posture.hndlExposedCount !== "number" || posture.hndlExposedCount < 0) {
    err("posture.hndlExposedCount must be a non-negative number");
  }
  const qv = posture.quantumVulnerable;
  if (!isObject(qv)) {
    err("posture.quantumVulnerable must be an object");
    return;
  }
  if (typeof qv.total !== "number" || qv.total < 0) {
    err("posture.quantumVulnerable.total must be a non-negative number");
  }
  if (!isObject(qv.bySeverity)) {
    err("posture.quantumVulnerable.bySeverity must be an object");
  } else {
    for (const sev of SEVERITY_ORDER) {
      if (typeof qv.bySeverity[sev] !== "number") {
        err(`posture.quantumVulnerable.bySeverity.${sev} must be a number`);
      }
    }
  }
}

/** Validate the `cbomSummary` block. */
function validateCbomSummary(summary: unknown, err: (m: string) => void): void {
  if (summary === undefined) {
    err("missing required field: cbomSummary");
    return;
  }
  if (!isObject(summary)) {
    err("cbomSummary must be an object");
    return;
  }
  if (typeof summary.serialNumber !== "string") err("cbomSummary.serialNumber must be a string");
  if (typeof summary.assetCount !== "number" || summary.assetCount < 0) {
    err("cbomSummary.assetCount must be a non-negative number");
  }
  if (!Array.isArray(summary.algorithmFamilies)) {
    err("cbomSummary.algorithmFamilies must be an array");
    return;
  }
  summary.algorithmFamilies.forEach((fam, i) => {
    if (!isObject(fam)) {
      err(`cbomSummary.algorithmFamilies[${i}] must be an object`);
      return;
    }
    if (typeof fam.family !== "string")
      err(`cbomSummary.algorithmFamilies[${i}].family must be a string`);
    if (typeof fam.count !== "number" || fam.count < 0) {
      err(`cbomSummary.algorithmFamilies[${i}].count must be a non-negative number`);
    }
    if (typeof fam.quantumVulnerable !== "boolean") {
      err(`cbomSummary.algorithmFamilies[${i}].quantumVulnerable must be a boolean`);
    }
  });
}

/** Validate the `policy` block. */
function validatePolicy(policy: unknown, err: (m: string) => void): void {
  if (policy === undefined) {
    err("missing required field: policy");
    return;
  }
  if (!isObject(policy)) {
    err("policy must be an object");
    return;
  }
  if (typeof policy.source !== "string") err("policy.source must be a string");
  if (typeof policy.deprecateClassicalAfter !== "number") {
    err("policy.deprecateClassicalAfter must be a number (year)");
  }
  if (typeof policy.disallowClassicalAfter !== "number") {
    err("policy.disallowClassicalAfter must be a number (year)");
  }
  if (policy.transitionDeadline !== null && typeof policy.transitionDeadline !== "string") {
    err("policy.transitionDeadline must be a string or null");
  }
  if (typeof policy.citation !== "string") err("policy.citation must be a string");
}
