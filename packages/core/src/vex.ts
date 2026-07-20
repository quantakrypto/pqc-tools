/**
 * OpenVEX export — turn a {@link ScanResult} into an OpenVEX 0.2.0 document so
 * the quantum-readiness posture flows into the SAME supply-chain pipeline that
 * already ingests CVE-based VEX (Vulnerability Exploitability eXchange).
 *
 * Reference: OpenVEX spec (https://openvex.dev/, `@context` v0.2.0).
 *
 * Modeling choice (documented, honest): PQC findings have no CVE, so each qScan
 * rule becomes a synthetic vulnerability `QK-<ruleId>`. Every finding is reported
 * `status: "affected"` — the classical, Shor-breakable primitive IS present in
 * the product by construction — with the rule's remediation as the VEX
 * `action_statement`. A `--triage` exposure verdict, when present, is surfaced in
 * `status_notes` (score / priority / rationale). qScan never downgrades a finding
 * to `not_affected`: only the operator can attest a mitigation, so that judgment
 * is deliberately left to them (they can post-process this document).
 */
import { createHash } from "node:crypto";

import type { Finding, ScanResult } from "./types.js";

/** A single OpenVEX statement: one synthetic vulnerability over its affected products. */
export interface OpenVexStatement {
  vulnerability: { name: string; description?: string };
  products: { "@id": string }[];
  status: "not_affected" | "affected" | "fixed" | "under_investigation";
  /** Recommended action for an `affected` product (the rule's remediation). */
  action_statement?: string;
  /** Free-form status detail — carries the `--triage` exposure verdict when present. */
  status_notes?: string;
}

/** An OpenVEX 0.2.0 document. */
export interface OpenVexDocument {
  "@context": "https://openvex.dev/ns/v0.2.0";
  "@id": string;
  author: string;
  timestamp: string;
  version: number;
  statements: OpenVexStatement[];
}

/** Options for {@link toOpenVex}. */
export interface OpenVexOptions {
  /** Document author (VEX issuer). Default: `"qScan"`. */
  author?: string;
}

/**
 * A stable product identifier for a finding as an IRI (OpenVEX requires product
 * `@id` to be an IRI): a `file:` URI with the line in the fragment, e.g.
 * `file:src/a.ts#L3`.
 */
function productId(f: Finding): string {
  return `file:${f.location.file}#L${f.location.line}`;
}

/**
 * Build an OpenVEX 0.2.0 document from a scan result. One statement per distinct
 * rule id, listing every affected `file:line` product. Output is deterministic
 * (statements sorted by vulnerability name, products sorted and de-duplicated;
 * the `@id` and `timestamp` derive from the result), so re-exporting the same
 * scan yields byte-identical VEX.
 */
export function toOpenVex(result: ScanResult, opts: OpenVexOptions = {}): OpenVexDocument {
  // Group findings by rule id → one VEX statement per rule.
  const byRule = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const list = byRule.get(f.ruleId);
    if (list) list.push(f);
    else byRule.set(f.ruleId, [f]);
  }

  const statements: OpenVexStatement[] = [...byRule.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([ruleId, findings]) => {
      const first = findings[0] as Finding;
      // De-duplicate + sort the affected products (a rule can fire many times).
      const products = [...new Set(findings.map(productId))].sort().map((id) => ({ "@id": id }));

      // Surface a triage verdict (if any finding for this rule carries one). Findings
      // of the same rule share a rule; the most-exposed verdict is the informative one.
      const triaged = findings
        .filter((f) => f.triage)
        .sort((a, b) => (b.triage?.exposureScore ?? 0) - (a.triage?.exposureScore ?? 0))[0]?.triage;

      const statement: OpenVexStatement = {
        vulnerability: {
          name: `QK-${ruleId}`,
          description: first.message,
        },
        products,
        status: "affected",
        action_statement: first.remediation ?? "Migrate to a NIST PQC standard (FIPS 203/204/205).",
      };
      if (triaged) {
        statement.status_notes =
          `qScan triage — exposure ${triaged.exposureScore}/100, priority ${triaged.priority}: ` +
          triaged.rationale;
      }
      return statement;
    });

  // Deterministic doc id + timestamp so the same scan yields identical VEX. The
  // triage `status_notes` are part of the identity: a triaged and an untriaged
  // export of the same scan are DIFFERENT documents and must not share an @id.
  const digest = createHash("sha256").update(`${result.root}|${result.toolVersion}`, "utf8");
  for (const s of statements) {
    digest.update(
      `\n${s.vulnerability.name}|${s.products.map((p) => p["@id"]).join(",")}|${s.status_notes ?? ""}`,
    );
  }
  const id = `https://quantakrypto.com/vex/${digest.digest("hex").slice(0, 16)}`;

  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": id,
    author: opts.author ?? "qScan",
    timestamp: result.finishedAt,
    version: 1,
    statements,
  };
}
