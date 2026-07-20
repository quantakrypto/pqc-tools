/**
 * Merge multiple CycloneDX 1.6 CBOMs into one combined cryptographic bill of
 * materials. This is what turns the "code + infra + live-endpoint" story into a
 * single artifact: a qScan CBOM (code + infrastructure-as-code/config) and a
 * qProbe CBOM (live endpoints) both emit `cryptographic-asset` components keyed by
 * a deterministic `bom-ref` per (algorithm, primitive), so merging is a union with
 * dedup — the same crypto seen by two planes collapses to one component whose
 * occurrence evidence spans both.
 *
 * Output is deterministic (components sorted by bom-ref, occurrences sorted by
 * location, a stable serial derived from the merged content), so re-merging the
 * same inputs yields byte-identical output.
 */
import { createHash } from "node:crypto";
import type { CycloneDxBom, CbomComponent } from "./cbom.js";

/** Occurrence record shape inside a component's `evidence.occurrences`. */
interface Occurrence {
  location: string;
  additionalContext?: string;
}

function occurrencesOf(c: CbomComponent): Occurrence[] {
  const ev = c.evidence as { occurrences?: unknown } | undefined;
  const occ = ev?.occurrences;
  return Array.isArray(occ) ? (occ as Occurrence[]) : [];
}

const HNDL_PROP = "quantakrypto:harvestNowDecryptLater";

function hndlOf(c: CbomComponent): boolean {
  // The flag is carried as a CycloneDX component `property` (name/value). Fall back
  // to the legacy `cryptoProperties.harvestNowDecryptLater` location so an
  // externally-authored / older CBOM still merges correctly.
  const prop = c.properties?.find((p) => p.name === HNDL_PROP);
  if (prop) return prop.value === "true";
  return (
    (c.cryptoProperties as { harvestNowDecryptLater?: unknown } | undefined)
      ?.harvestNowDecryptLater === true
  );
}

/** Return a copy of `props` with the HNDL flag set to `value`. */
function withHndl(
  props: { name: string; value: string }[] | undefined,
  value: boolean,
): { name: string; value: string }[] {
  const rest = (props ?? []).filter((p) => p.name !== HNDL_PROP);
  return [...rest, { name: HNDL_PROP, value: String(value) }];
}

/** Union + dedup occurrences by `location`, sorted deterministically. */
function mergeOccurrences(a: Occurrence[], b: Occurrence[]): Occurrence[] {
  const byLoc = new Map<string, Occurrence>();
  for (const o of [...a, ...b]) if (!byLoc.has(o.location)) byLoc.set(o.location, o);
  return [...byLoc.values()].sort((x, y) =>
    x.location < y.location ? -1 : x.location > y.location ? 1 : 0,
  );
}

/**
 * Merge CBOMs into one. Components with the same `bom-ref` (same algorithm +
 * primitive) are combined; their occurrence evidence is unioned and their
 * harvest-now-decrypt-later flag is OR-ed. Tool and root metadata from every input
 * is preserved.
 */
export function mergeCboms(boms: readonly CycloneDxBom[]): CycloneDxBom {
  const byRef = new Map<string, CbomComponent>();
  const toolComponents: unknown[] = [];
  const toolSeen = new Set<string>();
  const roots: string[] = [];

  for (const bom of boms) {
    // Collect tool + root metadata (dedup tools by name@version).
    const tools = (bom.metadata as { tools?: { components?: unknown[] } })?.tools?.components;
    if (Array.isArray(tools)) {
      for (const t of tools) {
        const tc = t as { name?: string; version?: string };
        const key = `${tc.name}@${tc.version}`;
        if (!toolSeen.has(key)) {
          toolSeen.add(key);
          toolComponents.push(t);
        }
      }
    }
    const root = (bom.metadata as { component?: { name?: string } })?.component?.name;
    if (typeof root === "string" && root && !roots.includes(root)) roots.push(root);

    // `components` is optional in the CycloneDX 1.6 spec — a legal CBOM can carry none
    // (a scan that found nothing). Treat a missing array as empty instead of crashing.
    for (const c of bom.components ?? []) {
      const ref = c["bom-ref"];
      const existing = byRef.get(ref);
      if (!existing) {
        // Deep-ish copy so we can mutate evidence/properties without touching the input.
        byRef.set(ref, {
          ...c,
          cryptoProperties: { ...c.cryptoProperties },
          properties: c.properties ? [...c.properties] : undefined,
          evidence: { occurrences: occurrencesOf(c) },
        });
      } else {
        const merged = mergeOccurrences(occurrencesOf(existing), occurrencesOf(c));
        existing.evidence = { occurrences: merged };
        // OR the harvest-now-decrypt-later flag across the merged copies.
        existing.properties = withHndl(existing.properties, hndlOf(existing) || hndlOf(c));
      }
    }
  }

  const components = [...byRef.values()].sort((a, b) =>
    a["bom-ref"] < b["bom-ref"] ? -1 : a["bom-ref"] > b["bom-ref"] ? 1 : 0,
  );

  // Content-address the serial over bom-refs AND their occurrence locations (+ roots),
  // so two merges that differ only in occurrence evidence get distinct serials — a
  // CycloneDX serialNumber is meant to identify a BOM *instance*, and downstream
  // bom-link/dedup tooling relies on that. Occurrences are already sorted.
  const serialSeed =
    components
      .map(
        (c) =>
          `${c["bom-ref"]}#${occurrencesOf(c)
            .map((o) => o.location)
            .join(",")}`,
      )
      .join("|") + `|${roots.join(",")}`;
  const h = createHash("sha256").update(serialSeed, "utf8").digest("hex");
  const serial = `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${serial}`,
    version: 1,
    metadata: {
      tools: { components: toolComponents },
      component: {
        type: "application",
        "bom-ref": "root",
        name: roots.length ? `combined: ${roots.join(" + ")}` : "combined",
      },
    },
    components,
  };
}
