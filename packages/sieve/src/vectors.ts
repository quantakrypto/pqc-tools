/**
 * Loader for OFFICIAL NIST ACVP Known-Answer-Test (KAT) vector files.
 *
 * HONESTY NOTE: Sieve ships NO cryptographic test vectors. It does not and must
 * not fabricate expected pk/sk/ct/ss/sig bytes. This module only PARSES vector
 * files that the user downloads from NIST and points Sieve at via --vectors.
 * See vectors/README.md for where to obtain them and the file format.
 *
 * Supported input: the NIST ACVP-server JSON format for ML-KEM (keyGen,
 * encapDecap) and ML-DSA (keyGen, sigGen, sigVer). The ACVP JSON encodes bytes
 * as hex strings. We normalize the fields we need into a flat list of typed
 * test cases. Anything we don't recognize is ignored (not invented).
 *
 * Uses only node:fs. No cryptography.
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { isParamSet } from "./sizes.js";
import type { Family, ParamSet } from "./sizes.js";

/** A normalized ML-KEM keygen vector: seed -> (pk, sk). */
interface KemKeygenVector {
  kind: "kem-keygen";
  param: ParamSet;
  /** Concatenated d||z seed (hex-decoded). */
  seed?: Uint8Array;
  pk: Uint8Array;
  sk: Uint8Array;
}

/** A normalized ML-KEM encapsulation vector: (pk, coins) -> (ct, ss). */
interface KemEncapVector {
  kind: "kem-encap";
  param: ParamSet;
  pk: Uint8Array;
  /** Encapsulation coins/message m (hex-decoded), if present. */
  coins?: Uint8Array;
  ct: Uint8Array;
  ss: Uint8Array;
}

/** A normalized ML-KEM decapsulation vector: (sk, ct) -> ss. */
interface KemDecapVector {
  kind: "kem-decap";
  param: ParamSet;
  sk: Uint8Array;
  ct: Uint8Array;
  ss: Uint8Array;
}

/** A normalized ML-DSA signature-verification vector: (pk, msg, sig) -> ok. */
interface DsaVerifyVector {
  kind: "dsa-verify";
  param: ParamSet;
  pk: Uint8Array;
  msg: Uint8Array;
  sig: Uint8Array;
  expected: boolean;
}

/** Any normalized vector. */
export type Vector = KemKeygenVector | KemEncapVector | KemDecapVector | DsaVerifyVector;

/**
 * Provenance of one ACVP vector file (docs/compliance/acvp-provenance.md): a
 * content hash over the RAW bytes plus the declared source, so a passing `kat`
 * run is traceable to the exact operator-supplied inputs. Sieve records what it
 * was given; it never fetches or ships vectors (ADR-0004).
 */
export interface VectorFileProvenance {
  path: string;
  sha256: string;
  sizeBytes: number;
  algorithm: string | null;
  mode: string | null;
  /** Parameter sets seen in the file. */
  parameterSets: string[];
  /** Operator-declared origin, or "unknown (operator-supplied)". */
  sourceUrl: string;
  /** Recognized test cases consumed from this file. */
  casesUsed: number;
}

/** Result of scanning a vectors directory. */
export interface VectorSet {
  vectors: Vector[];
  /** Files that were read. */
  files: string[];
  /** Non-fatal parse notes (unrecognized files/groups). */
  notes: string[];
  /** Per-file provenance for every vector file used (kat traceability). */
  provenance: VectorFileProvenance[];
  /** True when the operator declared a source via `vectors-manifest.json`. */
  provenanceDeclared: boolean;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error(`invalid hex string (len ${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Map an ACVP parameterSet string to our canonical ParamSet, or undefined.
 * ACVP uses e.g. "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s" — lower-casing
 * and `_`→`-` yields our canonical ids for all three families (incl. FIPS 205). */
function normParam(family: Family, raw: unknown): ParamSet | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.toLowerCase().replace(/_/g, "-");
  if (isParamSet(s) && s.startsWith(family)) return s;
  return undefined;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asObj(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}
function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/**
 * Parse one ACVP test-vectors JSON document into normalized vectors.
 * The ACVP shape is: { algorithm, mode, testGroups: [{ parameterSet, tests:[...] }] }.
 */
function parseAcvpDocument(doc: unknown, notes: string[], file: string): Vector[] {
  const root = asObj(doc);
  const algorithm = str(root["algorithm"])?.toUpperCase() ?? "";
  const mode = str(root["mode"])?.toLowerCase() ?? "";
  const out: Vector[] = [];

  // Order matters: "SLH-DSA" contains "DSA", so test SLH before the ML-DSA branch.
  const family: Family | undefined = algorithm.includes("KEM")
    ? "ml-kem"
    : algorithm.includes("SLH")
      ? "slh-dsa"
      : algorithm.includes("DSA")
        ? "ml-dsa"
        : undefined;
  if (family === undefined) {
    notes.push(`${file}: unrecognized algorithm "${algorithm}", skipped`);
    return out;
  }

  for (const groupRaw of asArray(root["testGroups"])) {
    const group = asObj(groupRaw);
    const param = normParam(family, group["parameterSet"]);
    if (param === undefined) {
      notes.push(`${file}: skipped group with parameterSet=${String(group["parameterSet"])}`);
      continue;
    }
    const fn = str(group["function"])?.toLowerCase(); // encapDecap: "encapsulation"/"decapsulation"

    for (const testRaw of asArray(group["tests"])) {
      const t = asObj(testRaw);
      try {
        if (family === "ml-kem") {
          if (mode.includes("keygen")) {
            const d = str(t["d"]);
            const z = str(t["z"]);
            const seedHex = str(t["seed"]) ?? (d && z ? d + z : undefined);
            out.push({
              kind: "kem-keygen",
              param,
              ...(seedHex ? { seed: hexToBytes(seedHex) } : {}),
              pk: hexToBytes(reqHex(t, "ek", "pk")),
              sk: hexToBytes(reqHex(t, "dk", "sk")),
            });
          } else if (mode.includes("encapdecap") || mode.includes("encap")) {
            // function may distinguish encapsulation vs decapsulation cases.
            if (fn === "decapsulation" || ("dk" in t && "c" in t)) {
              out.push({
                kind: "kem-decap",
                param,
                sk: hexToBytes(reqHex(t, "dk", "sk")),
                ct: hexToBytes(reqHex(t, "c", "ct")),
                ss: hexToBytes(reqHex(t, "k", "ss")),
              });
            } else {
              const m = str(t["m"]);
              out.push({
                kind: "kem-encap",
                param,
                pk: hexToBytes(reqHex(t, "ek", "pk")),
                ...(m ? { coins: hexToBytes(m) } : {}),
                ct: hexToBytes(reqHex(t, "c", "ct")),
                ss: hexToBytes(reqHex(t, "k", "ss")),
              });
            }
          } else {
            notes.push(`${file}: unrecognized ML-KEM mode "${mode}"`);
          }
        } else {
          // ML-DSA / SLH-DSA: we can robustly check sigVer cases (verdict-driven).
          if (mode.includes("sigver") || ("signature" in t && "pk" in t)) {
            const expected = t["testPassed"];
            // NIST ACVP sigVer files mix valid and INTENTIONALLY-INVALID
            // signatures; the expected verdict lives in `testPassed`. If that
            // field is absent (or not a boolean) we cannot know whether the
            // signature should verify, so we SKIP the case rather than invent
            // `true` — defaulting to true flags a conformant SUT (which
            // correctly returns valid:false on a bad signature) as failing.
            if (typeof expected !== "boolean") {
              notes.push(`${file}: skipped a sigVer case with no boolean "testPassed" verdict`);
              continue;
            }
            out.push({
              kind: "dsa-verify",
              param,
              pk: hexToBytes(reqHex(t, "pk", "ek")),
              msg: hexToBytes(reqHex(t, "message", "msg")),
              sig: hexToBytes(reqHex(t, "signature", "sig")),
              expected,
            });
          } else {
            notes.push(`${file}: ML-DSA mode "${mode}" not used for KAT (sign is nonce-dependent)`);
          }
        }
      } catch (err) {
        notes.push(`${file}: skipped a test case: ${(err as Error).message}`);
      }
    }
  }
  return out;
}

/** Read the first present hex field among `keys`, else throw. */
function reqHex(t: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = str(t[k]);
    if (v !== undefined) return v;
  }
  throw new Error(`missing field (any of: ${keys.join(", ")})`);
}

/**
 * Load and normalize all `*.json` ACVP vector files in `dir`.
 *
 * @throws if `dir` does not exist or contains no readable JSON files.
 */
/** Operator-declared source manifest filename (not itself a vector file). */
const VECTORS_MANIFEST = "vectors-manifest.json";

export function loadVectors(dir: string): VectorSet {
  const st = statSync(dir); // throws ENOENT if missing
  if (!st.isDirectory()) {
    throw new Error(`--vectors path is not a directory: ${dir}`);
  }

  // Optional provenance manifest: `{ "sourceUrl": "https://…" }` declaring where
  // the operator obtained these vectors. Absent → provenance is undeclared.
  let declaredSource: string | undefined;
  try {
    const m = JSON.parse(readFileSync(join(dir, VECTORS_MANIFEST), "utf8")) as {
      sourceUrl?: unknown;
    };
    if (typeof m.sourceUrl === "string" && m.sourceUrl.trim()) declaredSource = m.sourceUrl.trim();
  } catch {
    /* no manifest — provenanceDeclared stays false */
  }

  const entries = readdirSync(dir).filter(
    (f) => f.toLowerCase().endsWith(".json") && f.toLowerCase() !== VECTORS_MANIFEST,
  );
  if (entries.length === 0) {
    throw new Error(`no .json vector files found in ${dir}`);
  }

  const vectors: Vector[] = [];
  const files: string[] = [];
  const notes: string[] = [];
  const provenance: VectorFileProvenance[] = [];

  for (const name of entries) {
    const path = join(dir, name);
    // Hash the RAW bytes as supplied, before parsing — proves exactly what was used.
    const raw = readFileSync(path);
    const sha256 = createHash("sha256").update(raw).digest("hex");
    let doc: unknown;
    try {
      doc = JSON.parse(raw.toString("utf8"));
    } catch (err) {
      notes.push(`${name}: not valid JSON (${(err as Error).message})`);
      continue;
    }
    files.push(name);
    const before = vectors.length;
    // ACVP test-vector files may be a single object or an array of prompts.
    const docs = Array.isArray(doc) ? doc : [doc];
    for (const d of docs) {
      vectors.push(...parseAcvpDocument(d, notes, name));
    }

    // Best-effort ACVP metadata for the provenance record.
    const root = asObj(docs[0]);
    const params = new Set<string>();
    for (const g of asArray(root["testGroups"])) {
      const p = str(asObj(g)["parameterSet"]);
      if (p) params.add(p);
    }
    provenance.push({
      path: name,
      sha256,
      sizeBytes: raw.length,
      algorithm: str(root["algorithm"]) ?? null,
      mode: str(root["mode"]) ?? null,
      parameterSets: [...params],
      sourceUrl: declaredSource ?? "unknown (operator-supplied)",
      casesUsed: vectors.length - before,
    });
  }

  return { vectors, files, notes, provenance, provenanceDeclared: declaredSource !== undefined };
}
