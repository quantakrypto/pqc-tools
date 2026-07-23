/**
 * @quantakrypto/core — shared types (the locked public contract).
 *
 * These types are the stable interface between every tool in the monorepo
 * (qScan, the MCP server, the GitHub Action). Treat additions as backwards
 * compatible; treat renames/removals as breaking.
 */

/** How serious a finding is, ordered most → least severe. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How sure the detector is that the finding is a real use of the algorithm. */
export type Confidence = "high" | "medium" | "low";

/** What kind of cryptographic concern a finding represents. */
export type FindingCategory =
  | "kem" // key encapsulation / public-key encryption (e.g. RSA-OAEP)
  | "key-exchange" // (EC)DH
  | "signature" // RSA/ECDSA/EdDSA signing
  | "tls" // transport configuration
  | "certificate" // X.509 / PKI material
  | "dependency" // a quantum-vulnerable library in the dependency tree
  | "hash" // weak / pre-quantum hash usage
  | "rng"; // randomness concerns

/** Classical asymmetric algorithm families that are not quantum-safe. */
export type AlgorithmFamily =
  "RSA" | "ECDH" | "ECDSA" | "EdDSA" | "DH" | "DSA" | "X25519" | "X448" | "ECIES" | "unknown";

/** A precise location inside a scanned file. */
export interface SourceLocation {
  /** Path relative to the scan root, using POSIX separators. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** 1-based column number, if known. */
  column?: number;
  /** 1-based end line, for multi-line matches. */
  endLine?: number;
  /** The matched source text (trimmed, single line). */
  snippet?: string;
}

/** Relative urgency an LLM triage pass assigns to a finding. */
export type TriagePriority = "now" | "soon" | "later";

/**
 * Optional LLM triage annotation attached to a finding by `qscan --triage`.
 * Purely additive: it re-ranks and explains, it never suppresses a finding and
 * never influences the exit code (which is computed from `severity` alone).
 */
export interface TriageAnnotation {
  /** 0–100 real-world exposure/exploitability estimate. */
  exposureScore: number;
  priority: TriagePriority;
  rationale: string;
}

/** A single detected concern. */
export interface Finding {
  /** Stable rule identifier, e.g. "rsa-keygen", "ecdh-usage", "tls-legacy-version", "dep-vulnerable". */
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  /** The classical algorithm involved, when applicable. */
  algorithm?: AlgorithmFamily;
  /** True when this is exposed to "harvest now, decrypt later". */
  hndl: boolean;
  /** One-line human explanation of the concern. */
  message: string;
  /** Suggested post-quantum remediation (e.g. ML-KEM, hybrid X25519MLKEM768). */
  remediation?: string;
  /** Associated CWE identifier, e.g. "CWE-327" (broken crypto), "CWE-326" (weak strength). */
  cwe?: string;
  /**
   * True when the matched snippet IS the sensitive value (e.g. a PEM private/
   * public key block, an `ssh-rsa AAAA…` public key). Reporters ALWAYS drop the
   * snippet for such findings, regardless of any redaction flag.
   */
  sensitive?: boolean;
  /** Optional LLM triage annotation (`qscan --triage`); never affects exit code. */
  triage?: TriageAnnotation;
  location: SourceLocation;
}

/** Package ecosystems the dependency scanner understands. */
export type DependencyEcosystem = "npm" | "pypi" | "cargo" | "go" | "maven" | "rubygems" | "nuget";

/** A known quantum-vulnerable dependency entry. */
export interface VulnerableDependency {
  /** Package name (as written in the ecosystem's manifest). */
  name: string;
  ecosystem: DependencyEcosystem;
  /** Why it's flagged (what classical crypto it provides). */
  reason: string;
  /** Algorithm families the package primarily exposes. */
  algorithms: AlgorithmFamily[];
  severity: Severity;
  /**
   * Explicit harvest-now-decrypt-later override. When omitted, HNDL is inferred
   * from whether any listed family is a confidentiality family. Set `false` for
   * signing-only packages (e.g. JWS/JWT libraries) that list RSA/EC as families
   * but never do key transport or key agreement — signatures are not HNDL-exposed.
   */
  hndl?: boolean;
}

/**
 * Which logical scope a detector belongs to. Drives the source/config scope
 * toggles in {@link ScanOptions} (replacing the old ruleId-prefix inference).
 */
export type DetectorScope = "source" | "config";

/**
 * The programming language / surface a detector targets. `"any"` means the
 * detector is language-agnostic (e.g. PEM material, config files).
 */
export type DetectorLanguage =
  | "js"
  | "python"
  | "go"
  | "java"
  | "csharp"
  | "rust"
  | "ruby"
  | "php"
  | "elixir"
  | "c"
  | "swift"
  | "objc"
  | "dart"
  | "solidity"
  | "any";

/**
 * Declarative metadata for a single rule a detector can emit. This is the
 * catalog entry: the stable, queryable description of a rule keyed by the
 * `ruleId` it stamps onto findings. It is the single source of truth for a
 * rule's title / severity / category / remediation, consumed by the SARIF
 * `rules[]` block, the MCP `explain_finding` resolver, and future per-rule
 * enable/disable + language-pack work.
 *
 * For most rules the metadata is fixed and `detect()` builds findings straight
 * from it (see `findingFromRule`). A few rules are inherently multi-variant
 * (e.g. `node-crypto-keygen` spans RSA/EC/DSA/DH/Ed25519 at different
 * severities); for those the metadata here is a REPRESENTATIVE umbrella and
 * `detect()` refines the per-finding fields at match time. The catalog always
 * enumerates every emittable ruleId regardless.
 */
export interface RuleMeta {
  /** Stable rule id — matches {@link Finding.ruleId}. Unique across the catalog. */
  id: string;
  /** Canonical human title. */
  title: string;
  category: FindingCategory;
  severity: Severity;
  /** Default confidence for findings of this rule. */
  confidence: Confidence;
  /** Harvest-now-decrypt-later exposure. */
  hndl: boolean;
  /** Representative classical algorithm family; refined per-finding when it varies. */
  algorithm?: AlgorithmFamily;
  /** Associated CWE identifier (e.g. "CWE-327"). */
  cwe?: string;
  /** Suggested post-quantum remediation. When omitted, derived from {@link algorithm}. */
  remediation?: string;
  /** Canonical one-line human explanation; may be refined per-finding. */
  message: string;
  /** True when this rule's matched snippet IS sensitive key material. */
  sensitive?: boolean;
  /** Short description of what the rule detects (for catalog / MCP surfaces). */
  description?: string;
}

/** A pluggable source detector. Detectors are pure and stateless. */
export interface Detector {
  /** Unique id, used as the Finding.ruleId prefix space. */
  id: string;
  /** Human description of what the detector looks for. */
  description: string;
  /**
   * Logical scope of this detector's findings. Used by `scan()` to honour the
   * `config` / `source` toggles. Defaults to `"source"` when omitted (for
   * backward compatibility with externally-defined detectors).
   */
  scope?: DetectorScope;
  /**
   * Language this detector targets, for documentation / registry filtering.
   * Defaults to `"js"` when omitted.
   */
  language?: DetectorLanguage;
  /**
   * The rules this detector can emit, as declarative metadata. Together across
   * all detectors these form the rule catalog ({@link DetectorRegistry.ruleCatalog}).
   * Optional for backward compatibility with externally-defined detectors, but
   * all built-in detectors declare it.
   */
  rules?: RuleMeta[];
  /** Whether this detector should run against the given file path. */
  appliesTo(filePath: string): boolean;
  /** Inspect a single file's contents and return zero or more findings. */
  detect(input: DetectorInput): Finding[];
}

export interface DetectorInput {
  /** Path relative to the scan root (POSIX). */
  file: string;
  /** Full file contents. */
  content: string;
}

/** Options controlling a scan. */
export interface ScanOptions {
  /** Absolute or relative directory (or single file) to scan. */
  root: string;
  /**
   * Restrict the walk to paths matching one of these include patterns
   * (substring or relative-path-prefix match). When omitted, all non-excluded
   * files are scanned. Wired into the walker.
   */
  include?: string[];
  /** Extra exclude patterns (in addition to the built-in defaults). */
  exclude?: string[];
  /** Disable the built-in ignore list (node_modules, .git, dist, …). */
  noDefaultIgnores?: boolean;
  /** Scan source files for inline crypto usage. Default: true. */
  source?: boolean;
  /** Scan dependency manifests/lockfiles for vulnerable libraries. Default: true. */
  dependencies?: boolean;
  /** Scan config files (TLS, certificates). Default: true. */
  config?: boolean;
  /** Max file size to read, in bytes. Default: 2 MiB. */
  maxFileSize?: number;
  /**
   * Scan minified / generated / bundled files (large single-line content)
   * instead of skipping them. Default: false (skip them for speed).
   */
  scanMinified?: boolean;
  /**
   * Explicit relative file list (POSIX, relative to `root`) to scan instead of
   * walking the tree. Used for incremental / changed-files scans. Each path is
   * still subject to the binary / size filters. When set, the directory walk is
   * bypassed entirely.
   */
  files?: string[];
  /**
   * Override / extend the built-in detector set. When omitted, the default
   * registry's detectors are used.
   */
  detectors?: Detector[];
  /**
   * Rule ids to suppress. Any finding whose `ruleId` is listed here is dropped
   * after detection. Serializable (a plain string array), so it is honoured on
   * both the serial and the worker-thread (`scanParallel`) paths. See the rule
   * catalog ({@link DetectorRegistry.ruleCatalog}) for the valid ids.
   */
  disabledRules?: string[];
  /**
   * Path to an on-disk scan cache. When set, unchanged files (same content hash)
   * reuse their previous findings instead of re-running detectors, and the cache
   * is rewritten after the scan. Invalidated wholesale when the tool version,
   * detector set, or `disabledRules` change. Optional; omitted = no caching.
   * The cache forces the in-process (serial) path.
   */
  cacheFile?: string;
  /** Optional progress callback. */
  onFile?: (file: string) => void;
  /**
   * Optional abort signal. When it fires mid-walk the scan stops cooperatively
   * and rejects with an `AbortError` (a `DOMException`-like error with
   * `name === "AbortError"`).
   */
  signal?: AbortSignal;
  /**
   * Work budget: maximum number of files to scan. When exceeded mid-walk the
   * scan stops and throws a `BudgetExceededError`. Unlimited when omitted.
   */
  maxFiles?: number;
  /**
   * Work budget: maximum cumulative bytes of scanned file content. When
   * exceeded mid-walk the scan stops and throws a `BudgetExceededError`.
   * Unlimited when omitted.
   */
  maxBytes?: number;
}

/** Extra options for {@link scanParallel}, layered onto {@link ScanOptions}. */
export interface ParallelScanOptions extends ScanOptions {
  /**
   * Number of worker threads. Default: `os.availableParallelism()`. A value of
   * 0 or 1 forces the in-process serial path.
   */
  concurrency?: number;
  /**
   * Combined-size floor (bytes) below which the scan always runs in-process.
   * Default: 2 MiB. Also stays serial below `parallelFileThreshold` files.
   */
  parallelThresholdBytes?: number;
  /** File-count floor below which the scan always runs in-process. Default: 200. */
  parallelFileThreshold?: number;
  /** Target bytes per worker chunk. Default: 4 MiB. */
  chunkBytes?: number;
}

/** Aggregated counts produced from a scan's findings. */
export interface CryptoInventory {
  byAlgorithm: Partial<Record<AlgorithmFamily, number>>;
  byCategory: Partial<Record<FindingCategory, number>>;
  bySeverity: Record<Severity, number>;
  /** Number of findings exposed to harvest-now-decrypt-later. */
  hndlCount: number;
  /** 0–100 readiness score (100 = no classical asymmetric crypto found). */
  readinessScore: number;
}

/**
 * Non-fatal things that happened during a scan that reduce coverage. Surfaced so
 * a silent under-scan (e.g. half the tree was unreadable) can't masquerade as a
 * clean "0 findings" result — reporters warn when any count is non-zero.
 */
export interface ScanDiagnostics {
  /** Files that could not be read (permissions, vanished, decode failure) and were skipped. */
  unreadable: number;
  /** Files skipped because they look machine-minified / generated (scan with `scanMinified` to include). */
  skippedMinified: number;
}

/** The full result of a scan. */
export interface ScanResult {
  /** The scan root (as provided). */
  root: string;
  findings: Finding[];
  filesScanned: number;
  /**
   * Coverage diagnostics: counts of files skipped as unreadable or minified.
   * Optional for backward compatibility with hand-built results.
   */
  diagnostics?: ScanDiagnostics;
  /**
   * Of `filesScanned`, how many were in a source language the scanner can actually
   * analyze for inline crypto (the 13 packs: JS/TS, Python, Go, Java/Kotlin/Scala,
   * C#, Rust, Ruby, PHP, Elixir, C/C++, Swift, Objective-C, Dart). When this is 0
   * but `filesScanned` > 0, the readiness score reflects NO analyzable code — the
   * crypto likely lives in an unsupported language (Lua, Perl, …) — and
   * reporters surface that so a bare 100/100 can't read as "safe". Optional for
   * backward compatibility with hand-built results.
   */
  analyzedFiles?: number;
  inventory: CryptoInventory;
  /** ISO timestamps. */
  startedAt: string;
  finishedAt: string;
  /** Tool version that produced the result. */
  toolVersion: string;
}

/** Output formats qScan / reporters can emit. */
export type ReportFormat = "human" | "json" | "sarif";

/** A remediation recommendation for a classical algorithm. */
export interface Remediation {
  algorithm: AlgorithmFamily;
  /** Short recommended replacement, e.g. "ML-KEM-768 (hybrid X25519MLKEM768)". */
  recommendation: string;
  /** Longer rationale. */
  detail: string;
}
