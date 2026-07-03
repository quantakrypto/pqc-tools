/**
 * quantakrypto MCP tools, backed by {@link @quantakrypto/core}.
 *
 * Every tool returns an MCP {@link ToolResult} ({ content, isError? }). Each
 * handler runs core calls through {@link safe} so any runtime failure (a bad
 * path, a work-budget overflow, an unexpected error) surfaces as a readable
 * `isError` tool result with host details stripped, rather than a protocol-level
 * crash.
 */

import process from "node:process";

import {
  VERSION,
  AbortError,
  BudgetExceededError,
  buildInventory,
  detectFile,
  detectors,
  remediationFor,
  scan,
  SEVERITY_ORDER,
  toCbom,
  vulnerableDependencies,
} from "@quantakrypto/core";
import type {
  AlgorithmFamily,
  CryptoInventory,
  Finding,
  Remediation,
  ScanOptions,
  ScanResult,
  VulnerableDependency,
} from "@quantakrypto/core";

import { errorResult, textResult } from "./protocol.js";
import type { JsonSchema, ToolContext, ToolDefinition, ToolResult } from "./protocol.js";
import { resolveRule } from "./rules.js";
import { resolveFsConfig, resolveScanPath } from "./fsconfig.js";

/** All classical algorithm families we can advise on, used for validation/help. */
const ALGORITHM_FAMILIES: AlgorithmFamily[] = [
  "RSA",
  "ECDH",
  "ECDSA",
  "EdDSA",
  "DH",
  "DSA",
  "X25519",
  "X448",
  "ECIES",
  "unknown",
];

/**
 * Map a core failure to a caller-safe message. Cancellation and budget overflows
 * are intentional, expected outcomes — their messages are author-controlled and
 * carry no host detail, so they pass through. Every other error may embed a
 * server path (an `ENOENT … '/etc/shadow'`, a stack), so it is logged locally
 * and replaced with a generic string; the remote caller never sees internals.
 */
function describeError(label: string, err: unknown): string {
  if (err instanceof AbortError) return `${label} was aborted (request timed out).`;
  if (err instanceof BudgetExceededError) {
    // Author-written, no host detail: "maxFiles budget exceeded (limit: …)".
    return `${label} failed: ${err.message}`;
  }
  const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
  process.stderr.write(`quantakrypto MCP: ${label} failed: ${detail}\n`);
  return `${label} failed: an internal error occurred.`;
}

/**
 * Run a possibly-throwing core call, mapping any failure to an error tool
 * result. Returns either the value or a {@link ToolResult} sentinel. Error
 * messages are sanitized via {@link describeError} so server paths never leak.
 */
async function safe<T>(
  label: string,
  fn: () => T | Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; result: ToolResult }> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, result: errorResult(describeError(label, err)) };
  }
}

/**
 * Resolve the FS-tool policy (root allow-list + work budgets) once per call from
 * the live environment, then validate the caller's path against it and assemble
 * the {@link ScanOptions} for a confined, bounded, cancellable scan.
 *
 * Returns an `errorResult` when the path escapes the allow-list (a `..`
 * traversal or an out-of-root absolute path), so the FS tools can `return` it
 * directly. The `signal` from the transport's request deadline (when present) is
 * threaded in so a timed-out request actually aborts the underlying scan.
 */
function buildScanOptions(
  requested: string,
  context?: ToolContext,
): { ok: true; options: ScanOptions } | { ok: false; result: ToolResult } {
  const config = resolveFsConfig(process.env);
  const decision = resolveScanPath(config, requested);
  if (!decision.ok) {
    return { ok: false, result: errorResult(`scan rejected: ${decision.reason}`) };
  }
  return {
    ok: true,
    options: {
      root: decision.path,
      signal: context?.signal,
      maxFiles: config.maxFiles,
      maxBytes: config.maxBytes,
    },
  };
}

/** Map a free-text algorithm string onto a known {@link AlgorithmFamily}. */
function normalizeAlgorithm(input: string): AlgorithmFamily {
  const cleaned = input
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  for (const fam of ALGORITHM_FAMILIES) {
    if (fam.toUpperCase() === cleaned) return fam;
  }
  // Common aliases / families folded into the canonical set.
  if (cleaned.startsWith("RSA")) return "RSA";
  if (cleaned.includes("ECDSA")) return "ECDSA";
  if (cleaned.includes("ED25519") || cleaned.includes("EDDSA")) return "EdDSA";
  if (cleaned.includes("X448") || cleaned.includes("CURVE448")) return "X448";
  if (cleaned.includes("X25519") || cleaned.includes("CURVE25519")) return "X25519";
  if (cleaned.includes("ECDH")) return "ECDH";
  if (cleaned.includes("ECIES")) return "ECIES";
  if (cleaned === "DH" || cleaned.includes("DIFFIEHELLMAN")) return "DH";
  if (cleaned === "DSA") return "DSA";
  return "unknown";
}

/** Render a scan result as a compact human-readable summary. */
function summarizeScan(result: ScanResult): string {
  const inv = result.inventory;
  const lines: string[] = [];
  lines.push(`quantakrypto scan of ${result.root}`);
  lines.push(`Files scanned: ${result.filesScanned}`);
  lines.push(`Findings: ${result.findings.length}`);
  lines.push(`Readiness score: ${inv.readinessScore}/100`);
  lines.push(`Harvest-now-decrypt-later exposure: ${inv.hndlCount} finding(s)`);

  const sev = SEVERITY_ORDER.filter((s) => (inv.bySeverity[s] ?? 0) > 0)
    .map((s) => `${s}: ${inv.bySeverity[s]}`)
    .join(", ");
  if (sev) lines.push(`By severity: ${sev}`);

  const algos = Object.entries(inv.byAlgorithm)
    .filter(([, n]) => (n ?? 0) > 0)
    .map(([a, n]) => `${a}: ${n}`)
    .join(", ");
  if (algos) lines.push(`By algorithm: ${algos}`);

  if (result.findings.length > 0) {
    lines.push("");
    lines.push("Top findings:");
    const top = [...result.findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .slice(0, 20);
    for (const f of top) {
      const loc = `${f.location.file}:${f.location.line}`;
      lines.push(`- [${f.severity}] ${f.ruleId} (${loc}) — ${f.message}`);
    }
    if (result.findings.length > top.length) {
      lines.push(`… and ${result.findings.length - top.length} more.`);
    }
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const scanPathTool: ToolDefinition = {
  name: "scan_path",
  description:
    "Scan a file or directory for classical (quantum-vulnerable) asymmetric " +
    "cryptography using quantakrypto. Returns a readiness summary and findings.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to scan.",
      },
      format: {
        type: "string",
        enum: ["summary", "json"],
        description:
          "Output format: 'summary' (default) for readable text, 'json' for the raw ScanResult.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("scan_path requires a non-empty 'path' string.");
    }
    const format = args.format === "json" ? "json" : "summary";
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const result = scanned.value;
    if (format === "json") {
      return textResult(JSON.stringify(result, null, 2));
    }
    return textResult(summarizeScan(result));
  },
};

const inventoryCryptoTool: ToolDefinition = {
  name: "inventory_crypto",
  description:
    "Produce a post-quantum readiness inventory for a path: a 0-100 readiness " +
    "score plus counts of cryptographic findings by algorithm, category, and severity.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to inventory.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("inventory_crypto requires a non-empty 'path' string.");
    }
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const result = scanned.value;

    // Prefer a freshly built inventory from findings; fall back to the scan's own.
    const built = await safe<CryptoInventory>("buildInventory", () =>
      buildInventory(result.findings),
    );
    const inventory = built.ok ? built.value : result.inventory;

    const lines: string[] = [];
    lines.push(`Post-quantum readiness for ${result.root}`);
    lines.push(`Readiness score: ${inventory.readinessScore}/100`);
    lines.push(`HNDL exposure: ${inventory.hndlCount}`);
    lines.push("");
    lines.push("By algorithm:");
    for (const [algo, n] of Object.entries(inventory.byAlgorithm)) {
      if ((n ?? 0) > 0) lines.push(`  ${algo}: ${n}`);
    }
    lines.push("By category:");
    for (const [cat, n] of Object.entries(inventory.byCategory)) {
      if ((n ?? 0) > 0) lines.push(`  ${cat}: ${n}`);
    }
    lines.push("By severity:");
    for (const sev of SEVERITY_ORDER) {
      const n = inventory.bySeverity[sev] ?? 0;
      if (n > 0) lines.push(`  ${sev}: ${n}`);
    }
    return {
      content: [
        { type: "text", text: lines.join("\n") },
        { type: "text", text: JSON.stringify(inventory, null, 2) },
      ],
    };
  },
};

const explainFindingTool: ToolDefinition = {
  name: "explain_finding",
  description:
    "Explain a quantakrypto finding and its post-quantum remediation. Provide a " +
    "ruleId (e.g. 'forge-rsa-keygen', 'elliptic-ec', 'node-rsa', 'pem-ec-private-key') " +
    "and/or an algorithm (e.g. 'RSA', 'ECDSA'). The ruleId is resolved against the " +
    "core detector set, so library and config rules explain correctly.",
  inputSchema: {
    type: "object",
    properties: {
      ruleId: {
        type: "string",
        description: "The finding's rule id, matching a detector id prefix.",
      },
      algorithm: {
        type: "string",
        description: "The classical algorithm family involved (e.g. RSA, ECDH, ECDSA).",
      },
    },
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const ruleId = typeof args.ruleId === "string" ? args.ruleId.trim() : "";
    const algoInput = typeof args.algorithm === "string" ? args.algorithm.trim() : "";
    if (!ruleId && !algoInput) {
      return errorResult("explain_finding requires at least one of 'ruleId' or 'algorithm'.");
    }

    const lines: string[] = [];

    // Resolve the rule against core's actual detector set/registry (P0-5),
    // not by a fragile id-prefix match. Library rules (forge-*, elliptic-ec,
    // node-rsa, …) resolve to their `crypto-libs` detector and carry their
    // algorithm, so they now explain correctly.
    let resolvedAlgorithm: AlgorithmFamily | undefined;
    if (ruleId) {
      const resolved = resolveRule(ruleId);
      resolvedAlgorithm = resolved.algorithm;
      const meta = resolved.meta;
      lines.push(`Rule: ${meta ? `${ruleId} — ${meta.title}` : ruleId}`);
      if (resolved.detector) {
        lines.push(`Detector: ${resolved.detector.id} — ${resolved.detector.description}`);
      } else if (resolved.via === "unresolved") {
        lines.push(
          "No matching detector found in the catalog (rule may be unknown to this core version).",
        );
      }
      // Rule catalog metadata (severity / category / HNDL / remediation) so the
      // explanation is actionable on its own, not just a detector pointer.
      if (meta) {
        lines.push(
          `Severity: ${meta.severity} · Category: ${meta.category} · HNDL-exposed: ${meta.hndl ? "yes" : "no"}`,
        );
        lines.push(`What it detects: ${meta.description ?? meta.message}`);
        if (meta.remediation) lines.push(`Rule remediation: ${meta.remediation}`);
      }
    }

    // Prefer an explicit algorithm; otherwise use the one the rule resolved to.
    const algorithm: AlgorithmFamily | undefined = algoInput
      ? normalizeAlgorithm(algoInput)
      : resolvedAlgorithm && resolvedAlgorithm !== "unknown"
        ? resolvedAlgorithm
        : undefined;

    if (algorithm) {
      if (lines.length) lines.push("");
      lines.push(`Algorithm: ${algorithm}`);
      const rem = await safe<Remediation | undefined>("remediationFor", () =>
        remediationFor(algorithm),
      );
      if (rem.ok && rem.value) {
        lines.push(
          `Why it matters: ${algorithm} relies on hardness assumptions (integer factorization / discrete log) that Shor's algorithm breaks on a cryptographically-relevant quantum computer.`,
        );
        lines.push(`Recommendation: ${rem.value.recommendation}`);
        lines.push(`Detail: ${rem.value.detail}`);
      } else if (rem.ok) {
        lines.push("No specific remediation is registered for this algorithm.");
      } else {
        return rem.result;
      }
    }

    return textResult(lines.join("\n"));
  },
};

const suggestHybridTool: ToolDefinition = {
  name: "suggest_hybrid",
  description:
    "Recommend a post-quantum / hybrid migration. Provide an 'algorithm' " +
    "(e.g. RSA, ECDH, ECDSA) or free-text 'context' describing the usage.",
  inputSchema: {
    type: "object",
    properties: {
      algorithm: {
        type: "string",
        description: "Classical algorithm family to migrate away from.",
      },
      context: {
        type: "string",
        description:
          "Free-text description of the cryptographic usage (used when no algorithm is given).",
      },
    },
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const algoInput = typeof args.algorithm === "string" ? args.algorithm.trim() : "";
    const context = typeof args.context === "string" ? args.context.trim() : "";
    if (!algoInput && !context) {
      return errorResult("suggest_hybrid requires either 'algorithm' or 'context'.");
    }

    const algorithm = normalizeAlgorithm(algoInput || context);
    const lines: string[] = [];
    lines.push(`Migration guidance for: ${algoInput || context}`);
    lines.push(`Detected family: ${algorithm}`);

    const rem = await safe<Remediation | undefined>("remediationFor", () =>
      remediationFor(algorithm),
    );
    if (rem.ok && rem.value) {
      lines.push(`Recommended replacement: ${rem.value.recommendation}`);
      lines.push(`Rationale: ${rem.value.detail}`);
    } else {
      // Defensive fallback: core has a remediation for every known family, so
      // this only triggers if the lookup throws or the algorithm is unrecognised.
      lines.push(...staticHybridAdvice(algorithm));
    }

    lines.push("");
    lines.push(
      "Hybrid migrations combine a classical primitive with a NIST PQC algorithm " +
        "so security holds if either survives. Roll out hybrids first, then drop the " +
        "classical half once the PQC side is proven in your environment.",
    );
    return textResult(lines.join("\n"));
  },
};

/** Built-in PQC guidance used when core's remediation table is unavailable. */
function staticHybridAdvice(algorithm: AlgorithmFamily): string[] {
  switch (algorithm) {
    case "RSA":
    case "ECIES":
      return [
        "Recommended replacement: ML-KEM-768 for key establishment (hybrid X25519MLKEM768).",
        "For signatures use ML-DSA-65 (Dilithium) or SLH-DSA (SPHINCS+) where statelessness matters.",
      ];
    case "ECDH":
    case "DH":
    case "X25519":
      return [
        "Recommended replacement: hybrid X25519MLKEM768 key exchange (ML-KEM-768 + X25519).",
        "Supported in modern TLS 1.3 stacks; prefer the hybrid named group over bare ML-KEM.",
      ];
    case "ECDSA":
    case "EdDSA":
    case "DSA":
      return [
        "Recommended replacement: ML-DSA-65 (Dilithium) for general signatures.",
        "Use SLH-DSA (SPHINCS+) for long-lived roots or where a stateless hash-based scheme is preferred.",
      ];
    default:
      return [
        "Recommended replacement: adopt NIST PQC — ML-KEM for key establishment, ML-DSA for signatures.",
        "Deploy as hybrids (classical + PQC) during transition.",
      ];
  }
}

const listRulesTool: ToolDefinition = {
  name: "list_rules",
  description: "List the quantakrypto detector catalog: every detector id and what it looks for.",
  inputSchema: {
    type: "object",
    properties: {},
    additionalProperties: false,
  },
  async handler(): Promise<ToolResult> {
    const detectorList = await safe("detectors", () => detectors);
    if (!detectorList.ok) return detectorList.result;
    const catalog = detectorList.value.map((d) => ({ id: d.id, description: d.description }));
    if (catalog.length === 0) {
      return textResult(
        "No detectors are registered in @quantakrypto/core yet (the catalog is empty).",
      );
    }
    const human = catalog.map((d) => `- ${d.id}: ${d.description}`).join("\n");
    return {
      content: [
        {
          type: "text",
          text: `quantakrypto detector catalog (${catalog.length} rules):\n${human}`,
        },
        { type: "text", text: JSON.stringify(catalog, null, 2) },
      ],
    };
  },
};

const generateCbomTool: ToolDefinition = {
  name: "generate_cbom",
  description:
    "Scan a path and emit a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) " +
    "of the classical cryptographic assets found, for compliance / supply-chain " +
    "tooling. Reads the filesystem, so it is gated like scan_path over HTTP.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to inventory.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("generate_cbom requires a non-empty 'path' string.");
    }
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const cbom = await safe("toCbom", () => toCbom(scanned.value));
    if (!cbom.ok) return cbom.result;
    return textResult(JSON.stringify(cbom.value, null, 2));
  },
};

// ---------------------------------------------------------------------------
// Copilot tools — let an AI coding agent migrate *through* the deterministic
// engine ("the model proposes, the engine disposes"). plan_migration scans and
// orders the work; get_fix_examples shows the code change; verify_fix re-runs
// the detectors on the agent's edited code to confirm the classical crypto is
// actually gone; check_dependency and score_delta quantify the work.
// ---------------------------------------------------------------------------

/** Map a language name (or a filename's extension) to a source extension the detectors gate on. */
function languageToExtension(language: string): string | null {
  const l = language.trim().toLowerCase().replace(/^\./, "");
  const map: Record<string, string> = {
    js: ".js",
    javascript: ".js",
    jsx: ".jsx",
    ts: ".ts",
    typescript: ".ts",
    tsx: ".tsx",
    mjs: ".mjs",
    cjs: ".cjs",
    py: ".py",
    python: ".py",
    go: ".go",
    golang: ".go",
    java: ".java",
    kotlin: ".kt",
    kt: ".kt",
    cs: ".cs",
    csharp: ".cs",
    "c#": ".cs",
    dotnet: ".cs",
    rs: ".rs",
    rust: ".rs",
    rb: ".rb",
    ruby: ".rb",
    c: ".c",
    "c++": ".cpp",
    cpp: ".cpp",
    cc: ".cc",
    h: ".h",
    hpp: ".hpp",
  };
  return map[l] ?? null;
}

/** Before/after migration snippets per classical family. Static + deterministic. */
const FIX_EXAMPLES: Partial<
  Record<AlgorithmFamily, { note: string; before: string; after: string }>
> = {
  RSA: {
    note: "RSA key establishment → ML-KEM-768 (hybrid X25519MLKEM768). RSA signatures → ML-DSA-65.",
    before:
      "// key establishment\nconst { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });\nconst enc = crypto.publicEncrypt(publicKey, data);",
    after:
      "// hybrid KEM (e.g. @noble/post-quantum or a TLS 1.3 hybrid group)\nimport { MlKem768 } from 'mlkem';\nconst kem = new MlKem768();\nconst [encapsulated, sharedSecret] = await kem.encap(peerPublicKey); // pair with X25519 for hybrid",
  },
  ECDH: {
    note: "ECDH / DH key agreement → hybrid X25519MLKEM768 (ML-KEM-768 + X25519).",
    before:
      "const ecdh = crypto.createECDH('prime256v1');\nconst shared = ecdh.computeSecret(peerKey);",
    after:
      "// TLS: negotiate the X25519MLKEM768 named group. In app code, combine ML-KEM-768\n// with X25519 and KDF the concatenated secrets so security holds if either survives.",
  },
  DH: {
    note: "Finite-field DH → hybrid X25519MLKEM768.",
    before: "const dh = crypto.createDiffieHellman(2048);",
    after: "// Replace with ML-KEM-768 encapsulation, deployed as a hybrid with X25519.",
  },
  X25519: {
    note: "X25519 is modern but classical; wrap it in a hybrid X25519MLKEM768 rather than dropping it.",
    before: "const alice = crypto.generateKeyPairSync('x25519');",
    after: "// Keep X25519 AND add ML-KEM-768; derive the session key from both (hybrid).",
  },
  ECDSA: {
    note: "ECDSA signatures → ML-DSA-65 (Dilithium), or SLH-DSA where statelessness matters.",
    before: "const sig = crypto.sign('sha256', msg, ecPrivateKey);",
    after:
      "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\nconst sig = ml_dsa65.sign(mlDsaSecretKey, msg);",
  },
  EdDSA: {
    note: "Ed25519/Ed448 signatures → ML-DSA-65 (or a hybrid Ed25519+ML-DSA during transition).",
    before: "const sig = crypto.sign(null, msg, ed25519PrivateKey);",
    after:
      "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\nconst sig = ml_dsa65.sign(mlDsaSecretKey, msg);",
  },
  DSA: {
    note: "DSA is deprecated; rotate keys and migrate to ML-DSA-65.",
    before: "crypto.generateKeyPairSync('dsa', { modulusLength: 2048 });",
    after:
      "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\nconst keys = ml_dsa65.keygen();",
  },
};

const planMigrationTool: ToolDefinition = {
  name: "plan_migration",
  description:
    "Scan a path and return a deterministic, prioritized post-quantum migration " +
    "plan: findings grouped by algorithm, ordered harvest-now-decrypt-later first, " +
    "each with its PQC target and the readiness-score impact. Reads the filesystem, " +
    "so it is gated like scan_path over HTTP.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to plan a migration for.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("plan_migration requires a non-empty 'path' string.");
    }
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const plan = await buildMigrationPlan(scanned.value);
    return {
      content: [
        { type: "text", text: plan.human },
        { type: "text", text: JSON.stringify(plan.structured, null, 2) },
      ],
    };
  },
};

/** Migration-phase buckets, ordered by urgency. */
interface PlanGroup {
  algorithm: AlgorithmFamily;
  count: number;
  hndlCount: number;
  remediation: string;
  locations: string[];
}
interface PlanPhase {
  phase: number;
  title: string;
  rationale: string;
  groups: PlanGroup[];
}

/** Build a deterministic, prioritized migration plan from a scan result. */
async function buildMigrationPlan(
  result: ScanResult,
): Promise<{ human: string; structured: Record<string, unknown> }> {
  const findings = result.findings;
  const byPhase: Record<number, Finding[]> = { 1: [], 2: [], 3: [] };
  for (const f of findings) {
    // Phase 1: HNDL-exposed confidentiality (harvest now, decrypt later) — most urgent.
    // Phase 2: forgeable signatures. Phase 3: transport / certificate config.
    if (f.hndl) byPhase[1].push(f);
    else if (f.category === "tls" || f.category === "certificate") byPhase[3].push(f);
    else byPhase[2].push(f);
  }

  const phaseMeta: Record<number, { title: string; rationale: string }> = {
    1: {
      title: "Harvest-now-decrypt-later (do first)",
      rationale:
        "Key exchange / public-key encryption. Traffic captured today is decryptable once a quantum computer exists — migrate these first.",
    },
    2: {
      title: "Quantum-forgeable signatures",
      rationale:
        "Signatures are not retroactively broken, but become forgeable post-Q-day. Migrate before Q-day, prioritising long-lived keys.",
    },
    3: {
      title: "Transport & certificate configuration",
      rationale:
        "TLS versions, cipher suites, and certificate signature algorithms. Adopt hybrid PQC named groups and plan PQC-capable CA re-issuance.",
    },
  };

  async function groupsFor(list: Finding[]): Promise<PlanGroup[]> {
    const byAlgo = new Map<AlgorithmFamily, Finding[]>();
    for (const f of list) {
      const a = (f.algorithm ?? "unknown") as AlgorithmFamily;
      const arr = byAlgo.get(a) ?? [];
      arr.push(f);
      byAlgo.set(a, arr);
    }
    const groups: PlanGroup[] = [];
    for (const [algorithm, fs] of byAlgo) {
      const rem = await safe<Remediation | undefined>("remediationFor", () =>
        remediationFor(algorithm),
      );
      groups.push({
        algorithm,
        count: fs.length,
        hndlCount: fs.filter((f) => f.hndl).length,
        remediation:
          rem.ok && rem.value ? rem.value.recommendation : "Adopt NIST PQC (ML-KEM / ML-DSA).",
        locations: fs.slice(0, 8).map((f) => `${f.location.file}:${f.location.line}`),
      });
    }
    // Largest groups first within a phase.
    groups.sort((a, b) => b.count - a.count);
    return groups;
  }

  const phases: PlanPhase[] = [];
  for (const p of [1, 2, 3]) {
    if (byPhase[p].length === 0) continue;
    phases.push({
      phase: p,
      title: phaseMeta[p].title,
      rationale: phaseMeta[p].rationale,
      groups: await groupsFor(byPhase[p]),
    });
  }

  const lines: string[] = [];
  lines.push(`Post-quantum migration plan for ${result.root}`);
  lines.push(
    `Readiness score: ${result.inventory.readinessScore}/100 · ${findings.length} finding(s) · ${result.inventory.hndlCount} HNDL-exposed`,
  );
  if (findings.length === 0) {
    lines.push("");
    lines.push(
      result.analyzedFiles === 0
        ? "No analyzable source was scanned — this plan does NOT cover unsupported languages."
        : "No classical asymmetric cryptography found. Keep scanning in CI to hold the line.",
    );
    return { human: lines.join("\n"), structured: { root: result.root, phases: [] } };
  }
  for (const ph of phases) {
    lines.push("");
    lines.push(`Phase ${ph.phase}: ${ph.title}`);
    lines.push(`  ${ph.rationale}`);
    for (const g of ph.groups) {
      lines.push(
        `  - ${g.algorithm} × ${g.count}${g.hndlCount ? ` (${g.hndlCount} HNDL)` : ""} → ${g.remediation}`,
      );
      lines.push(
        `      e.g. ${g.locations.join(", ")}${g.count > g.locations.length ? ", …" : ""}`,
      );
    }
  }
  lines.push("");
  lines.push(
    "Use get_fix_examples for per-algorithm code changes, then verify_fix to confirm each edit.",
  );
  return {
    human: lines.join("\n"),
    structured: {
      root: result.root,
      readinessScore: result.inventory.readinessScore,
      totalFindings: findings.length,
      hndlExposed: result.inventory.hndlCount,
      phases,
    },
  };
}

const getFixExamplesTool: ToolDefinition = {
  name: "get_fix_examples",
  description:
    "Return before/after code examples for migrating a classical algorithm to a " +
    "post-quantum / hybrid replacement. Provide an 'algorithm' (RSA, ECDH, ECDSA, …) " +
    "or a 'ruleId' from a finding.",
  inputSchema: {
    type: "object",
    properties: {
      algorithm: {
        type: "string",
        description: "Classical algorithm family to migrate away from.",
      },
      ruleId: { type: "string", description: "A finding's ruleId (resolved to its algorithm)." },
    },
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const algoInput = typeof args.algorithm === "string" ? args.algorithm.trim() : "";
    const ruleId = typeof args.ruleId === "string" ? args.ruleId.trim() : "";
    if (!algoInput && !ruleId) {
      return errorResult("get_fix_examples requires 'algorithm' or 'ruleId'.");
    }
    let family: AlgorithmFamily;
    if (algoInput) {
      family = normalizeAlgorithm(algoInput);
    } else {
      const resolved = resolveRule(ruleId);
      family = resolved.meta?.algorithm ?? resolved.algorithm ?? "unknown";
    }
    // Fold families that share a fix onto the example we have.
    const key: AlgorithmFamily = family === "ECIES" ? "RSA" : family;
    const ex = FIX_EXAMPLES[key];
    if (!ex) {
      const rem = await safe<Remediation | undefined>("remediationFor", () =>
        remediationFor(family),
      );
      return textResult(
        `No canned example for ${family}. ${
          rem.ok && rem.value
            ? rem.value.recommendation
            : "Adopt NIST PQC (ML-KEM / ML-DSA), deployed as hybrids."
        }`,
      );
    }
    const text = [
      `Migration example — ${family}`,
      ex.note,
      "",
      "BEFORE (classical):",
      ex.before,
      "",
      "AFTER (post-quantum / hybrid):",
      ex.after,
      "",
      "Deploy as a hybrid (classical + PQC) first; drop the classical half once the PQC side is proven.",
    ].join("\n");
    return {
      content: [
        { type: "text", text },
        { type: "text", text: JSON.stringify({ algorithm: family, ...ex }, null, 2) },
      ],
    };
  },
};

const verifyFixTool: ToolDefinition = {
  name: "verify_fix",
  description:
    "Run the quantakrypto detectors over a code snippet (NOT the filesystem) and " +
    "report any classical crypto that remains. Use this to confirm an edit actually " +
    "removed the quantum-vulnerable usage. Provide 'code' plus a 'language' or 'filename'.",
  inputSchema: {
    type: "object",
    properties: {
      code: { type: "string", description: "The source code to check." },
      language: {
        type: "string",
        description: "Language of the code (js, ts, python, go, java, csharp, rust, ruby, c, …).",
      },
      filename: {
        type: "string",
        description:
          "Optional filename; its extension selects the detectors (overrides 'language').",
      },
    },
    required: ["code"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const code = typeof args.code === "string" ? args.code : "";
    if (!code) return errorResult("verify_fix requires a non-empty 'code' string.");
    const filename = typeof args.filename === "string" ? args.filename.trim() : "";
    const language = typeof args.language === "string" ? args.language.trim() : "";

    let name: string;
    if (filename) {
      name = filename;
    } else if (language) {
      const ext = languageToExtension(language);
      if (!ext) {
        return errorResult(
          `verify_fix: unknown language "${language}". Supported: js/ts, python, go, java, kotlin, csharp, rust, ruby, c/c++ — or pass a 'filename'.`,
        );
      }
      name = `snippet${ext}`;
    } else {
      return errorResult(
        "verify_fix requires a 'language' or a 'filename' to know which detectors to run.",
      );
    }

    const found = await safe<Finding[]>("detectFile", () =>
      detectFile(name, code, detectors, { source: true, config: true, deps: true }),
    );
    if (!found.ok) return found.result;
    const findings = found.value;
    if (findings.length === 0) {
      const supported =
        languageToExtension(language || filename.replace(/^.*(\.[^.]+)$/, "$1")) !== null;
      const caveat = supported
        ? "Fix verified: no classical asymmetric cryptography detected in this snippet."
        : "No classical crypto detected — but this language is NOT one the scanner analyzes, so this is not a verification. Use a supported language.";
      return textResult(caveat);
    }
    const lines = [`Still ${findings.length} classical finding(s) — fix NOT complete:`];
    for (const f of findings) {
      lines.push(
        `- [${f.severity}] ${f.ruleId} (line ${f.location.line})${f.hndl ? " (HNDL)" : ""} — ${f.message}`,
      );
    }
    return {
      content: [
        { type: "text", text: lines.join("\n") },
        { type: "text", text: JSON.stringify(findings, null, 2) },
      ],
    };
  },
};

const checkDependencyTool: ToolDefinition = {
  name: "check_dependency",
  description:
    "Check whether a package is in quantakrypto's known quantum-vulnerable dependency " +
    "database (the classical crypto it exposes). Provide 'name' and optional 'ecosystem' (default npm).",
  inputSchema: {
    type: "object",
    properties: {
      name: {
        type: "string",
        description: "Package name to look up (e.g. 'node-forge', 'jsonwebtoken').",
      },
      ecosystem: { type: "string", description: "Package ecosystem. Default: npm." },
    },
    required: ["name"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const name = typeof args.name === "string" ? args.name.trim().toLowerCase() : "";
    if (!name) return errorResult("check_dependency requires a non-empty 'name'.");
    const ecosystem =
      typeof args.ecosystem === "string" ? args.ecosystem.trim().toLowerCase() : "npm";

    const db = await safe<readonly VulnerableDependency[]>(
      "vulnerableDependencies",
      () => vulnerableDependencies,
    );
    if (!db.ok) return db.result;
    const hit = db.value.find(
      (d) => d.name.toLowerCase() === name && d.ecosystem.toLowerCase() === ecosystem,
    );
    if (!hit) {
      return textResult(
        `"${name}" (${ecosystem}) is NOT in the known quantum-vulnerable dependency database. ` +
          "That is not proof it's safe — it may simply not be catalogued, or its crypto may be in your own code. Scan the source too.",
      );
    }
    const rem = await safe<Remediation | undefined>("remediationFor", () =>
      remediationFor(hit.algorithms[0] ?? "unknown"),
    );
    const text = [
      `${hit.name} (${hit.ecosystem}) — quantum-vulnerable [${hit.severity}]`,
      `Exposes: ${hit.algorithms.join(", ")}`,
      `Why: ${hit.reason}`,
      rem.ok && rem.value
        ? `Migrate toward: ${rem.value.recommendation}`
        : "Migrate toward NIST PQC (ML-KEM / ML-DSA).",
    ].join("\n");
    return {
      content: [
        { type: "text", text },
        { type: "text", text: JSON.stringify(hit, null, 2) },
      ],
    };
  },
};

const scoreDeltaTool: ToolDefinition = {
  name: "score_delta",
  description:
    "Compute the readiness-score and HNDL change between two finding sets (e.g. before " +
    "and after a migration). Pass 'before' and 'after' as arrays of findings from " +
    "scan_path --format json.",
  inputSchema: {
    type: "object",
    properties: {
      before: {
        type: "array",
        description: "Findings before the change (from a scan's JSON findings).",
      },
      after: { type: "array", description: "Findings after the change." },
    },
    required: ["before", "after"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    if (!Array.isArray(args.before) || !Array.isArray(args.after)) {
      return errorResult("score_delta requires 'before' and 'after' arrays of findings.");
    }
    const before = args.before as Finding[];
    const after = args.after as Finding[];
    const invBefore = await safe<CryptoInventory>("buildInventory", () => buildInventory(before));
    if (!invBefore.ok) return invBefore.result;
    const invAfter = await safe<CryptoInventory>("buildInventory", () => buildInventory(after));
    if (!invAfter.ok) return invAfter.result;

    const dScore = invAfter.value.readinessScore - invBefore.value.readinessScore;
    const dHndl = invAfter.value.hndlCount - invBefore.value.hndlCount;
    const dCount = after.length - before.length;
    const sign = (n: number) => (n > 0 ? `+${n}` : `${n}`);
    const text = [
      "Readiness delta",
      `Score:   ${invBefore.value.readinessScore} → ${invAfter.value.readinessScore}  (${sign(dScore)})`,
      `Findings: ${before.length} → ${after.length}  (${sign(dCount)})`,
      `HNDL:    ${invBefore.value.hndlCount} → ${invAfter.value.hndlCount}  (${sign(dHndl)})`,
      dScore > 0
        ? "Progress: readiness improved."
        : dScore < 0
          ? "Regression: readiness dropped — new classical crypto was introduced."
          : "No net change in readiness.",
    ].join("\n");
    return {
      content: [
        { type: "text", text },
        {
          type: "text",
          text: JSON.stringify(
            {
              before: {
                score: invBefore.value.readinessScore,
                findings: before.length,
                hndl: invBefore.value.hndlCount,
              },
              after: {
                score: invAfter.value.readinessScore,
                findings: after.length,
                hndl: invAfter.value.hndlCount,
              },
              delta: { score: dScore, findings: dCount, hndl: dHndl },
            },
            null,
            2,
          ),
        },
      ],
    };
  },
};

/**
 * Tools that read arbitrary filesystem paths. Disabled by default on the HTTP
 * transport (see {@link ./http.ts}) because a hosted endpoint must not be an
 * arbitrary-file-read oracle (security audit Q-01). The stdio transport, which
 * trusts the local user, always exposes them.
 */
export const FS_TOOL_NAMES: readonly string[] = [
  "scan_path",
  "inventory_crypto",
  "generate_cbom",
  "plan_migration",
];

/** All quantakrypto MCP tools, in a stable order. */
export const quantakryptoTools: ToolDefinition[] = [
  scanPathTool,
  inventoryCryptoTool,
  explainFindingTool,
  suggestHybridTool,
  listRulesTool,
  generateCbomTool,
  // Copilot tools — migrate through the engine.
  planMigrationTool,
  getFixExamplesTool,
  verifyFixTool,
  checkDependencyTool,
  scoreDeltaTool,
];

/** The core version these tools are built against (re-exported for diagnostics). */
export const CORE_VERSION = VERSION;

/** Exposed for tests and advanced callers. */
export const __test = {
  normalizeAlgorithm,
  summarizeScan,
  staticHybridAdvice,
  buildScanOptions,
  describeError,
};

/** Keep the schema type imported and referenced (documentation aid). */
export type ToolInputSchema = JsonSchema;
