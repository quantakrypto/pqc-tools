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
  buildRemediateRequest,
  buildTriageRequest,
  compareFindings,
  detectors,
  fingerprintFinding,
  isManifestFile,
  languageToExtension,
  remediateFindings,
  remediationFor,
  remediationForTier,
  scan,
  SEVERITY_ORDER,
  toCbom,
  verifyFix,
  vulnerableDependencies,
} from "@quantakrypto/core";
import type {
  AlgorithmFamily,
  CryptoInventory,
  Finding,
  Remediation,
  ScanOptions,
  ScanResult,
  VerifyResult,
  VulnerableDependency,
} from "@quantakrypto/core";

import { errorResult, textResult } from "./protocol.js";
import type { ToolContext, ToolDefinition, ToolResult } from "./protocol.js";
import { resolveRule } from "./rules.js";
import { realpathInsideRoots, resolveFsConfig, resolveScanPath } from "./fsconfig.js";

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
async function buildScanOptions(
  requested: string,
  context?: ToolContext,
): Promise<{ ok: true; options: ScanOptions } | { ok: false; result: ToolResult }> {
  const config = resolveFsConfig(process.env);
  const decision = resolveScanPath(config, requested);
  if (!decision.ok) {
    return { ok: false, result: errorResult(`scan rejected: ${decision.reason}`) };
  }
  // Symlink-escape hardening: re-verify containment against the real, resolved
  // paths so a symlink inside a root can't read outside it (audit: mcp #1).
  if (!(await realpathInsideRoots(decision.path, config))) {
    return {
      ok: false,
      result: errorResult("scan rejected: path resolves outside the configured root(s) (symlink)."),
    };
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
    const opts = await buildScanOptions(path, context);
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
    const opts = await buildScanOptions(path, context);
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
    "(e.g. RSA, ECDH, ECDSA) or free-text 'context' describing the usage. " +
    "Set 'tier' to 'category-5' for CNSA 2.0 / national-security systems.",
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
      tier: {
        type: "string",
        enum: ["category-3", "category-5"],
        description:
          "Security tier: 'category-3' (default, commercial — ML-KEM-768 / ML-DSA-65) or " +
          "'category-5' (CNSA 2.0 / NSS, long-lived secrets — ML-KEM-1024 / ML-DSA-87).",
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
    const tier =
      args.tier === "category-5"
        ? "category-5"
        : args.tier === "category-3"
          ? "category-3"
          : undefined;
    const lines: string[] = [];
    lines.push(`Migration guidance for: ${algoInput || context}`);
    lines.push(`Detected family: ${algorithm}`);
    if (tier) lines.push(`Security tier: ${tier}`);

    const rem = await safe<Remediation | undefined>("remediationFor", () =>
      tier ? remediationForTier(algorithm, tier) : remediationFor(algorithm),
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
    const opts = await buildScanOptions(path, context);
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

// `languageToExtension` + `verifyFix` now live in @quantakrypto/core so this tool and
// the remediation pipeline share one definition of "the fix is verified".

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
    const opts = await buildScanOptions(path, context);
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

    if (!filename && !language) {
      return errorResult(
        "verify_fix requires a 'language' or a 'filename' to know which detectors to run.",
      );
    }
    if (!filename && languageToExtension(language) === null) {
      return errorResult(
        `verify_fix: unknown language "${language}". Supported: js/ts, python, go, java, kotlin, csharp, rust, ruby, c/c++ — or pass a 'filename'.`,
      );
    }

    const res = await safe<VerifyResult>("verifyFix", () =>
      verifyFix(code, { filename, language }),
    );
    if (!res.ok) return res.result;
    const { supported, findings } = res.value;
    if (findings.length === 0) {
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
    // Validate element shape too (mirrors triage/remediate) — a malformed
    // `severity` otherwise yields a NaN readiness score rendered as authoritative.
    if (!areFindings(args.before) || !areFindings(args.after)) {
      return errorResult("score_delta: 'before' and 'after' must be arrays of valid findings.");
    }
    const before = args.before;
    const after = args.after;
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
 * True when every element looks like a scan Finding (a string `ruleId` and a
 * `location.file`). Guards the triage/remediate tools so a malformed `findings`
 * element surfaces as a tool `isError` result rather than throwing a protocol
 * `-32603` internal error downstream (audit: mcp #4).
 */
function areFindings(arr: readonly unknown[]): arr is Finding[] {
  return arr.every(
    (f) =>
      f !== null &&
      typeof f === "object" &&
      typeof (f as { ruleId?: unknown }).ruleId === "string" &&
      typeof (f as { location?: { file?: unknown } }).location?.file === "string",
  );
}

const triageFindingsTool: ToolDefinition = {
  name: "triage_findings",
  description:
    "Produce a deterministic triage REQUEST bundle (rubric + verdict schema + " +
    "per-finding metadata) for YOU (the host agent) to reason over. This tool does " +
    "NOT call any model and needs no API key. Assess each finding's real-world " +
    "exposure, then call apply_triage with your verdicts. Pass 'findings' as an " +
    "array from scan_path --format json.",
  inputSchema: {
    type: "object",
    properties: {
      findings: { type: "array", description: "Findings from a scan's JSON output." },
    },
    required: ["findings"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    if (!Array.isArray(args.findings) || !areFindings(args.findings)) {
      return errorResult(
        "triage_findings requires a 'findings' array of scan findings (each with a string ruleId and location.file).",
      );
    }
    const findings = args.findings;
    const request = buildTriageRequest(findings, "metadata");
    // Pair each context with the finding fingerprint the verdict must echo back.
    const items = findings.map((f, i) => ({
      fingerprint: fingerprintFinding(f),
      context: request.contexts[i],
    }));
    // The verdict schema advertised to the agent MUST include `fingerprint`
    // (the instructions require it, and apply_triage keys on it) — core's
    // single-verdict schema doesn't, so extend it here (audit: mcp bundle).
    const props = (request.schema as { properties?: Record<string, unknown> }).properties ?? {};
    const schema = {
      type: "object",
      required: ["fingerprint", "exposureScore", "priority", "rationale"],
      properties: { fingerprint: { type: "string" }, ...props },
    };
    const bundle = { rubric: request.rubric, schema, items };
    return {
      content: [
        {
          type: "text",
          text:
            "Triage request. For each item, decide {exposureScore 0-100, priority, rationale} " +
            "per the rubric, then call apply_triage with the same 'findings' and a 'verdicts' " +
            "array (each carrying the item's 'fingerprint'). You never suppress a finding.",
        },
        { type: "text", text: JSON.stringify(bundle, null, 2) },
      ],
    };
  },
};

/** Validate one caller-supplied triage verdict. Returns null when malformed. */
function parseVerdict(
  v: unknown,
): { fingerprint: string; exposureScore: number; priority: string; rationale: string } | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const fingerprint = o.fingerprint;
  const exposureScore = o.exposureScore;
  const priority = o.priority;
  const rationale = o.rationale;
  if (typeof fingerprint !== "string") return null;
  // `Number.isFinite` rejects NaN/Infinity — NaN passes both `< 0` and `> 100`
  // (they're false) and would poison the exposure sort comparator (audit: mcp #3).
  if (typeof exposureScore !== "number" || !Number.isFinite(exposureScore)) return null;
  if (exposureScore < 0 || exposureScore > 100) return null;
  if (priority !== "now" && priority !== "soon" && priority !== "later") return null;
  if (typeof rationale !== "string") return null;
  return { fingerprint, exposureScore, priority, rationale };
}

const applyTriageTool: ToolDefinition = {
  name: "apply_triage",
  description:
    "Deterministically attach your triage verdicts to their findings and re-sort by " +
    "exposure (highest first). Never suppresses. Pass the same 'findings' array you " +
    "triaged plus a 'verdicts' array of { fingerprint, exposureScore, priority, rationale }.",
  inputSchema: {
    type: "object",
    properties: {
      findings: { type: "array", description: "The findings that were triaged." },
      verdicts: { type: "array", description: "One verdict per finding, keyed by fingerprint." },
    },
    required: ["findings", "verdicts"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    if (!Array.isArray(args.findings) || !Array.isArray(args.verdicts)) {
      return errorResult("apply_triage requires 'findings' and 'verdicts' arrays.");
    }
    if (!areFindings(args.findings)) {
      return errorResult(
        "apply_triage: each 'findings' element needs a string ruleId and location.file.",
      );
    }
    const findings = args.findings;
    const byFingerprint = new Map<string, ReturnType<typeof parseVerdict>>();
    let skipped = 0;
    for (const raw of args.verdicts) {
      const v = parseVerdict(raw);
      if (v) byFingerprint.set(v.fingerprint, v);
      else skipped++;
    }
    const annotated = findings.map((f) => {
      const v = byFingerprint.get(fingerprintFinding(f));
      return v
        ? {
            ...f,
            triage: {
              exposureScore: v.exposureScore,
              priority: v.priority as "now" | "soon" | "later",
              rationale: v.rationale,
            },
          }
        : f;
    });
    annotated.sort((a, b) => {
      const ea = a.triage?.exposureScore ?? -1;
      const eb = b.triage?.exposureScore ?? -1;
      if (eb !== ea) return eb - ea;
      return compareFindings(a, b);
    });
    const applied = annotated.filter((f) => f.triage).length;
    const head =
      `Triaged ${applied}/${findings.length} finding(s), re-sorted by exposure.` +
      (skipped ? ` ${skipped} malformed verdict(s) ignored.` : "");
    return {
      content: [
        { type: "text", text: head },
        { type: "text", text: JSON.stringify(annotated, null, 2) },
      ],
    };
  },
};

const remediateFindingsTool: ToolDefinition = {
  name: "remediate_findings",
  description:
    "Produce a deterministic remediation REQUEST bundle (rubric + fix schema + " +
    "per-finding metadata + fingerprints) for YOU (the host agent) to fix. This " +
    "tool calls no model and needs no key. For each finding, propose the corrected " +
    "FULL file content, then VERIFY with verify_fix and keep only fixes that clear " +
    "the finding. Never touch files with secrets; never auto-merge. Pass 'findings' " +
    "from scan_path --format json.",
  inputSchema: {
    type: "object",
    properties: {
      findings: { type: "array", description: "Findings from a scan's JSON output." },
    },
    required: ["findings"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    if (!Array.isArray(args.findings) || !areFindings(args.findings)) {
      return errorResult(
        "remediate_findings requires a 'findings' array of scan findings (each with a string ruleId and location.file).",
      );
    }
    const findings = args.findings;
    const request = buildRemediateRequest(findings, "metadata");
    const items = findings.map((f, i) => ({
      fingerprint: fingerprintFinding(f),
      context: request.contexts[i],
    }));
    const bundle = { instructions: request.instructions, schema: request.schema, items };
    return {
      content: [
        {
          type: "text",
          text:
            "Remediation request. For each item, propose {path, newContent, explanation} " +
            "(the FULL corrected file), call verify_fix on your newContent, and keep only " +
            "verified fixes. Skip any file containing secrets. This never merges anything.",
        },
        { type: "text", text: JSON.stringify(bundle, null, 2) },
      ],
    };
  },
};

const applyVerifiedPatchTool: ToolDefinition = {
  name: "apply_verified_patch",
  description:
    "Deterministically VERIFY a proposed fix before writing it — runs the same " +
    "patch-policy + verify_fix + blast-radius gates as `qremediate` (offline, no " +
    "key, no network). Give the finding, the file's current content, and your " +
    "proposed FULL corrected content; returns approved:true only if the patch is " +
    "in-policy, clears the finding, adds no new finding, introduces no network/exec " +
    "sink, and is bounded in size. This does NOT write the file — you write it, " +
    "only when approved, and never auto-merge.",
  inputSchema: {
    type: "object",
    properties: {
      finding: {
        type: "object",
        description: "The scan finding being fixed (needs a string ruleId and location.file).",
      },
      originalContent: { type: "string", description: "The file's current full content." },
      newContent: { type: "string", description: "Your proposed full corrected file content." },
    },
    required: ["finding", "originalContent", "newContent"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const finding = args.finding as Finding;
    if (!finding || typeof finding !== "object" || !areFindings([finding])) {
      return errorResult(
        "apply_verified_patch requires a 'finding' with a string ruleId and location.file.",
      );
    }
    if (typeof args.originalContent !== "string" || typeof args.newContent !== "string") {
      return errorResult(
        "apply_verified_patch requires string 'originalContent' and 'newContent'.",
      );
    }
    const file = finding.location.file;
    const originalContent = args.originalContent;
    const patch = {
      path: file,
      newContent: args.newContent,
      ruleId: finding.ruleId,
      source: "llm" as const,
    };
    const res = await safe("apply_verified_patch", () =>
      remediateFindings([finding], {
        readContent: () => originalContent,
        patchSource: () => patch,
        policy: {
          findingFiles: new Set([file]),
          manifestFiles: new Set(isManifestFile(file) ? [file] : []),
        },
      }),
    );
    if (!res.ok) return res.result;
    const approved = res.value.applied.length > 0;
    return textResult(
      JSON.stringify(
        {
          approved,
          path: file,
          ruleId: finding.ruleId,
          ...(approved ? {} : { reason: res.value.rejected[0]?.reason ?? "rejected" }),
          note: approved
            ? "Cleared every deterministic gate — safe to write. Open a diff/PR for review; never auto-merge."
            : "Rejected by the deterministic gates — do NOT write this patch.",
        },
        null,
        2,
      ),
    );
  },
};

/**
 * `probe_endpoint` — actively probe ONE live TLS/SSH endpoint the caller OWNS for
 * post-quantum readiness. This is the ONLY MCP tool that opens a network socket;
 * the qprobe plane is loaded via dynamic import so the server stays offline until
 * the tool is actually invoked, and the ownership attestation gate is enforced in
 * qProbe's `runProbe` before any connection. On the HTTP transport it is OFF by
 * default (see {@link NETWORK_TOOL_NAMES}) — a hosted endpoint should not probe
 * arbitrary hosts — but a trusted operator can opt in with
 * QUANTAKRYPTO_MCP_ALLOW_NETWORK=1.
 */
const probeEndpointTool: ToolDefinition = {
  name: "probe_endpoint",
  description:
    "Actively probe ONE live TLS/SSH endpoint YOU OWN for post-quantum readiness " +
    "(PQC-hybrid key exchange X25519MLKEM768, classical certificate posture). REQUIRES " +
    "an ownership attestation: set i_own_this=true to confirm you are authorized to test " +
    "the target. Refuses CIDR ranges / wildcards / lists — one host at a time. Performs " +
    "only a benign, unauthenticated handshake and never modifies the endpoint. NOTE: this " +
    "is the ONLY quantakrypto MCP tool that opens a network connection; the server is " +
    "otherwise offline. Over HTTP it is disabled unless the operator sets " +
    "QUANTAKRYPTO_MCP_ALLOW_NETWORK=1.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "A single host or host:port you own (no ranges/CIDRs/wildcards).",
      },
      mode: {
        type: "string",
        enum: ["tls", "ssh", "auto"],
        description: "Probe mode (default: auto — SSH on :22, TLS otherwise).",
      },
      i_own_this: {
        type: "boolean",
        description:
          "Attestation that you are authorized to probe this endpoint. Must be true; the probe is refused otherwise.",
      },
      timeout_ms: { type: "number", description: "Per-connection timeout in ms (default 8000)." },
    },
    required: ["target", "i_own_this"],
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const target = args.target;
    if (typeof target !== "string" || target.length === 0) {
      return errorResult("probe_endpoint requires a non-empty 'target' string.");
    }
    if (args.i_own_this !== true) {
      return errorResult(
        "probe_endpoint refused: set i_own_this=true to attest you are authorized to probe this endpoint. Active probing of endpoints you do not own may be unlawful.",
      );
    }
    const mode = args.mode === "tls" || args.mode === "ssh" ? args.mode : "auto";
    const timeoutMs = typeof args.timeout_ms === "number" ? args.timeout_ms : undefined;
    // Dynamic import keeps the networked qprobe plane out of the server process
    // until this tool is actually used; runProbe enforces the attestation gate.
    const qprobe = await import("@quantakrypto/qprobe");
    // Parse the target explicitly so a CIDR/range/list refusal returns a helpful
    // message rather than a scrubbed internal error.
    let parsed;
    try {
      parsed = qprobe.parseTarget(target, mode === "ssh" ? 22 : 443);
    } catch (e) {
      return errorResult(`probe_endpoint: ${e instanceof Error ? e.message : String(e)}`);
    }
    const probed = await safe("probe_endpoint", () =>
      qprobe.runProbe({ targets: [parsed], mode, attest: { iOwnThis: true }, timeoutMs }),
    );
    if (!probed.ok) return probed.result;
    const { reports, findings, inventory } = probed.value;
    const lines: string[] = [];
    let unreachable = 0;
    for (const r of reports) {
      lines.push(`${r.target.host}:${r.target.port} [${r.mode}]`);
      const err = r.ssh?.error ?? r.tls?.error ?? r.hybrid?.error;
      if (err && r.findings.length === 0) {
        unreachable++;
        // Do NOT let an unreachable/errored endpoint read as a clean 100/100.
        lines.push(`  ⚠ probe error: ${err} — endpoint NOT assessed (not a clean result)`);
      }
      for (const p of r.positives) lines.push(`  ✓ ${p}`);
      for (const f of r.findings) lines.push(`  [${f.severity}] ${f.title} — ${f.message}`);
    }
    const note =
      unreachable > 0
        ? " — NOTE: an endpoint could not be reached/handshaken, so this is NOT a clean bill of health"
        : "";
    lines.push(
      `\n${findings.length} finding${findings.length === 1 ? "" : "s"} · ${inventory.hndlCount} HNDL-exposed · readiness ${inventory.readinessScore}/100${note}`,
    );
    return {
      content: [
        { type: "text", text: lines.join("\n") },
        { type: "text", text: JSON.stringify({ findings, inventory }, null, 2) },
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

/**
 * Tools that open network connections. On the HTTP transport they are OFF by
 * default — a hosted MCP should not probe arbitrary hosts — but a trusted operator
 * can opt in with QUANTAKRYPTO_MCP_ALLOW_NETWORK=1 (mirroring the FS-tools opt-in).
 * Always available on the local stdio transport, which trusts the local user.
 */
export const NETWORK_TOOL_NAMES: readonly string[] = ["probe_endpoint"];

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
  // BYOK triage + remediation — deterministic request/apply (host agent reasons; offline).
  triageFindingsTool,
  applyTriageTool,
  remediateFindingsTool,
  applyVerifiedPatchTool,
  // The only networked tool — offline until invoked; refused on the HTTP transport.
  probeEndpointTool,
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
  FIX_EXAMPLES,
};
