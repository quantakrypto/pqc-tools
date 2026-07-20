/**
 * @quantakrypto/core — public API (LOCKED CONTRACT).
 *
 * The exported NAMES and SIGNATURES below are the stable contract that
 * @quantakrypto/qscan, @quantakrypto/mcp and the GitHub Action depend on — do not change
 * them without updating all consumers. The implementations live in focused
 * modules under src/ and are re-exported here; the public surface is identical
 * to the original stub file.
 */
export * from "./types.js";

// Tool version, surfaced in reports. Keep in sync with package.json.
export { VERSION } from "./version.js";

// Minimal SARIF 2.1.0 log shape, defined alongside the reporters.
export type { SarifLog } from "./report.js";

// Core orchestration + built-in detector set.
export { scan, detectors, detectFile, compareFindings } from "./scan.js";

// Snippet-level fix verification (shared by MCP verify_fix + remediation).
export { verifyFix, languageToExtension } from "./verify.js";
export type { VerifyResult } from "./verify.js";

// Agent-plane shared types + the context redactor (offline; reused by MCP).
export type {
  ContextLevel,
  RedactedContext,
  TriageVerdict,
  Patch,
  FixProposal,
} from "./agent-types.js";
export { buildContext, renderPreflight } from "./redact.js";
export { TRIAGE_RUBRIC, TRIAGE_VERDICT_SCHEMA, buildTriageRequest } from "./triage.js";
export type { TriageRequest } from "./triage.js";
export {
  REMEDIATE_RUBRIC,
  FIX_REQUEST_SCHEMA,
  buildRemediateRequest,
} from "./remediate-request.js";
export type { RemediateRequest } from "./remediate-request.js";
export { checkPatchPolicy } from "./patch-policy.js";
export type { PolicyContext, PolicyDecision } from "./patch-policy.js";
export { withWorktree } from "./worktree.js";
export { codemodRegistry, codemodFor } from "./codemods/registry.js";
export type { Codemod } from "./codemods/registry.js";
export { configToggleCodemod } from "./codemods/config-toggle.js";
export { remediateFindings } from "./remediate-pipeline.js";
export type {
  RemediateOptions,
  RemediationResult,
  VerifiedPatch,
  RejectedPatch,
} from "./remediate-pipeline.js";

// Scan cancellation / work-budget errors.
export { AbortError, BudgetExceededError } from "./errors.js";

// Parallel scanning (worker_threads pool) + pure merge/chunk helpers.
export { scanParallel, mergeChunkResults, chunkByBytes } from "./parallel.js";
export type { ScanChunk, ChunkResult, SizedFile } from "./parallel.js";

// Detector registry (plugin point) + helpers + the rule catalog.
export { DetectorRegistry, defaultRegistry, detectorScope } from "./registry.js";
export type { RuleCatalogEntry } from "./registry.js";

// Canonical baseline (shared by qScan + the Action).
export {
  fingerprintFinding,
  baselineFromFindings,
  applyBaseline,
  loadBaseline,
  saveBaseline,
  BASELINE_VERSION,
} from "./baseline.js";
export type { Baseline } from "./baseline.js";

// Incremental scanning: changed-files helper (git-aware, tolerant).
export { changedFiles } from "./changed.js";

// Optional `quantakrypto.config.json` loader (P2-9; see docs/CONFIG.md).
export { loadConfig, ConfigError, CONFIG_FILENAME } from "./config.js";
export type { QuantakryptoFileConfig, LoadConfigResult } from "./config.js";

// Filesystem walker (relative POSIX paths, default ignores, size/binary filters).
export { walkFiles, isBinaryPath, isGeneratedPath, looksMinified } from "./walk.js";

// Analyzable-language coverage (which source languages the scanner inspects).
export {
  isAnalyzableSource,
  ANALYZABLE_SOURCE_EXTENSIONS,
  ANALYZABLE_LANGUAGES_LABEL,
} from "./detect-utils.js";

// Inventory + readiness score.
export { buildInventory } from "./inventory.js";

// Vulnerable-dependency database (the manifest scanner is used internally by scan()).
// `DEP_VULNERABLE_RULE` is the generic catalog entry for dependency findings
// (which don't come from a Detector, so aren't in the registry's rule catalog).
export { vulnerableDependencies, DEP_VULNERABLE_RULE, isManifestFile } from "./dependencies.js";

// Severity utilities (ordering, threshold, SARIF level) — shared across tools.
export { SEVERITY_ORDER, severityRank, meetsThreshold, sarifLevel } from "./severity.js";

// Reporters.
export { toSarif, toJson, formatSummary, formatTierGuidance } from "./report.js";
export type { ReportOptions } from "./report.js";

// CycloneDX 1.6 cryptographic bill of materials (CBOM) export.
export { toCbom } from "./cbom.js";
export type { CycloneDxBom, CbomComponent } from "./cbom.js";
// Merge multiple CBOMs (code + infra + live endpoints) into one combined BOM.
export { mergeCboms } from "./cbom-merge.js";
// ISO/IEC 27001 A.8.24 evidence-chain readiness report.
export { buildReadinessReport, signReadinessReport } from "./evidence.js";
export type {
  ReadinessReport,
  EvidenceFinding,
  ReadinessReportOptions,
  EvidenceSigner,
  SignEvidenceOptions,
} from "./evidence.js";

// Cryptography policy → per-finding verdicts (A.8.24 evidence §4).
export { buildPolicyMapping, parseCryptoPolicy, verdictForAlgorithm } from "./policy.js";
export type { CryptoPolicy, PolicyVerdict, PolicyMapping, PolicyFindingVerdict } from "./policy.js";

// Remediation lookup (family + tier-aware) and stateful-HBS guidance.
export {
  remediationFor,
  remediationForTier,
  TIER_PARAMS,
  STATEFUL_HBS_NOTE,
  PQC_TRANSITION_NOTE,
  statefulHbsApplies,
} from "./remediation.js";
export type { SecurityTier } from "./remediation.js";

// Post-quantum standards source of truth + review cadence.
export { PQC_STANDARDS, standardsReviewStatus } from "./standards.js";
export type { PqcStandards, StandardsCitation, StandardsReviewStatus } from "./standards.js";

// CWE identifier constants.
export {
  CWE_BROKEN_CRYPTO,
  CWE_WEAK_STRENGTH,
  CWE_CERT_VALIDATION,
  CWE_HARDCODED_KEY,
  CWE_RISKY_PRIMITIVE,
} from "./cwe.js";
