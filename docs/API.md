# Public API reference

> **Generated** by `scripts/gen-api-reference.mjs` - do not edit by hand. Run
> `npm run api:docs` to regenerate; `npm run api:check` fails CI if it drifts.

Only the symbols listed here are covered by the SemVer contract
([VERSIONING.md](VERSIONING.md)). Anything not re-exported from a package's entry
point is internal and may change in a patch. The machine-readable frozen surface is
[`api-surface.json`](api-surface.json).

## @quantakrypto/core

Public entry: `packages/core/src/index.ts` - 199 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `ANALYZABLE_LANGUAGES_LABEL` | const | Human label for the source languages the scanner can analyze for inline |
| `ANALYZABLE_SOURCE_EXTENSIONS` | const | Extensions the scanner can actually analyze for inline crypto usage today |
| `AbortError` | class | Thrown when a scan is aborted via `ScanOptions.signal`. `name` is `"AbortError"` |
| `AlgorithmFamily` | type | Classical asymmetric algorithm families that are not quantum-safe. |
| `AssetExposure` | interface | Per-asset rollup for the repo summary. |
| `BASELINE_VERSION` | const | Current on-disk baseline schema version. |
| `Baseline` | interface | The on-disk baseline shape: a version tag and a set of fingerprints. |
| `BudgetExceededError` | class | Thrown when a scan exceeds its `maxFiles` / `maxBytes` work budget mid-walk. |
| `CLASSIFICATION_SENSITIVITY` | const | Data-sensitivity weight (S) per classification. |
| `CONFIDENCE_WEIGHT` | const | Crypto-vulnerability weight (V) scaled by detector confidence. |
| `CONFIG_FILENAME` | const | Canonical config file name discovered at a scan root. |
| `CRYPTO_AGILITY_MANIFEST_VERSION` | const | Schema version of the manifest this module emits and validates. Bumped only on a |
| `CRYPTO_AGILITY_WELL_KNOWN_PATH` | const | The conventional path a manifest is served from, relative to the site origin. |
| `CWE_BROKEN_CRYPTO` | const | CWE-327: Use of a Broken or Risky Cryptographic Algorithm. |
| `CWE_CERT_VALIDATION` | const | CWE-295: Improper Certificate Validation. |
| `CWE_HARDCODED_KEY` | const | CWE-798: Use of Hard-coded Credentials (embedded private keys). |
| `CWE_RISKY_PRIMITIVE` | const | CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation. |
| `CWE_WEAK_STRENGTH` | const | CWE-326: Inadequate Encryption Strength. |
| `CbomComponent` | interface | A single CycloneDX `cryptographic-asset` component. |
| `Codemod` | interface | A deterministic fix for a class of findings. |
| `Confidence` | type | How sure the detector is that the finding is a real use of the algorithm. |
| `ConfigError` | class | Thrown when a known key has a malformed *value* (a usage error: exit 2). |
| `ContextLevel` | type | How much source context a redacted request carries. |
| `CryptoAgilityCbomSummary` | interface | A compact summary of the full CBOM, linking to it by serial number. |
| `CryptoAgilityFamily` | interface | A single algorithm family in use, mirroring the CBOM's grouping. |
| `CryptoAgilityManifest` | interface | The full crypto-agility manifest. |
| `CryptoAgilityManifestOptions` | interface | Inputs the CLI/runtime supplies that are not derivable from the scan. |
| `CryptoAgilityPolicy` | interface | The migration policy the project declares it is measured against. |
| `CryptoAgilityPosture` | interface | The project's cryptographic posture, distilled from the scan inventory. |
| `CryptoInventory` | interface | Aggregated counts produced from a scan's findings. |
| `CryptoPolicy` | interface | An organization-supplied cryptography policy (from a JSON file). |
| `CycloneDxBom` | interface | A CycloneDX 1.6 cryptographic bill of materials (kept permissive). |
| `DEFAULT_MIGRATION_HORIZON_YEARS` | const | Default years to complete the org's PQC migration (Y in Mosca's inequality). |
| `DEFAULT_PROFILE_ID` | const | The default profile id when `--profile` is not given. |
| `DEFAULT_QUANTUM_THREAT_YEARS` | const | Default years until a cryptographically-relevant quantum computer is assumed |
| `DEFAULT_UNBOUND_CLASSIFICATION` | const | Classification assumed for findings that bind to no declared asset. |
| `DEP_VULNERABLE_RULE` | const | Catalog entry for the `dep-vulnerable` rule. Dependency findings are produced |
| `DataClassification` | type | Data sensitivity classes, least → most sensitive. Vocabulary aligned with the |
| `DependencyEcosystem` | type | Package ecosystems the dependency scanner understands. |
| `Detector` | interface | A pluggable source detector. Detectors are pure and stateless. |
| `DetectorInput` | interface |  |
| `DetectorLanguage` | type | The programming language / surface a detector targets. `"any"` means the |
| `DetectorRegistry` | class | An ordered, id-indexed collection of detectors. Registration order is |
| `DetectorScope` | type | Which logical scope a detector belongs to. Drives the source/config scope |
| `EvidenceFinding` | interface | Stable per-finding record for the evidence body (deterministic per commit). |
| `EvidenceSigner` | interface | An EXTERNAL signer/timestamper the tool orchestrates. Per ADR-0004 the tool |
| `ExposureRationale` | interface | Full, auditable breakdown of one finding's exposure score. |
| `FIX_REQUEST_SCHEMA` | const | JSON Schema every fix proposal must satisfy. |
| `Finding` | interface | A single detected concern. |
| `FindingCategory` | type | What kind of cryptographic concern a finding represents. |
| `FindingExposure` | interface | A finding's computed exposure, keyed by fingerprint for website ingest. |
| `FixProposal` | interface | An LLM-proposed fix before it enters the deterministic pipeline. |
| `HNDL_FILENAME` | const | Canonical `hndl.yml` file name discovered at a scan root. |
| `HNDL_MODEL_VERSION` | const | Version of the exposure model. Bump on any weight / formula change. |
| `HndlDataAsset` | interface | A single declared data asset from `hndl.yml`. |
| `HndlDefaults` | interface | Defaults applied to findings that bind to no declared asset. |
| `HndlError` | class | Thrown when `hndl.yml` is malformed (structure or a bad known value). |
| `HndlHorizon` | interface | The Mosca horizons that gate the exposure model. |
| `HndlMap` | interface | A fully-parsed, validated `hndl.yml`. |
| `HndlReport` | interface | The complete HNDL analysis of a scan. |
| `HndlScope` | type | Logical scope a finding belongs to, used for optional scope-bound assets. The |
| `HndlSummary` | interface | Repo-level HNDL summary. |
| `HybridStance` | type | Whether classical+PQC hybridization is required during the transition, per regime. |
| `LoadConfigResult` | interface | Result of {@link loadConfig}: the resolved config plus where it came from. |
| `MANDATES` | const | The bundled mandate catalog. Keyed by `--mandate <id>`. |
| `Mandate` | interface |  |
| `MandateEvaluation` | interface |  |
| `MandateFindingVerdict` | interface |  |
| `MandateGateOptions` | interface |  |
| `MandateRule` | interface |  |
| `MandateRuleTier` | type | Which enforcement tier a clause encodes: warn (`deprecate`) or fail (`disallow`). |
| `MandateStatus` | type | A finding's status against a mandate, worst last: |
| `ManifestValidation` | interface | Outcome of {@link validateCryptoAgilityManifest}. |
| `NON_HNDL_DISCOUNT` | const | Discount applied to V when a finding is NOT harvest-now-decrypt-later exposed |
| `OpenVexDocument` | interface | An OpenVEX 0.2.0 document. |
| `OpenVexOptions` | interface | Options for {@link toOpenVex}. |
| `OpenVexStatement` | interface | A single OpenVEX statement: one synthetic vulnerability over its affected products. |
| `PQC_STANDARDS` | const | The current snapshot. Update on each quarterly review; the drift test keeps the |
| `PQC_TRANSITION_NOTE` | const | Forward-looking PQC standards worth tracking beyond the current FIPS 203/204/205 |
| `ParallelScanOptions` | interface | Extra options for {@link scanParallel}, layered onto {@link ScanOptions}. |
| `Patch` | interface | A concrete proposed edit: the full new content for a single file. |
| `PolicyContext` | interface | Files a remediation may write to. |
| `PolicyDecision` | interface |  |
| `PolicyFindingVerdict` | interface | One finding's verdict against the policy. |
| `PolicyMapping` | interface | The `policyMapping` block added to the evidence report. |
| `PolicyVerdict` | type | The three verdicts a finding can carry against a policy. |
| `PqcStandards` | interface | The full post-quantum standards snapshot the tool tracks. |
| `QuantakryptoFileConfig` | interface | The slice of options a `quantakrypto.config.json` can set. A subset of |
| `REMEDIATE_RUBRIC` | const | The system rubric for a fix proposal. |
| `ReadinessReport` | interface |  |
| `ReadinessReportOptions` | interface |  |
| `RedactedContext` | interface | A finding's context, redacted to a {@link ContextLevel} and secret-stripped. |
| `RejectedPatch` | interface |  |
| `RemediateOptions` | interface |  |
| `RemediateRequest` | interface | A remediation request bundle for the host agent. |
| `Remediation` | interface | A remediation recommendation for a classical algorithm. |
| `RemediationResult` | interface |  |
| `ReportFormat` | type | Output formats qScan / reporters can emit. |
| `ReportOptions` | interface | Options shared by the structured reporters ({@link toSarif} / {@link toJson}). |
| `RuleMeta` | interface | Declarative metadata for a single rule a detector can emit. This is the |
| `SEVERITY_ORDER` | const | Severity ordering, most → least severe. Index 0 is the most severe. |
| `SEVERITY_VULNERABILITY` | const | Crypto-vulnerability weight (V) contributed by a finding's severity. |
| `STANDARDS_PROFILES` | const | Built-in regime profiles. Facts reflect each authority's published PQC-transition |
| `STATEFUL_HBS_NOTE` | const | Guidance for stateful hash-based signatures (SP 800-208: LMS / XMSS / HSS). |
| `SarifLog` | interface | Minimal SARIF 2.1.0 log shape (kept permissive on purpose). |
| `ScanChunk` | interface | One unit of work dispatched to a worker. |
| `ScanDiagnostics` | interface | Non-fatal things that happened during a scan that reduce coverage. Surfaced so |
| `ScanOptions` | interface | Options controlling a scan. |
| `ScanResult` | interface | The full result of a scan. |
| `SecurityTier` | type | Security tier for remediation guidance. |
| `Severity` | type | How serious a finding is, ordered most → least severe. |
| `SignEvidenceOptions` | interface | Options for {@link signReadinessReport}: a detached-signature and/or a timestamp signer. |
| `SourceLocation` | interface | A precise location inside a scanned file. |
| `StandardsCitation` | interface | A single standards fact with its citation and when it was last verified. |
| `StandardsProfile` | interface | A regime's PQC guidance profile. |
| `StandardsReviewStatus` | interface | Result of {@link standardsReviewStatus}. |
| `TIER_PARAMS` | const | Per-tier KEM / signature parameter sets. |
| `TRIAGE_RUBRIC` | const | The system rubric that defines what an exposure verdict means. |
| `TRIAGE_VERDICT_SCHEMA` | const | JSON Schema every triage verdict must satisfy. |
| `TriageAnnotation` | interface | Optional LLM triage annotation attached to a finding by `qscan --triage`. |
| `TriagePriority` | type | Relative urgency an LLM triage pass assigns to a finding. |
| `TriageRequest` | interface | A triage request bundle: the rubric, the verdict schema, and redacted contexts. |
| `TriageVerdict` | interface | An LLM triage verdict for a single finding (never suppresses it). The |
| `VERSION` | const | The tool version surfaced in reports. Kept in its own module so reporters and |
| `VerifiedPatch` | interface |  |
| `VerifyReadinessResult` | interface | The result of {@link verifyReadinessReport}. |
| `VerifyResult` | interface | Result of {@link verifyFix}: the findings that remain, and whether the |
| `VulnerableDependency` | interface | A known quantum-vulnerable dependency entry. |
| `applyBaseline` | function | Split findings into those NOT in the baseline (`newFindings`) and those that |
| `assertKnownMandates` | function | Validate mandate ids loudly, matching `parseCryptoPolicy`'s fail-loud |
| `baselineFromFindings` | function | Build a {@link Baseline} from a set of findings (deduped, sorted). |
| `buildContext` | function | Build the redacted context for `finding` at `level`. `fileContent` is the full |
| `buildCryptoAgilityManifest` | function | Build a crypto-agility manifest from a scan result. Pure: every runtime input |
| `buildInventory` | function | Build the full inventory (counts + HNDL + score) from a set of findings. |
| `buildPolicyMapping` | function | Map every finding to a policy verdict, with per-verdict counts. Deterministic: |
| `buildReadinessReport` | function | Build the A.8.24 readiness report for a scan result. The attestation's |
| `buildRemediateRequest` | function | Build a remediation request bundle (offline; metadata level unless `readContent`). |
| `buildTriageRequest` | function | Build a triage request bundle for a set of findings. Offline: for non-metadata |
| `changedFiles` | function | Return the list of changed files (relative POSIX paths) under `root`. |
| `checkPatchPolicy` | function | Decide whether `patch` may be applied under `ctx`. |
| `codemodFor` | function | The first codemod that applies to `finding`, or undefined. |
| `codemodRegistry` | const | All registered codemods, in priority order. |
| `compareFindings` | function | Stable comparator: by file, then line, then ruleId. Exported for reuse. |
| `computeHndl` | function | Compute HNDL exposure for a set of findings against a declared data map. |
| `configToggleCodemod` | const |  |
| `defaultRegistry` | const | The default registry, preloaded with {@link builtinDetectors}. Used by |
| `defaultStandardsProfile` | function | The default profile (NIST). Always defined. |
| `detectFile` | function | Run all applicable detectors + the manifest scanner over a single file's |
| `detectors` | const | The full set of built-in detectors exposed on the public API. Re-exported |
| `evaluateMandates` | function | Evaluate findings against the selected mandates as of `now`. Unknown mandate |
| `findingFingerprint` | function | Identity key for a finding's exposure. Prefers a `finding.fingerprint` field |
| `findingScope` | function | The scope a finding belongs to. Dependency findings (from the manifest |
| `fingerprintFinding` | function | Stable, line-INSENSITIVE fingerprint of a finding: the hex SHA-256 of |
| `formatProfileGuidance` | function | Per-family migration targets tailored to a selected {@link StandardsProfile} |
| `formatSummary` | function | Render a human-readable summary of a scan result. Colour is off by default; |
| `formatTierGuidance` | function | Per-family migration targets for a CNSA security tier — surfaces the otherwise |
| `getMandate` | const |  |
| `getStandardsProfile` | function | Look up a built-in profile by id, or `undefined` when unknown. |
| `globMatch` | function | Match a POSIX path against a glob supporting `**` (any path segments incl. |
| `isAnalyzableSource` | function | True when a path is in a source language the scanner can analyze for crypto. |
| `isBinaryPath` | function | True if the file's extension marks it as binary / non-text. |
| `isManifestFile` | function | True if a file path looks like a manifest we can parse for dependencies. |
| `languageToExtension` | function | Map a language name (or a bare extension) to a source extension whose |
| `loadBaseline` | function | Load a baseline from disk. Returns an empty baseline (rather than throwing) |
| `loadConfig` | function | Load a `quantakrypto.config.json` for a scan. |
| `loadHndlMap` | function | Load and validate the `hndl.yml` for a scan. By default reads |
| `looksMinified` | function | Heuristic content check for machine-minified / generated files with no |
| `mandateGateFails` | function | The gate decision under the "deadline-aware" default: fail only once a DISALLOW |
| `mandateIds` | const |  |
| `meetsThreshold` | function | True when `severity` is at or above `threshold` (i.e. at least as severe). |
| `mergeCboms` | function | Merge CBOMs into one. Components with the same `bom-ref` (same algorithm + |
| `moscaFactor` | function | M - the Mosca factor (0..1). `X` is the data's protection horizon |
| `parseCryptoPolicy` | function | Validate + normalize a parsed policy object (from an operator's JSON file). |
| `parseHndlMap` | function | Validate a parsed `hndl.yml` object into a typed {@link HndlMap}. Applies |
| `remediateFindings` | function | Run each finding through patchSource → policy → verify, collecting the patches |
| `remediationFor` | function | Look up the recommended post-quantum remediation for a classical algorithm. |
| `remediationForProfile` | function | Regime-aware remediation. Composes the base family guidance with a |
| `remediationForTier` | function | Tier-aware remediation. Returns the base family remediation plus the |
| `renderPreflight` | function | Render the exact payload text a `--dry-run` preflight would send. |
| `sarifLevel` | function | Map our severity to a SARIF 2.1.0 result level. |
| `saveBaseline` | function | Write a baseline derived from the given findings to disk as pretty JSON |
| `scaffoldHndlYaml` | function | Scaffold an `hndl.yml` document seeded from a scan's findings. Config-scope, |
| `scan` | function | Recursively scan a directory (or single file, or explicit file list) for |
| `scanParallel` | function | Scan in parallel across a worker-thread pool, falling back to the in-process |
| `severityRank` | function | Rank of a severity within {@link SEVERITY_ORDER} (0 = most severe). Lower |
| `signReadinessReport` | function | Fill a readiness report's attestation with a detached signature and/or RFC-3161 |
| `standardsProfileIds` | function | All built-in profile ids, in a stable order (default first). |
| `statefulHbsApplies` | function | True when stateful HBS (SP 800-208) is a reasonable alternative for a family. |
| `toCbom` | function | Build a CycloneDX 1.6 CBOM from a scan result. One component per distinct |
| `toJson` | function | Serialize a scan result as a plain JSON-friendly object. |
| `toOpenVex` | function | Build an OpenVEX 0.2.0 document from a scan result. One statement per distinct |
| `toSarif` | function | Serialize a scan result as SARIF 2.1.0. |
| `validateCryptoAgilityManifest` | function | Validate an untrusted value against the crypto-agility manifest schema. |
| `verifyFix` | function | Run all detectors over `code`, selecting them by `filename` (extension) or |
| `verifyReadinessReport` | function | Recompute the deterministic content hash over a readiness report's body and |
| `vulnerabilityFactor` | function | V - crypto-vulnerability factor for a finding (0..1). |
| `vulnerableDependencies` | const | Known quantum-vulnerable npm dependencies. |
| `walkFiles` | value |  |
| `withWorktree` | function | Create a detached worktree of `repoRoot` at HEAD, run `fn` with its path, and |

## @quantakrypto/qscan

Public entry: `packages/qscan/src/index.ts` - 60 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `ArgError` | class | Thrown on malformed input; the CLI maps this to exit code 2. |
| `BASELINE_VERSION` | value |  |
| `Baseline` | type |  |
| `ChangedFilesFn` | type | Resolve the changed-file list for incremental scans. Injectable for testing; |
| `ConfigurableKey` | type | Option keys that a `quantakrypto.config.json` may also set. When such a key was set |
| `CryptoAgilityEmitResult` | interface | Outcome of {@link runCryptoAgilityEmit}: the rendered manifest and the scan. |
| `EXIT` | const | Process-style exit codes qScan uses. |
| `Finding` | type |  |
| `HELP_TEXT` | const | The full `--help` screen. |
| `HndlInitResult` | interface | Outcome of {@link runHndlInit}: the scaffold plus where it should be written. |
| `ParsedArgs` | type | Result of {@link parseArgs}: either resolved options or a meta action. |
| `ParsedRun` | interface | A successful parse: resolved options plus which configurable keys were explicit. |
| `QscanFormat` | type | Output formats qScan accepts on the command line. Extends core's |
| `QscanOptions` | interface | Fully-resolved options the CLI/programmatic runner operates on. |
| `QscanRun` | interface | Outcome of {@link runQscan}. |
| `REMEDIATE_EXIT` | const |  |
| `REMEDIATE_HELP` | const |  |
| `RemediateHooks` | interface |  |
| `RemediateMode` | type |  |
| `RemediateOptions` | interface |  |
| `RemediateRun` | interface |  |
| `RenderReportOptions` | interface | Rendering controls for {@link renderReport}. |
| `ResolvedConfig` | interface | What {@link resolveConfig} returns: the merged options + provenance. |
| `RunQscanHooks` | interface | Behavioral hooks for {@link runQscan}, mainly for testing. |
| `SEVERITY_ORDER` | value |  |
| `ScanFn` | type | The scan implementation `runQscan` calls. Matches `@quantakrypto/core`'s `scan` / |
| `ScanOptions` | type |  |
| `ScanResult` | type |  |
| `applyBaseline` | function | Partition findings into those kept and those suppressed by a baseline. |
| `applyConfig` | function | Apply a parsed config onto options under the precedence rule. Pure; returns a |
| `asFormat` | function | Validate/normalize a `--format` value. |
| `asInt` | function | Validate/normalize a non-negative integer flag value. |
| `asSeverity` | function | Validate/normalize a severity value. |
| `baselineFromFindings` | value |  |
| `buildBaseline` | function | Build a {@link Baseline} from a set of findings (deduped + sorted). Alias for |
| `defaultOptions` | function | Default options, before any flags are applied. |
| `fingerprint` | const | Compute a stable fingerprint for a finding. Alias for core's |
| `fingerprintFinding` | value |  |
| `loadBaseline` | value |  |
| `meetsThreshold` | value |  |
| `parseArgs` | function |  |
| `parseRemediateArgs` | function | Parse qremediate argv. |
| `readBaseline` | function | Read a baseline file from disk and return its accepted fingerprints as a set. |
| `renderCbom` | function | Render a CycloneDX 1.6 CBOM (cryptographic bill of materials) for the scan, |
| `renderHuman` | function | Render the human-readable banner. |
| `renderJson` | function | Render the JSON report (pretty-printed, no trailing newline). |
| `renderReport` | function | Render a scan result in the requested format. |
| `renderSarif` | function | Render the SARIF 2.1.0 report (pretty-printed, no trailing newline). |
| `renderVex` | function | Render an OpenVEX 0.2.0 document for the scan (pretty-printed, no trailing |
| `resolveConfig` | function | Load and merge `quantakrypto.config.json` into the parsed CLI options. |
| `runCryptoAgilityEmit` | function | Emit a crypto-agility manifest for a repo (`qscan crypto-agility emit` / |
| `runCryptoAgilityValidate` | function | Validate a LOCAL crypto-agility manifest file against the schema |
| `runHndlInit` | function | Scaffold an `hndl.yml` for a repo (`qscan hndl init`). Runs a scan to seed the |
| `runQscan` | function | Run a complete qScan pass: scan → baseline → threshold → render. |
| `runRemediate` | function | Run a complete qremediate pass. Pure w.r.t. process; the bin prints + exits. |
| `saveBaseline` | value |  |
| `severityRank` | value |  |
| `unifiedDiff` | function | Minimal unified diff for a localized change (3 lines of context). |
| `versionLine` | function | The `--version` line. |
| `writeBaseline` | function | Serialize and write a baseline to disk (pretty-printed, trailing newline). |

## @quantakrypto/mcp

Public entry: `packages/mcp/src/index.ts` - 25 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `CORE_VERSION` | const | The core version these tools are built against (re-exported for diagnostics). |
| `Content` | type |  |
| `CreateServerOptions` | interface |  |
| `ErrorCode` | const | Standard JSON-RPC 2.0 error codes (plus MCP conventions). |
| `JSONRPC_VERSION` | const | The fixed JSON-RPC protocol marker. |
| `JsonRpcFailure` | interface | A failed JSON-RPC response. |
| `JsonRpcRequest` | interface | A JSON-RPC 2.0 request or notification (notifications omit `id`). |
| `JsonRpcResponse` | type |  |
| `JsonRpcSuccess` | interface | A successful JSON-RPC response. |
| `JsonSchema` | interface | A minimal JSON Schema object describing a tool's input. |
| `MCP_PROTOCOL_VERSION` | const | MCP protocol revision this server speaks. The `initialize` handshake echoes |
| `McpServer` | class | A minimal, spec-faithful MCP server. Register tools with {@link registerTool} |
| `McpServerOptions` | interface |  |
| `RpcError` | class | An error that carries a JSON-RPC error code, thrown by tool handlers/dispatch. |
| `SERVER_NAME` | const | The MCP server name advertised to clients. |
| `SERVER_VERSION` | const | The version reported by the server (kept in sync with @quantakrypto/core). |
| `ServerInfo` | interface | Identifying info advertised to clients during `initialize`. |
| `TextContent` | interface | A single piece of MCP content. We only emit text content in this server. |
| `ToolDefinition` | interface | A registered tool: descriptor plus its async handler. |
| `ToolDescriptor` | interface | The public descriptor of a tool, as returned by `tools/list`. |
| `ToolResult` | interface | The result envelope returned by a `tools/call`. |
| `createQuantakryptoServer` | function | Create a fully-wired quantakrypto {@link McpServer} with all tools registered. |
| `errorResult` | function | Convenience: wrap a string as an error text tool result. |
| `quantakryptoTools` | const | All quantakrypto MCP tools, in a stable order. |
| `textResult` | function | Convenience: wrap one or more strings as a non-error text tool result. |

## @quantakrypto/sieve

Public entry: `packages/sieve/src/index.ts` - 46 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `BugClass` | type | A bug-class tag linking a category/check to quantakrypto's antiform taxonomy. |
| `CATEGORIES` | const | The full catalog, in execution order. |
| `CategoryCounts` | interface | Per-category counts. |
| `CategoryResult` | interface | The aggregate outcome of running one category. |
| `Check` | interface | One atomic assertion within a category. |
| `DEFAULT_ENV_ALLOWLIST` | const | Minimal environment variables a child process generally needs to locate its |
| `DsaSizes` | interface | Byte sizes for an ML-DSA parameter set (FIPS 204, Table 2). |
| `Family` | type | Algorithm families Sieve knows how to drive. |
| `KemSizes` | interface | Byte sizes for an ML-KEM parameter set (FIPS 203, Table 3). |
| `PARAM_SETS` | const | All known parameter-set identifiers, in canonical order. |
| `PROTOCOL_VERSION` | const | Protocol version. Bumped on any breaking wire change. |
| `ParamSet` | type | Canonical parameter-set identifiers accepted on the CLI / API. |
| `ProtocolError` | class | Raised when a line from the SUT cannot be parsed into a valid Response. |
| `Request` | type | Any request Sieve may send. |
| `Response` | type | Any response the SUT may emit. |
| `RunSieveOptions` | interface | Options for {@link runSieve}. |
| `Runner` | class | A long-lived handle to a spawned SUT. Construct once per test run, issue many |
| `RunnerOptions` | interface | Options for constructing a {@link Runner}. |
| `SieveReport` | interface | The full report. |
| `SignatureFamily` | type | Families that support the signature operations (sign / verify). |
| `SignatureSizes` | type | A signature-family size record (ML-DSA or SLH-DSA). |
| `Sizes` | type | Union of the size shapes. |
| `SlhDsaSizes` | interface | Byte sizes for an SLH-DSA parameter set (FIPS 205, Table 2). |
| `Status` | type | Status of a single check or a whole category. |
| `SutCrashError` | class | Thrown when the SUT process dies before/while a request is in flight. |
| `TimeoutError` | class | Thrown when a request exceeds its timeout. |
| `Vector` | type | Any normalized vector. |
| `VectorSet` | interface | Result of scanning a vectors directory. |
| `asDsaSizes` | function | Narrowing helper: DSA size record or `undefined`. |
| `asKemSizes` | function | Narrowing helper: KEM size record or `undefined`. |
| `asSignatureSizes` | function | Narrowing helper: any signature-family size record (ML-DSA or SLH-DSA) or |
| `asSlhDsaSizes` | function | Narrowing helper: SLH-DSA size record or `undefined`. |
| `buildReport` | function | Assemble a {@link SieveReport} from category results and run metadata. |
| `buildSutEnv` | function | Build the environment handed to the spawned SUT. |
| `categoriesFor` | function | Categories applicable to a family (plus family-agnostic ones). |
| `decodeResponse` | function | Parse one NDJSON line from the SUT into a validated {@link Response}. |
| `encodeRequest` | function | Serialize a request to a single NDJSON line (including the trailing "\n"). |
| `formatHuman` | function | Human-readable terminal rendering (no color codes; CI-friendly). |
| `formatJson` | function | Pretty JSON rendering. |
| `fromB64` | function | Decode a base64 string to bytes. |
| `isParamSet` | function | Type guard: is `s` a recognized parameter-set identifier? |
| `loadVectors` | function |  |
| `overallVerdict` | function | Compute the overall verdict: FAIL if any non-advisory category failed. |
| `runSieve` | function | Spawn the SUT, run the applicable categories, and return an aggregated |
| `sizesFor` | function | Look up the size record for a parameter set. |
| `toB64` | function | Encode raw bytes to a base64 string. |

## @quantakrypto/agent

Public entry: `packages/agent/src/index.ts` - 18 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `AGENT_PACKAGE` | const | @quantakrypto/agent — BYOK LLM client for qScan triage and remediation. |
| `FIX_PROMPT_VERSION` | const | Bump when the fix rubric/schema changes. |
| `JsonSchema` | type | A tiny JSON-Schema validator covering exactly the subset the agent emits |
| `LlmClient` | interface | A provider adapter: turns an {@link LlmRequest} into schema-valid JSON. |
| `LlmConfig` | interface | BYOK provider configuration. `apiKey` is resolved from env by the caller. |
| `LlmRequest` | interface | A single structured completion request. |
| `ProposeFixOptions` | interface |  |
| `TRIAGE_PROMPT_VERSION` | const | Bump when the rubric/schema changes so the response cache invalidates. |
| `TriageOptions` | interface |  |
| `anthropicClient` | function |  |
| `cacheKey` | function | Compose the cache key for one finding's request. |
| `loadResponseCache` | function | Load the response cache, or an empty map on any problem. |
| `openAiCompatibleClient` | function |  |
| `proposeFix` | function | Ask the model for a fix. Returns a {@link FixProposal} (full new file content) |
| `resolveClient` | function | Pick the adapter for `config.provider`. `fetchImpl` is injectable for tests. |
| `saveResponseCache` | function | Write the response cache atomically. Errors are swallowed. |
| `triageFindings` | function | Produce an exposure verdict per above-floor finding. |
| `validateAgainstSchema` | function | Validate `value` against the JSON-Schema subset we emit. |

## @quantakrypto/qprobe

Public entry: `packages/qprobe/src/index.ts` - 42 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `AttestationError` | class |  |
| `AttestationInput` | interface |  |
| `EndpointReport` | interface |  |
| `GROUP_SECP256R1` | const |  |
| `GROUP_X25519` | const |  |
| `GROUP_X25519MLKEM768` | const |  |
| `HybridSupport` | interface |  |
| `IMAP_DIALOG` | const | IMAP (RFC 3501): `* OK` greeting → `a1 STARTTLS` → `a1 OK`. |
| `KexInit` | interface |  |
| `POP3_DIALOG` | const | POP3 (RFC 2595): `+OK` greeting → `STLS` → `+OK`. |
| `PQ_SSH_KEX` | const | PQC / hybrid SSH key-exchange algorithm names (OpenSSH + drafts). |
| `ProbeMode` | type |  |
| `RunOptions` | interface |  |
| `RunResult` | interface |  |
| `ServerHelloInfo` | interface | The result of reading a ServerHello / HelloRetryRequest. |
| `SshProbeResult` | interface |  |
| `Target` | interface | A single validated endpoint. |
| `TargetError` | class |  |
| `TlsNegotiated` | interface |  |
| `TlsRecord` | interface | A parsed TLS record. |
| `authorizeTargets` | function | Authorize a set of targets or throw {@link AttestationError}. Returns silently |
| `buildClientHello` | function | Build a raw ClientHello TLS record advertising the hybrid group. `keyShareGroup` |
| `certSignatureAlgorithm` | function | Extract the signatureAlgorithm OID (and mapped family) from a DER certificate. |
| `classifySsh` | function | Findings for an SSH endpoint from its KEXINIT. |
| `classifyTls` | function | Findings for a TLS endpoint from the negotiated params + the hybrid probe. |
| `decodeOid` | function | Decode a DER OID value (the bytes inside the OID TLV) to dotted-decimal. |
| `oidToSignatureFamily` | function | Map a signature-algorithm OID to a classical family (or undefined). |
| `parseOwnedHosts` | function | Parse an ownership manifest file's text into a host allow-list. |
| `parseRecords` | function | Split a buffer into TLS records. Stops at the first truncated record. |
| `parseServerHelloBody` | function | Parse a ServerHello handshake message body (the bytes AFTER the 4-byte handshake |
| `parseTarget` | function | Parse and validate a single target. Throws {@link TargetError} for anything |
| `readServerHello` | function | Read the first ServerHello/HRR out of a raw response buffer, if any. |
| `resolveMode` | function | Choose a probe mode for "auto" from the well-known port: SSH on 22, SMTP |
| `runProbe` | function | Authorize (throws {@link AttestationError} / {@link TargetError} on failure — no |
| `smtpAdvertisesStartTls` | function | True if an EHLO reply advertises the STARTTLS capability. |
| `smtpReplyComplete` | function | True once `buf` contains a COMPLETE SMTP reply (last line is `NNN␠…`). |
| `sslRequestFrame` | function | The 8-byte libpq SSLRequest message: length(0x00000008) + code(80877103). |
| `toCbomReport` | function |  |
| `toJsonReport` | function |  |
| `toSarifReport` | function |  |
| `toScanResult` | function | Adapt a {@link RunResult} to a {@link ScanResult}. `filesScanned` is the number |
| `x25519RawPublic` | function | A raw 32-byte X25519 public key (from node:crypto — a real, valid key). |
