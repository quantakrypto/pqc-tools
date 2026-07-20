# Public API reference

> **Generated** by `scripts/gen-api-reference.mjs` — do not edit by hand. Run
> `npm run api:docs` to regenerate; `npm run api:check` fails CI if it drifts.

Only the symbols listed here are covered by the SemVer contract
([VERSIONING.md](VERSIONING.md)). Anything not re-exported from a package's entry
point is internal and may change in a patch. The machine-readable frozen surface is
[`api-surface.json`](api-surface.json).

## @quantakrypto/core

Public entry: `packages/core/src/index.ts` — 139 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `ANALYZABLE_LANGUAGES_LABEL` | value |  |
| `ANALYZABLE_SOURCE_EXTENSIONS` | value |  |
| `AbortError` | value |  |
| `AlgorithmFamily` | type | @quantakrypto/core — shared types (the locked public contract). |
| `BASELINE_VERSION` | value |  |
| `Baseline` | type |  |
| `BudgetExceededError` | value |  |
| `CONFIG_FILENAME` | value |  |
| `CWE_BROKEN_CRYPTO` | value |  |
| `CWE_CERT_VALIDATION` | value |  |
| `CWE_HARDCODED_KEY` | value |  |
| `CWE_RISKY_PRIMITIVE` | value |  |
| `CWE_WEAK_STRENGTH` | value |  |
| `CbomComponent` | type |  |
| `ChunkResult` | type |  |
| `Codemod` | type |  |
| `Confidence` | type | @quantakrypto/core — shared types (the locked public contract). |
| `ConfigError` | value |  |
| `ContextLevel` | type |  |
| `CryptoInventory` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `CryptoPolicy` | type |  |
| `CycloneDxBom` | type |  |
| `DEP_VULNERABLE_RULE` | value |  |
| `DependencyEcosystem` | type | @quantakrypto/core — shared types (the locked public contract). |
| `Detector` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `DetectorInput` | interface |  |
| `DetectorLanguage` | type | @quantakrypto/core — shared types (the locked public contract). |
| `DetectorRegistry` | value |  |
| `DetectorScope` | type | @quantakrypto/core — shared types (the locked public contract). |
| `EvidenceFinding` | type |  |
| `EvidenceSigner` | type |  |
| `FIX_REQUEST_SCHEMA` | value |  |
| `Finding` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `FindingCategory` | type | @quantakrypto/core — shared types (the locked public contract). |
| `FixProposal` | type |  |
| `LoadConfigResult` | type |  |
| `PQC_STANDARDS` | value |  |
| `PQC_TRANSITION_NOTE` | value |  |
| `ParallelScanOptions` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `Patch` | type |  |
| `PolicyContext` | type |  |
| `PolicyDecision` | type |  |
| `PolicyFindingVerdict` | type |  |
| `PolicyMapping` | type |  |
| `PolicyVerdict` | type |  |
| `PqcStandards` | type |  |
| `QuantakryptoFileConfig` | type |  |
| `REMEDIATE_RUBRIC` | value |  |
| `ReadinessReport` | type |  |
| `ReadinessReportOptions` | type |  |
| `RedactedContext` | type |  |
| `RejectedPatch` | type |  |
| `RemediateOptions` | type |  |
| `RemediateRequest` | type |  |
| `Remediation` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `RemediationResult` | type |  |
| `ReportFormat` | type | @quantakrypto/core — shared types (the locked public contract). |
| `ReportOptions` | type |  |
| `RuleCatalogEntry` | type |  |
| `RuleMeta` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `SEVERITY_ORDER` | value |  |
| `STATEFUL_HBS_NOTE` | value |  |
| `SarifLog` | type |  |
| `ScanChunk` | type |  |
| `ScanDiagnostics` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `ScanOptions` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `ScanResult` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `SecurityTier` | type |  |
| `Severity` | type | @quantakrypto/core — shared types (the locked public contract). |
| `SignEvidenceOptions` | type |  |
| `SizedFile` | type |  |
| `SourceLocation` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `StandardsCitation` | type |  |
| `StandardsReviewStatus` | type |  |
| `TIER_PARAMS` | value |  |
| `TRIAGE_RUBRIC` | value |  |
| `TRIAGE_VERDICT_SCHEMA` | value |  |
| `TriageAnnotation` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `TriagePriority` | type | @quantakrypto/core — shared types (the locked public contract). |
| `TriageRequest` | type |  |
| `TriageVerdict` | type |  |
| `VERSION` | value |  |
| `VerifiedPatch` | type |  |
| `VerifyResult` | type |  |
| `VulnerableDependency` | interface | @quantakrypto/core — shared types (the locked public contract). |
| `applyBaseline` | value |  |
| `baselineFromFindings` | value |  |
| `buildContext` | value |  |
| `buildInventory` | value |  |
| `buildPolicyMapping` | value |  |
| `buildReadinessReport` | value |  |
| `buildRemediateRequest` | value |  |
| `buildTriageRequest` | value |  |
| `changedFiles` | value |  |
| `checkPatchPolicy` | value |  |
| `chunkByBytes` | value |  |
| `codemodFor` | value |  |
| `codemodRegistry` | value |  |
| `compareFindings` | value |  |
| `configToggleCodemod` | value |  |
| `defaultRegistry` | value |  |
| `detectFile` | value |  |
| `detectorScope` | value |  |
| `detectors` | value |  |
| `fingerprintFinding` | value |  |
| `formatSummary` | value |  |
| `formatTierGuidance` | value |  |
| `isAnalyzableSource` | value |  |
| `isBinaryPath` | value |  |
| `isGeneratedPath` | value |  |
| `isManifestFile` | value |  |
| `languageToExtension` | value |  |
| `loadBaseline` | value |  |
| `loadConfig` | value |  |
| `looksMinified` | value |  |
| `meetsThreshold` | value |  |
| `mergeCboms` | value |  |
| `mergeChunkResults` | value |  |
| `parseCryptoPolicy` | value |  |
| `remediateFindings` | value |  |
| `remediationFor` | value |  |
| `remediationForTier` | value |  |
| `renderPreflight` | value |  |
| `sarifLevel` | value |  |
| `saveBaseline` | value |  |
| `scan` | value |  |
| `scanParallel` | value |  |
| `severityRank` | value |  |
| `signReadinessReport` | value |  |
| `standardsReviewStatus` | value |  |
| `statefulHbsApplies` | value |  |
| `toCbom` | value |  |
| `toJson` | value |  |
| `toSarif` | value |  |
| `verdictForAlgorithm` | value |  |
| `verifyFix` | value |  |
| `vulnerableDependencies` | value |  |
| `walkFiles` | value |  |
| `withWorktree` | value |  |

## @quantakrypto/qscan

Public entry: `packages/qscan/src/index.ts` — 54 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `ArgError` | value |  |
| `BASELINE_VERSION` | value |  |
| `Baseline` | type |  |
| `ChangedFilesFn` | type | @quantakrypto/qscan — programmatic API. |
| `ConfigurableKey` | type |  |
| `EXIT` | const | @quantakrypto/qscan — programmatic API. |
| `Finding` | type |  |
| `HELP_TEXT` | value |  |
| `ParsedArgs` | type |  |
| `ParsedRun` | type |  |
| `QscanFormat` | type |  |
| `QscanOptions` | type |  |
| `QscanRun` | interface | @quantakrypto/qscan — programmatic API. |
| `REMEDIATE_EXIT` | value |  |
| `REMEDIATE_HELP` | value |  |
| `RemediateHooks` | type |  |
| `RemediateMode` | type |  |
| `RemediateOptions` | type |  |
| `RemediateRun` | type |  |
| `RenderReportOptions` | interface | @quantakrypto/qscan — programmatic API. |
| `ResolvedConfig` | type |  |
| `RunQscanHooks` | interface | @quantakrypto/qscan — programmatic API. |
| `SEVERITY_ORDER` | value |  |
| `ScanFn` | type | @quantakrypto/qscan — programmatic API. |
| `ScanOptions` | type |  |
| `ScanResult` | type |  |
| `applyBaseline` | value |  |
| `applyConfig` | value |  |
| `asFormat` | value |  |
| `asInt` | value |  |
| `asSeverity` | value |  |
| `baselineFromFindings` | value |  |
| `buildBaseline` | value |  |
| `defaultOptions` | value |  |
| `fingerprint` | value |  |
| `fingerprintFinding` | value |  |
| `loadBaseline` | value |  |
| `meetsThreshold` | value |  |
| `parseArgs` | value |  |
| `parseRemediateArgs` | value |  |
| `readBaseline` | value |  |
| `renderCbom` | value |  |
| `renderHuman` | value |  |
| `renderJson` | value |  |
| `renderReport` | function | @quantakrypto/qscan — programmatic API. |
| `renderSarif` | value |  |
| `resolveConfig` | value |  |
| `runQscan` | function | @quantakrypto/qscan — programmatic API. |
| `runRemediate` | value |  |
| `saveBaseline` | value |  |
| `severityRank` | value |  |
| `unifiedDiff` | value |  |
| `versionLine` | value |  |
| `writeBaseline` | value |  |

## @quantakrypto/mcp

Public entry: `packages/mcp/src/index.ts` — 25 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `CORE_VERSION` | value |  |
| `Content` | type |  |
| `CreateServerOptions` | interface |  |
| `ErrorCode` | value |  |
| `JSONRPC_VERSION` | value |  |
| `JsonRpcFailure` | type |  |
| `JsonRpcRequest` | type |  |
| `JsonRpcResponse` | type |  |
| `JsonRpcSuccess` | type |  |
| `JsonSchema` | type |  |
| `MCP_PROTOCOL_VERSION` | value |  |
| `McpServer` | value |  |
| `McpServerOptions` | type |  |
| `RpcError` | value |  |
| `SERVER_NAME` | const | @quantakrypto/mcp — public API. |
| `SERVER_VERSION` | const | @quantakrypto/mcp — public API. |
| `ServerInfo` | type |  |
| `TextContent` | type |  |
| `ToolDefinition` | type |  |
| `ToolDescriptor` | type |  |
| `ToolResult` | type |  |
| `createQuantakryptoServer` | function | @quantakrypto/mcp — public API. |
| `errorResult` | value |  |
| `quantakryptoTools` | value |  |
| `textResult` | value |  |

## @quantakrypto/sieve

Public entry: `packages/sieve/src/index.ts` — 46 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `BugClass` | type |  |
| `CATEGORIES` | value |  |
| `CategoryCounts` | type |  |
| `CategoryResult` | type |  |
| `Check` | type |  |
| `DEFAULT_ENV_ALLOWLIST` | value |  |
| `DsaSizes` | type |  |
| `Family` | type |  |
| `KemSizes` | type |  |
| `PARAM_SETS` | value |  |
| `PROTOCOL_VERSION` | value |  |
| `ParamSet` | type |  |
| `ProtocolError` | value |  |
| `Request` | type |  |
| `Response` | type |  |
| `RunSieveOptions` | interface | @quantakrypto/sieve — programmatic API. |
| `Runner` | value |  |
| `RunnerOptions` | type |  |
| `SieveReport` | type |  |
| `SignatureFamily` | type |  |
| `SignatureSizes` | type |  |
| `Sizes` | type |  |
| `SlhDsaSizes` | type |  |
| `Status` | type |  |
| `SutCrashError` | value |  |
| `TimeoutError` | value |  |
| `Vector` | type |  |
| `VectorSet` | type |  |
| `asDsaSizes` | value |  |
| `asKemSizes` | value |  |
| `asSignatureSizes` | value |  |
| `asSlhDsaSizes` | value |  |
| `buildReport` | value |  |
| `buildSutEnv` | value |  |
| `categoriesFor` | value |  |
| `decodeResponse` | value |  |
| `encodeRequest` | value |  |
| `formatHuman` | value |  |
| `formatJson` | value |  |
| `fromB64` | value |  |
| `isParamSet` | value |  |
| `loadVectors` | value |  |
| `overallVerdict` | value |  |
| `runSieve` | function | @quantakrypto/sieve — programmatic API. |
| `sizesFor` | value |  |
| `toB64` | value |  |

## @quantakrypto/agent

Public entry: `packages/agent/src/index.ts` — 18 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `AGENT_PACKAGE` | const | @quantakrypto/agent — BYOK LLM client for qScan triage and remediation. |
| `FIX_PROMPT_VERSION` | value |  |
| `JsonSchema` | type |  |
| `LlmClient` | type |  |
| `LlmConfig` | type |  |
| `LlmRequest` | type |  |
| `ProposeFixOptions` | type |  |
| `TRIAGE_PROMPT_VERSION` | value |  |
| `TriageOptions` | type |  |
| `anthropicClient` | value |  |
| `cacheKey` | value |  |
| `loadResponseCache` | value |  |
| `openAiCompatibleClient` | value |  |
| `proposeFix` | value |  |
| `resolveClient` | value |  |
| `saveResponseCache` | value |  |
| `triageFindings` | value |  |
| `validateAgainstSchema` | value |  |

## @quantakrypto/qprobe

Public entry: `packages/qprobe/src/index.ts` — 42 exported symbols.

| Symbol | Kind | Summary |
| --- | --- | --- |
| `AttestationError` | value |  |
| `AttestationInput` | value |  |
| `EndpointReport` | interface |  |
| `GROUP_SECP256R1` | const |  |
| `GROUP_X25519` | const |  |
| `GROUP_X25519MLKEM768` | const |  |
| `HybridSupport` | type |  |
| `IMAP_DIALOG` | value |  |
| `KexInit` | type |  |
| `POP3_DIALOG` | value |  |
| `PQ_SSH_KEX` | value |  |
| `ProbeMode` | type |  |
| `RunOptions` | interface |  |
| `RunResult` | interface |  |
| `ServerHelloInfo` | interface | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `SshProbeResult` | type |  |
| `Target` | type |  |
| `TargetError` | value |  |
| `TlsNegotiated` | type |  |
| `TlsRecord` | interface | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `authorizeTargets` | value |  |
| `buildClientHello` | function | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `certSignatureAlgorithm` | value |  |
| `classifySsh` | value |  |
| `classifyTls` | value |  |
| `decodeOid` | value |  |
| `oidToSignatureFamily` | value |  |
| `parseOwnedHosts` | value |  |
| `parseRecords` | function | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `parseServerHelloBody` | function | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `parseTarget` | value |  |
| `readServerHello` | function | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
| `resolveMode` | function | @quantakrypto/qprobe — active post-quantum readiness probing of live TLS/SSH |
| `runProbe` | function | @quantakrypto/qprobe — active post-quantum readiness probing of live TLS/SSH |
| `smtpAdvertisesStartTls` | value |  |
| `smtpReplyComplete` | value |  |
| `sslRequestFrame` | value |  |
| `toCbomReport` | value |  |
| `toJsonReport` | value |  |
| `toSarifReport` | value |  |
| `toScanResult` | value |  |
| `x25519RawPublic` | function | Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest |
