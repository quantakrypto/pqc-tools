/**
 * Static help / usage text for the qScan CLI.
 *
 * Kept in its own module so it can be unit-tested and reused without pulling in
 * filesystem or process side effects.
 */

import { VERSION } from "@quantakrypto/core";

/** The full `--help` screen. */
export const HELP_TEXT = `qscan — find quantum-vulnerable cryptography in any codebase

USAGE
  qscan [path] [options]
  qscan hndl init [path]        Scaffold an hndl.yml data map (see --hndl)
  qscan crypto-agility emit [path]    Write a crypto-agility manifest (exits 0)
  qscan crypto-agility validate <file>  Check a local manifest against the schema

ARGUMENTS
  path                          Directory or file to scan (default: ".")

OPTIONS
  --format <human|json|sarif|cbom|evidence|vex>
                                Output format (default: human)
  --cbom                        Alias for --format cbom (CycloneDX CBOM)
  --format vex                  OpenVEX 0.2.0 document — one statement per rule,
                                status "affected", with remediation + any
                                --triage verdict for supply-chain VEX pipelines
  --merge <cbom.json>           Merge an external CBOM (e.g. a qprobe endpoint
                                CBOM) into the --cbom output via CycloneDX
                                bom-link — one combined code + infra CBOM.
                                Repeatable.
  --format evidence             ISO 27001 A.8.24 readiness report — findings +
                                inventory + CBOM + a deterministic content hash
                                (sign/timestamp it with an external signer)
  --policy <file>               Crypto-policy JSON; adds conformant/violation/
                                transition verdicts to the evidence report. With
                                --mandate, permitted/in-transition families are
                                acknowledged and exempt from --fail-now/--lead-months
                                (a passed disallow deadline still fails)
  --sign <command>              Sign the evidence report: its contentHash is
                                piped to <command> on stdin; stdout is recorded
                                as the detached signature (needs --format evidence)
  --timestamp <command>         Like --sign, but records an RFC-3161 timestamp
                                token from <command> (needs --format evidence)
  -o, --output <file>           Write the report to a file instead of stdout
  --severity-threshold <level>  Fail (exit 1) on findings at/above this level;
                                one of critical|high|medium|low|info
                                (default: high)
  --no-source                   Skip scanning source files for inline crypto
  --no-deps                     Skip scanning dependency manifests
  --no-config                   Skip scanning config files (TLS/certificates)
  --config <path>               Use this quantakrypto.config.json instead of
                                auto-discovering one at the scan root
  --no-config-file              Disable quantakrypto.config.json auto-discovery
  --ignore <pattern>            Exclude paths matching <pattern> (repeatable)
  --include <pattern>           Restrict the scan to matching paths (repeatable)
  --max-file-size <bytes>       Skip files larger than <bytes> (default: 2 MiB)
  --no-default-ignores          Don't skip node_modules/.git/dist by default
  --scan-minified               Scan minified/generated/bundled files too
  --changed                     Scan only files changed in the git work tree
  --since <git-ref>             With --changed, diff against <git-ref>
  --parallel                    Scan using a worker-thread pool when worthwhile
  --concurrency <n>             Worker count for --parallel (implies --parallel);
                                0 forces the in-process serial path
  --top <n>                     List <n> findings in the human report (default: 5)
  --tier <category-3|category-5> Add CNSA migration targets to the report footer
                                (category-5 = CNSA 2.0: ML-KEM-1024 / ML-DSA-87;
                                an alias for --profile cnsa-2.0)
  --profile <id>                Tailor migration guidance to a standards regime:
                                nist (default) | cnsa-2.0 | bsi-tr-02102 | anssi |
                                uk-ncsc. Sets the parameter sets, deadlines, and
                                whether hybridization is required/recommended/optional
  --mandate <id>                Gate findings against a compliance mandate's dated
                                clauses (repeatable): cnsa-2.0 | nist-ir-8547. Reports
                                each prohibited finding with its clause + deadline;
                                fails the build only once a disallow deadline has passed
                                (a passed deprecate date warns). The
                                verdicts also ride in --format json (mandateMapping),
                                sarif (run.properties.mandate), and evidence (hashed)
  --lead-months <n>             Fail early when a --mandate deadline is within n months
  --fail-now                    Fail on any --mandate-prohibited finding, ignoring the date
  --cache [file]                Reuse findings for unchanged files across runs
                                (default file: .quantakrypto-cache.json)
  --triage                      BYOK LLM pass that re-ranks findings by real
                                exposure and explains them (never suppresses,
                                never changes the exit code). Needs an API key in
                                QK_LLM_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY
  --triage-floor <level>        Only triage findings at/above this level (default: medium)
  --max-findings <n>            Cap findings sent to the LLM during triage (default: 100; spend guard)
  --context <level>             Source shared with the LLM: metadata|snippet|
                                function|file (default: snippet; secrets always redacted)
  --dry-run                     With --triage, print the exact payload that would
                                be sent and exit without calling the provider
  --llm-provider <name>         anthropic | openai-compatible (default: anthropic)
  --llm-model <id>              Model id for the BYOK provider
  --hndl                        Score harvest-now-decrypt-later exposure per
                                finding + a repo summary from hndl.yml (data
                                assets, classification, retention + secrecy
                                lifetime vs the quantum-threat horizon; Mosca's
                                inequality). Adds exposure fields to json/sarif;
                                additive, never changes the exit code. Scaffold
                                the map with "qscan hndl init". See docs/HNDL.md
  --audit                       Opt-in supply-chain audit: run each present
                                ecosystem's advisory tool (cargo audit / pip-audit
                                / npm audit) for known-vulnerable pinned
                                dependencies, and verify the declared source
                                repository resolves (provenance). Findings merge
                                into the report and the exit code. A missing tool
                                or a network hiccup degrades to a diagnostic on
                                stderr, never a failure. Requires the ecosystem's
                                audit tool on PATH; the provenance HEAD request is
                                the only network call qScan itself makes
  --crypto-agility              Emit a crypto-agility posture manifest instead of a
                                scan report (equivalent to "crypto-agility emit";
                                always exits 0). A well-known-URL JSON document any
                                agent/CI bot can read like security.txt: readiness
                                score, quantum-vulnerable findings by severity, CBOM
                                algorithm families, policy deadlines. Combine with
                                --attestation / --hybrid-kex / --policy / -o.
                                See docs/CRYPTO-AGILITY-MANIFEST.md
  --attestation <url>           Record a posture-credential URL in the manifest
                                (recorded verbatim, never fetched; offline boundary)
  --hybrid-kex / --no-hybrid-kex
                                Assert hybrid post-quantum key exchange is / is not
                                in use in the manifest (default: null / undetermined,
                                since a static scan can't observe a negotiated group)
  --baseline <file>             Suppress findings listed in a baseline file
  --write-baseline <file>       Write current findings as a baseline, then exit 0
  --quiet                       Suppress the human summary banner
  --no-snippets                 Omit code snippets from the json/sarif report
  --color                       Force ANSI color in the human report
  --no-color                    Disable ANSI color (also: NO_COLOR env). Color is
                                decoration only — every signal is printed as text
  -v, --version                 Print version and exit
  -h, --help                    Print this help and exit

EXIT CODES
  0   No findings at/above the threshold (or a baseline was written)
  1   One or more findings at/above the severity threshold
  2   Usage error or I/O failure

EXAMPLES
  qscan .                       Scan the current directory
  qscan src --format sarif -o qscan.sarif
  qscan . --severity-threshold critical
  qscan . --write-baseline qscan-baseline.json
  qscan . --baseline qscan-baseline.json
  qscan . --include src --include lib
  qscan . --config ./ci/quantakrypto.config.json
  qscan . --changed --since origin/main
  qscan . --parallel --concurrency 4
  qscan . --cbom -o qscan-cbom.json
  qscan hndl init               Scaffold hndl.yml seeded with detected assets
  qscan . --hndl --format json  Emit per-finding HNDL exposure + a repo summary
  qscan . --audit               Add dependency-advisory + provenance checks
  qscan . --crypto-agility -o .well-known/crypto-agility.json
  qscan crypto-agility validate .well-known/crypto-agility.json
`;

/** The `--version` line. */
export function versionLine(): string {
  return `qscan ${VERSION}`;
}
