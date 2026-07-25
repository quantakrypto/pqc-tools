<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpenSSF Best Practices badge - pre-filled answers

Answer sheet for the [OpenSSF Best Practices](https://www.bestpractices.dev) (formerly CII) **passing** badge for `quantakrypto/pqc-tools`. Register the project at bestpractices.dev (sign in with GitHub, add `https://github.com/quantakrypto/pqc-tools`), then use the evidence below to answer each criterion. Almost every criterion is already **Met**.

When done, paste the badge markdown into `README.md` and Scorecard's CII-Best-Practices check goes green.

Legend: **Met** / **N/A** / *Unmet (action)*.

## Basics
| Criterion | Answer | Evidence |
|---|---|---|
| description_good | Met | `README.md` describes the toolkit (qScan, Sieve, qProbe, MCP, action). |
| interact / discussion | Met | GitHub Issues + Discussions enabled. |
| contribution | Met | `CONTRIBUTING.md`. |
| contribution_requirements | Met | `CONTRIBUTING.md` states PR + tests + lint requirements. |
| floss_license / _osi | Met | Apache-2.0 (OSI-approved); `package.json` `"license": "Apache-2.0"`, `REUSE.toml` `path="**"`. |
| license_location | Met | `LICENSE` at repo root. |
| documentation_basics | Met | `README.md` + `docs/` (API, CONFIG, VERSIONING, THREAT-MODEL, SUPPLY-CHAIN, COMPLIANCE, ADRs). |
| documentation_interface | Met | `docs/API.md`, per-package READMEs, generated `api-surface.json`. |
| sites_https | Met | GitHub + npm are HTTPS. |
| english | Met | All docs in English. |
| maintained | Met | Active commit history; Dependabot + CI. |

## Change control
| Criterion | Answer | Evidence |
|---|---|---|
| repo_public / repo_track / repo_distributed | Met | Public Git repo on GitHub. |
| version_unique / version_semver | Met | Per-package semver; policy in `docs/VERSIONING.md`. |
| version_tags | Met | Git tags + GitHub Releases; `v1` action tag. |
| release_notes | Met | `CHANGELOG.md`. |
| release_notes_vulns | Met | `CHANGELOG.md` records security-relevant fixes (e.g., the recent ReDoS / sampling fixes). |

## Reporting
| Criterion | Answer | Evidence |
|---|---|---|
| report_process / report_tracker / report_archive | Met | GitHub Issues (public, archived). |
| report_responses / enhancement_responses | Met | Maintainers triage issues/PRs. |
| vulnerability_report_process | Met | `SECURITY.md` → **security@quantakrypto.com** + GitHub private vulnerability reporting; follows ISO/IEC 29147 + 30111. |
| vulnerability_report_private | Met | `SECURITY.md` documents private reporting (email + GitHub "Report a vulnerability"). |
| vulnerability_report_response | Met | `SECURITY.md` commits to a plan within 10 business days. |

## Quality
| Criterion | Answer | Evidence |
|---|---|---|
| build / build_common_tools / build_floss_tools | Met | `npm run build` (`tsc --build`); FLOSS toolchain. |
| test / test_invocation | Met | `npm test` (Node built-in test runner; `packages/*/test/*.test.ts` + `scripts/test`). |
| test_most | Met | Broad unit tests + property-based fuzz tests (fast-check) on the parsers. |
| test_continuous_integration | Met | `.github/workflows/ci.yml` runs build + test + lint on every PR and push (required status checks). |
| test_policy / tests_are_added / tests_documented_added | Met | `CONTRIBUTING.md` requires tests for new functionality; enforced in review. |
| warnings / warnings_fixed / warnings_strict | Met | ESLint (`npm run lint`) + strict `tsconfig`; CI "lint + format" gate blocks on warnings. |

## Security
| Criterion | Answer | Evidence |
|---|---|---|
| know_secure_design / know_common_errors | Met | `docs/THREAT-MODEL.md`, ADRs, and the team builds PQC security tooling; CodeQL + Scorecard + qScan self-scan in CI. |
| crypto_published | Met | Uses NIST-standardized algorithms (FIPS 203/204/205) and Node's `crypto`; no home-grown primitives. |
| crypto_call / crypto_floss | Met | Cryptographic operations use Node.js `crypto` (FLOSS, widely reviewed). |
| crypto_keylength | Met | Standard parameter sets (e.g., ML-KEM-768); no undersized keys. |
| crypto_working / crypto_weaknesses | Met | No broken algorithms used for security (MD5/SHA-1 appear only as *detection targets*, not in the tool's own security). |
| crypto_random | Met | `crypto.randomBytes`; the ML-KEM probe key uses unbiased rejection sampling. |
| crypto_pfs | N/A | Not a network service establishing long-lived sessions; qProbe is a read-only client, hosted MCP TLS is terminated by the platform. |
| crypto_password_storage / crypto_certificate_verification | N/A | No password storage. qProbe deliberately does not verify certs (it inspects posture, documented). |
| delivery_mitm / delivery_unsigned | Met | npm over HTTPS **with provenance** (Sigstore/OIDC in `release.yml`); GitHub Actions pinned by commit SHA (`scripts/check-action-pins.mjs`). |
| vulnerabilities_fixed_60_days / vulnerabilities_critical_fixed | Met | Dependabot enabled; recent High alerts (js-yaml, brace-expansion) fixed promptly. |
| no_leaked_credentials | Met | GitHub secret scanning enabled; no secrets committed. |

## Analysis
| Criterion | Answer | Evidence |
|---|---|---|
| static_analysis / _common_vulnerabilities | Met | CodeQL (`.github/workflows/codeql.yml`), ESLint, OpenSSF Scorecard, and qScan self-scan (dogfood) all run in CI. |
| static_analysis_fixed | Met | CodeQL findings triaged: real ones fixed, by-design ones dismissed with reasons. |
| static_analysis_often | Met | CodeQL runs on every push/PR + weekly schedule. |
| dynamic_analysis | Met | Property-based fuzzing (fast-check) of the untrusted-input parsers (qProbe TLS/SSH/X.509, Sieve protocol). |
| dynamic_analysis_unsafe | N/A | TypeScript/JavaScript (memory-safe); no unsafe-language analysis needed. |
| dynamic_analysis_enable_assertions | Met | Tests assert invariants; fuzz properties assert robustness contracts. |

---
Net: every **MUST** for the passing badge is satisfied. Register, confirm each row above, and add the badge to `README.md`.
