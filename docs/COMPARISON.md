# quantakrypto/pqc-tools: How It Compares

Two head-to-head comparisons: **quantakrypto vs QRAMM / cryptodeps** (another crypto-dependency scanner) and **quantakrypto vs NIST** (the standards baseline both tools serve).

Scope note: every factual claim about quantakrypto below was verified against the source in `packages/` of this repo. Counts were produced by importing the built registry (`packages/core/dist/registry.js`) and the dependency catalog (`packages/core/dist/dependencies.js`), not read from prose. Claims about cryptodeps are taken from its published `PATTERNS.md`. Claims about NIST reflect the dated, cited standards snapshot the tool itself tracks in `packages/core/src/standards.ts` (see also [COMPLIANCE.md](COMPLIANCE.md) and [standards/pqc-standards.md](standards/pqc-standards.md)).

## What quantakrypto is

quantakrypto/pqc-tools is an open-source, zero-runtime-dependency toolchain for finding quantum-vulnerable cryptography in a codebase and its infrastructure, scoring post-quantum (PQC) readiness, wiring a CI gate, and conformance-testing PQC implementations. It ships as a monorepo of composable packages sharing one engine (`@quantakrypto/core`):

| Package | Role |
|---|---|
| `@quantakrypto/qscan` | CLI scanner: readiness score, SARIF / JSON / CBOM / OpenVEX / evidence output |
| `@quantakrypto/core` | Shared engine: detectors, dependency catalog, reporters, remediation, standards |
| `@quantakrypto/mcp` | Model Context Protocol server exposing scan / inventory / explain / plan tools to AI agents |
| `@quantakrypto/action` | GitHub Action that fails CI only on *new* quantum-vulnerable crypto |
| `@quantakrypto/sieve` | Conformance battery for ML-KEM / ML-DSA / SLH-DSA implementations (FIPS 203/204/205) |
| `@quantakrypto/qprobe` | Active probing of live TLS/SSH endpoints you own for PQC-hybrid readiness (ownership-gated) |
| `@quantakrypto/agent` | Opt-in BYOK LLM client (the only networked, key-holding plane) that powers `--triage` and `qremediate --llm` |

The engine posture is deterministic and offline by default: the model proposes, the engine disposes (verified in `packages/core/README.md`, ADR 0005, and the qProbe threat model). LLM assistance is isolated to `@quantakrypto/agent`; the deterministic detectors, patch policy, and `verify_fix` gate are the authority on what ships.

---

# Part 1: quantakrypto vs QRAMM / cryptodeps

cryptodeps (csnp, part of the QRAMM ecosystem) is a dependency-and-import crypto scanner. Its documented strength is per-ecosystem import-pattern matching over a large curated package database, plus, for Go, call-graph reachability analysis. It is a fair comparison point but not an identical remit.

## 1.1 Methodology, side by side

| Dimension | quantakrypto/pqc-tools | cryptodeps (csnp) |
|---|---|---|
| What it is | PQC-readiness toolchain: scanner + CI gate + MCP + conformance harness + active prober | Dependency / import crypto scanner focused on quantum-vulnerable libraries |
| Primary detection approach | 53 detectors emitting 299 rules (verified against `defaultRegistry`): regex-and-heuristic content detectors per language and per config surface, plus a curated 90-entry vulnerable-dependency catalog | Curated 1,100+ package database + per-ecosystem import-pattern matching + language-specific AST parsing + Go-only call-graph reachability |
| Dependency-manifest coverage | 8 ecosystems: npm, PyPI, Cargo, Go modules, Maven, RubyGems, NuGet, Composer (verified in `dependencies.ts`) | Documented import patterns for Go, npm, Python, Java; broader package DB behind them |
| Source-code coverage | 14 language packs (JS/TS, Python, Go, Java/Kotlin/Scala, C#, Rust, Ruby, PHP, Elixir, C/C++, Swift, Objective-C, Dart, Solidity/Move/Cairo) | AST analysis for its documented ecosystems |
| Reachability / call-graph | None. Detectors are pure per-file matchers (`Detector.detect` sees one file at a time). This is a real gap. | Go call-graph reachability determines which crypto is actually invoked. A genuine strength quantakrypto does not have. |
| Infrastructure / config surfaces | Extensive (36 config-scope detectors): TLS, SSH, cloud KMS, JWK/JWKS, JOSE/JWE, Terraform/OpenTofu, CloudFormation, Bicep, Pulumi, Ansible, k8s / cert-manager / Istio / SPIFFE-SPIRE, DNSSEC, DKIM, messaging (Kafka/MQTT), database (pgcrypto/TDE), PKCS#11/HSM, keystores, PEM material, secrets-at-rest, Vault, VPN, code-signing, WebAuthn, XML-DSig/SAML, stateful-HBS | Focused on dependencies and imports; not a documented infrastructure scanner |
| Active / live probing | qProbe probes owned TLS/SSH endpoints for X25519MLKEM768 hybrid key exchange and classical cert posture (ownership-gated) | Static only |
| Risk model | 5-level severity (critical/high/medium/low/info) plus a harvest-now-decrypt-later (HNDL) boolean per finding | VULNERABLE / PARTIAL / SAFE classification with a per-algorithm severity |
| Standards regimes | Selectable profiles: NIST (default), CNSA 2.0, BSI TR-02102, ANSSI, UK NCSC; plus `--tier category-3/category-5` | NIST FIPS 203/204/205 and CNSA 2.0 referenced in its docs |
| Outputs | SARIF 2.1.0, CycloneDX 1.6 CBOM, OpenVEX 0.2.0, JSON, human, ISO 27001 A.8.24 evidence; GitHub Action; MCP tools | Its own report formats |
| Conformance testing | Sieve tests third-party ML-KEM/ML-DSA/SLH-DSA implementations against FIPS 203/204/205 vectors | Not in scope |

## 1.2 Algorithm coverage

Marks reflect what quantakrypto actually detects and classifies, verified in code. "Partial" means the family is detected but only in a narrower context than cryptodeps classifies it, or without a sub-property (for example key size) that cryptodeps grades.

### Asymmetric (cryptodeps: VULNERABLE)

| Algorithm | quantakrypto | Note (verified) |
|---|---|---|
| RSA | Yes | Detected across all 14 source packs, the dependency catalog, PEM, JWK, TLS, and config surfaces; own `AlgorithmFamily`. |
| RSA-2048 / RSA-4096 | Partial | RSA usage is flagged, but severity is not down-graded by modulus size; no per-key-size rule as in cryptodeps. |
| ECDSA | Yes | Dedicated family; source + dependency + PEM/JWK/config detectors. |
| ECDH | Yes | Dedicated family. |
| Ed25519 | Yes | Detected as the `EdDSA` family. |
| Ed448 | Yes | `EdDSA` family (signatures); X448 handled as its own key-agreement family. |
| X25519 | Yes | Dedicated `X25519` family. |
| X448 | Yes (extra) | Dedicated `X448` family. cryptodeps does not list X448 separately. |
| DSA | Yes | Dedicated family. |
| DH / DHE | Yes | Dedicated `DH` family. |
| P-256 / P-384 / P-521 | Yes | Detected via curve names and curve libraries (for example Go `crypto/elliptic`, Rust `p256`/`p384`). |
| secp256k1 | Yes | Source + catalog (ethers, web3, bitcoinjs, `k256`, `secp256k1`) and the ES256K JWT alg. |
| ECIES | Yes (extra) | Dedicated `ECIES` family with its own remediation. Not a cryptodeps row. |

### JWT / JWS family (cryptodeps: VULNERABLE)

| Algorithm | quantakrypto | Note (verified) |
|---|---|---|
| RS256 / RS384 / RS512 | Yes | `RE_JWT_ALG` in `source.ts` matches RS256/384/512; also covered by the catalog (jsonwebtoken, jose, jwa). |
| ES256 / ES384 / ES512 | Yes | `RE_JWT_ALG` matches ES256/384/512 and additionally ES256K. |
| PS256 / PS384 / PS512 | Yes | `RE_JWT_ALG` matches PS256/384/512. |
| EdDSA (JWT alg) | Yes | Recognized in the JWT alg matcher and JOSE/JWK detectors. |

### Symmetric, HMAC, hashes, broken classical

| Algorithm | quantakrypto | Note (verified) |
|---|---|---|
| AES (all modes), ChaCha20/Poly1305 | No | Symmetric ciphers are out of scope by design (Grover only halves symmetric strength; not on the asymmetric migration path). Only surface if named inside a weak TLS cipher string. |
| HMAC HS256/384/512 | No | HMAC/JWS HS* not detected or graded. |
| MD5 | Partial | Flagged only when bound to a signature or X.509 certificate algorithm (Java JCA, .NET signing, X.509 OIDs, OpenSSL signing CLI) via `weak-hash-signature`. Bare `md5()` hashing is deliberately not flagged. |
| SHA-1 | Partial | Same signature/certificate binding as MD5; also surfaced by the DKIM (`rsa-sha1`) and XML-DSig detectors. Not flagged as a bare checksum. |
| SHA-256 / SHA-384 / SHA-512 / SHA-3 / BLAKE2/3 | No | Not inventoried. SHA-256 is deliberately not weighted as quantum-adjacent (see Part 2 for the rationale). |
| DES / 3DES / RC4 | Partial | Detected only inside weak TLS cipher-suite strings (`tls-weak-cipher`). No standalone "in application code" rule. |
| RC2 | No | Not present in any detector. |

### Post-quantum targets (cryptodeps: SAFE)

| Algorithm | quantakrypto | Note (verified) |
|---|---|---|
| ML-KEM (FIPS 203) | Yes | Primary KEM remediation target; recognized as PQC in qProbe; conformance-tested by Sieve. |
| ML-DSA (FIPS 204) | Yes | Primary signature remediation target; conformance-tested by Sieve. |
| SLH-DSA (FIPS 205) | Yes | Named as a signature remediation target; conformance-tested by Sieve. |
| Kyber / Dilithium / SPHINCS+ (pre-standard names) | Yes | Recognized as already-PQC. |
| Stateful HBS: LMS / HSS / XMSS / XMSSMT (SP 800-208) | Yes (extra) | Dedicated `stateful-hbs` detector. Not a cryptodeps row. |

## 1.3 Ecosystem and package coverage

### Parity: dependency ecosystems both cover

| Ecosystem | quantakrypto catalog entries (verified) | Representative overlap with cryptodeps |
|---|---|---|
| npm | 35 | node-forge, elliptic, jsonwebtoken, jose, node-rsa, tweetnacl, ssh2 |
| PyPI | 14 | cryptography, pycryptodome, pyjwt, python-jose, paramiko, pynacl, jwcrypto, tink |
| Go modules | 8 | golang.org/x/crypto, golang-jwt, go-jose, tink-go |
| Maven | 7 | BouncyCastle (bcprov), java-jwt, jjwt, nimbus-jose-jwt, tink |

Total curated vulnerable-dependency catalog: 90 entries (npm 35, PyPI 14, Cargo 9, Composer 9, Go 8, Maven 7, RubyGems 4, NuGet 4).

Every quantum-vulnerable public-key package cryptodeps documents is now in the catalog, including Google Tink (`com.google.crypto.tink` / `tink-crypto/tink-go` / PyPI `tink`), which is listed across all the ecosystems it ships in. See the note below for the one cryptodeps entry we deliberately leave out.

### Extras: what quantakrypto covers that cryptodeps' documented methodology does not

**Additional dependency ecosystems** (beyond cryptodeps' documented Go/npm/Python/Java):

- Cargo / Rust (9 entries: rsa, ring, p256, p384, k256, secp256k1, ed25519-dalek, x25519-dalek, openssl)
- Composer / PHP (9 entries: phpseclib/phpseclib, paragonie/sodium_compat, paragonie/halite, paragonie/paseto, firebase/php-jwt, lcobucci/jwt, web-token/jwt-framework, mdanter/ecc, simplito/elliptic-php)
- NuGet / .NET (4 entries: BouncyCastle.Cryptography, Portable.BouncyCastle, System.IdentityModel.Tokens.Jwt, Microsoft.IdentityModel.Tokens)
- RubyGems / Ruby (4 entries: jwt, net-ssh, rbnacl, ed25519)

**Additional source languages**: C#, Rust, Ruby, PHP, Elixir, C/C++, Swift, Objective-C, Dart, Solidity/Move/Cairo (14 packs total).

**Detection surfaces beyond dependencies and source imports** (36 config-scope detectors):

- Transport: TLS config and cipher suites, reverse-proxy/gRPC TLS, VPN, service mesh (Istio), messaging (Kafka/MQTT), database TLS/TDE (pgcrypto, libpq sslmode)
- Identity and keys: SSH and SSH-CA, JWK/JWKS, JOSE/JWE, PEM material, keystores, PKCS#11/HSM, cloud KMS, WebAuthn/FIDO2, DNSSEC, DKIM, XML-DSig/SAML, SPIFFE/SPIRE
- Infrastructure as code: Terraform/OpenTofu, CloudFormation, Bicep, Pulumi, Ansible, Kubernetes / cert-manager
- Supply chain and signing: code-signing (cosign/GPG/jarsigner/codesign/minisign, Authenticode, APK, RPM, NuGet), secrets-at-rest (SOPS/age, PGP, Sealed Secrets), Vault, OpenPGP
- PQC-adjacent: stateful hash-based signatures (SP 800-208)

**Capabilities cryptodeps' documented methodology does not include**: CBOM generation (CycloneDX 1.6); SARIF 2.1.0, OpenVEX 0.2.0, ISO 27001 A.8.24 evidence; a CI Action that gates only on newly introduced findings; an MCP server for AI coding agents; deterministic codemod remediation with a `verify_fix` gate; multi-regime standards profiles; active live-endpoint probing (qProbe); HNDL risk weighting; conformance testing of PQC implementations (Sieve).

### Where cryptodeps is stronger (honest)

- **Package database is much larger.** cryptodeps ships 1,100+ curated packages; quantakrypto's catalog is 90 asymmetric-focused entries and leans on its source/config detectors to catch usage the catalog does not name.
- **Go call-graph reachability.** cryptodeps can tell whether flagged crypto is actually reached, cutting false positives on dead or unused imports. quantakrypto has no reachability analysis in any language; every detector is a per-file matcher.

Correction to a common assumption: **Nimbus JOSE+JWT is covered.** The Maven artifact `nimbus-jose-jwt` is present in our catalog (verified), as is BouncyCastle (`bcprov-jdk18on`). Neither is a gap.

Deliberate exclusions (symmetric, hash, and password hashing): `crypto-js`, Argon2, scrypt, PBKDF2, and bcrypt are intentionally out of the catalog. `crypto-js` exposes only symmetric ciphers (AES/DES/3DES/RC4), hashes (MD5/SHA), HMAC, and PBKDF2, with no asymmetric public-key surface; the password KDFs are a different weakness class (CWE-916, needs a slow KDF). None of them is quantum-vulnerable public-key cryptography, so none is on the PQC migration path. cryptodeps lists these packages because its catalog inventories all crypto; quantakrypto's catalog is scoped to quantum-vulnerable asymmetric crypto, so the exclusion is deliberate, not a gap. (Broken symmetric ciphers such as DES/3DES/RC4 are still flagged where they appear in TLS cipher-suite configuration, just not as library dependencies.)

## 1.4 Verdict

quantakrypto trades cryptodeps' larger package database and Go reachability for much broader surface coverage (14 source languages, 36 infrastructure/config surfaces, live probing), a richer risk model (HNDL), selectable standards regimes, and standards-grade outputs (CBOM/SARIF/VEX) plus a conformance harness. On the algorithm taxonomy the two agree on everything asymmetric and on the JWT/JWS family; they diverge on symmetric/HMAC/general-hash, which quantakrypto leaves out by design. The two tools are complementary more than competing: cryptodeps answers "which of my dependencies contain reachable quantum-vulnerable crypto," quantakrypto answers "what is my whole system's PQC readiness, across code and infrastructure, and how do I gate and fix it."

---

# Part 2: quantakrypto vs NIST

NIST is not a tool; it is the standards baseline. This comparison reads NIST's prescribed migration methodology against what quantakrypto actually does, then maps our algorithm and standards handling to the specific publications, and states our defensible deviations plainly.

## 2.1 What NIST prescribes, and what quantakrypto does about it

| NIST prescribed step (IR 8547 / NCCoE / CNSA 2.0) | quantakrypto behavior (verified) |
|---|---|
| **Discover and inventory** all uses of quantum-vulnerable public-key crypto across code, systems, and third-party components | qscan produces a per-algorithm inventory across 14 source languages, 8 dependency ecosystems, and 36 infrastructure surfaces; exports a CycloneDX 1.6 CBOM of cryptographic assets |
| **Prioritize** by data sensitivity and exposure window (harvest-now-decrypt-later) | Per-finding HNDL boolean plus 5-level severity; a 0-100 readiness score aggregates the posture |
| **Migrate** to the standardized algorithms (FIPS 203/204/205) on the CNSA 2.0 / IR 8547 timelines | Remediation names ML-KEM / ML-DSA / SLH-DSA targets, hybrids for transition, and the deprecate-after-2030 / disallow-after-2035 timeline; deterministic codemods with a `verify_fix` gate apply the change |
| **Validate** implementations against the FIPS test vectors | Sieve conformance-tests third-party ML-KEM/ML-DSA/SLH-DSA implementations against FIPS 203/204/205 vectors |

quantakrypto positions itself at the discovery, prioritization, gating, and assisted-remediation layers of the NIST migration lifecycle. It informs and drives migration; it does not supply the PQC primitives themselves (those come from a real library such as liboqs).

## 2.2 Algorithm and standards mapping

quantakrypto tracks a dated, cited standards snapshot in `packages/core/src/standards.ts`, re-verified on a quarterly cadence, with a drift test that fails the build if the runtime remediation constants fall out of sync.

| NIST reference | quantakrypto alignment (verified) |
|---|---|
| FIPS 203 (ML-KEM) | Primary KEM remediation target. Category-3 default ML-KEM-768; Category-5 ML-KEM-1024. Hybrid X25519MLKEM768 recommended for transition; SecP384r1MLKEM1024 at the 1024 level. Sieve conformance-tests ML-KEM. |
| FIPS 204 (ML-DSA) | Primary signature remediation target. ML-DSA-65 (Category 3) / ML-DSA-87 (Category 5). Sieve conformance-tests ML-DSA. |
| FIPS 205 (SLH-DSA) | Alternative signature target for long-lived signatures. Sieve conformance-tests SLH-DSA. |
| SP 800-208 (stateful HBS: LMS/HSS, XMSS/XMSSMT) | Dedicated `stateful-hbs` detector; remediation surfaces LMS/XMSS/HSS for firmware/boot signing with an explicit state-management hazard warning. No Sieve stateful-signature battery yet. |
| CNSA 2.0 (Category 5 / NSS) | `--profile cnsa-2.0` and `--tier category-5` are wired into the qscan CLI (verified in `args.ts` / `help.ts`). They mandate ML-KEM-1024 / ML-DSA-87 and correctly refuse to surface X25519MLKEM768 as CNSA-compliant (its ML-KEM-768 component is sub-CNSA), pointing at SecP384r1MLKEM1024 instead. `--mandate cnsa-2.0` additionally gates findings against CNSA 2.0's dated deprecate/disallow clauses (family-level; see §2.4). |
| NIST IR 8547 (transition to PQC) | Deprecate-after-2030 / disallow-after-2035 timeline is encoded in every standards profile and surfaced in the transition note. Now also enforceable: `--mandate nist-ir-8547` gates findings against those dated clauses (warns after the deprecation date, fails after the disallow date; `--lead-months` / `--fail-now` tighten it). Aligns with the discovery-and-inventory phase IR 8547 calls for (per-algorithm inventory, HNDL count, 0-100 readiness score). |
| NCCoE PQC Migration project | Referenced in COMPLIANCE.md as migration-guidance context; quantakrypto is the discovery/inventory and gating layer, composed with a real PQC library for the primitives. |
| Emerging (tracked, not yet targets) | HQC (code-based backup KEM), FN-DSA / Falcon (draft FIPS 206), X-Wing (X25519 + ML-KEM-768 for HPKE) are recorded in the snapshot as items to track. |

## 2.3 Defensible deviations from NIST

- **HNDL weighting.** quantakrypto adds a harvest-now-decrypt-later boolean that NIST does not formalize as a per-finding flag. Confidentiality families (RSA-KEM, ECDH, DH, X25519, X448, ECIES) are marked HNDL-exposed; signature families are not (a signature has no confidentiality to harvest). This is a prioritization overlay, not a contradiction of NIST classification.
- **X25519 and RSA-2048 severity.** X25519 is treated as medium (modern and well-built, but still Shor-broken) rather than uniformly high; RSA is flagged as a family without down-grading by key size. These are risk-prioritization choices, consistent with NIST treating all classical public-key crypto as ultimately in scope for migration.
- **SHA-256 not marked partial.** Some tools grade SHA-256 as at-risk under Grover. quantakrypto does not, on the grounds that Grover only halves preimage strength, a CRQC does not conjure signature-hash collisions, and SHA-256 is not on the asymmetric migration path. Only MD5/SHA-1 in signature/certificate contexts are flagged, framed as quantum-adjacent (same migration window per SP 800-131A Rev 3), not quantum-broken.

## 2.4 Gaps vs NIST

- **CNSA 2.0 enforcement is now a dated, family-level gate — but still not parameter-level.** `--mandate cnsa-2.0` (repeatable; also `nist-ir-8547`) gates findings against the mandate's dated, named clauses: every prohibited classical public-key finding (RSA/ECDH/ECDSA/EdDSA/DH/DSA/ECIES) is reported with its clause, deadline, and citation; it warns once the 2030 deprecation date passes and fails the build only once the 2035 disallow date passes (`--lead-months <n>` fails early inside a lead window, `--fail-now` fails immediately). X25519/X448 are deliberately not flagged by the gate — they are the classical half of the recommended hybrids, so hybrid deployments do not false-positive. What remains missing is the *parameter-level* check: no policy detector flags a sub-CNSA PQC choice already in the code (for example ML-KEM-768 where 1024 is required). Documented honestly in COMPLIANCE.md.
- **No stateful-signature (SP 800-208) conformance battery.** The detector flags stateful HBS usage, but Sieve does not yet test LMS/XMSS state-reuse or exhaustion.

---

# Roadmap

In rough priority order, drawn from the honest gap lists above.

1. **Reachability analysis.** The single clearest capability cryptodeps has and quantakrypto lacks. A call-graph or import-usage reachability pass (starting with Go, then JS/TS and Python) would cut false positives on imported-but-unreached libraries.
2. **Grow the dependency catalog.** Move from 90 curated entries toward cryptodeps-scale coverage. The named public-key packages cryptodeps documents are now all present (Google Tink was the last); the remaining growth is breadth across the long tail of smaller libraries.
3. **CNSA 2.0 parameter-level policy.** *(Partially shipped.)* The dated, family-level half now exists: `--mandate cnsa-2.0` gates classical public-key findings against CNSA 2.0's named clauses and 2030/2035 deadlines (see §2.4), so a CNSA readiness check is no longer report-footer guidance only. Still open is the parameter-level half: a profile that asserts ML-KEM-1024 / ML-DSA-87 and flags sub-CNSA PQC choices (for example ML-KEM-768 where 1024 is required), making the check end-to-end pass/fail on the PQC side too.
4. **Stateful-signature conformance.** Add a Sieve stateful-signature (SP 800-208) category with state-reuse and exhaustion checks.
5. **Optional symmetric/hash breadth.** If parity with cryptodeps' full algorithm table is wanted, add an opt-in mode that inventories symmetric ciphers, HMAC, and general hashes (currently out of scope by the tool's asymmetric-plus-quantum-adjacent framing).
