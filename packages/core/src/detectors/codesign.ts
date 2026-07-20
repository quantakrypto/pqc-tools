/**
 * Config detector: classical **code-signing CLI** invocations in build scripts —
 * the tools that sign long-lived, distributable artifacts (Windows installers,
 * Android APKs, RPM/deb packages, NuGet packages, macOS apps) with a classical
 * RSA/ECDSA signing identity.
 *
 * Why this is quantum-migration debt: a code signature produced today keeps
 * verifying against its classical public key for the life of the artifact
 * (installers and packages linger on mirrors and machines for years). Once a
 * cryptographically-relevant quantum computer (CRQC) can recover the signing
 * key from that public key, every such signature becomes *forgeable* — an
 * attacker can mint a validly-signed trojaned installer. This is the
 * signature-side analogue of harvest-now-decrypt-later: there is no
 * confidentiality to harvest, so findings are `category:"signature"`,
 * `hndl:false`, but they are real debt to inventory now.
 *
 * How this differs from the two neighbouring signing detectors — kept
 * deliberately non-overlapping:
 *
 *  - `cicd.ts` (cicdDetector) is gated to CI *pipeline* files
 *    (`.github/workflows/*.yml`, `.gitlab-ci.yml`, Jenkinsfile, azure-pipelines,
 *    CircleCI) and matches the release-automation signers there
 *    (cosign / gpg / jarsigner / codesign / minisign). It intentionally does
 *    NOT fire on a plain `build.sh`, `build.ps1`, `build.gradle`, or Makefile.
 *  - `supply-chain.ts` (supplyChainDetector) covers container/artifact signing
 *    (Docker Content Trust, CNCF Notation, in-toto) in CI files, Dockerfiles,
 *    and shell scripts.
 *
 * This detector fills the gap: the *native platform* code-signing CLIs
 * (`signtool`, `osslsigncode`, `Set-AuthenticodeSignature`, `apksigner`, Gradle
 * `signingConfigs`, `rpmsign`/`dpkg-sig`, `nuget sign`, `notarytool`) as they
 * appear in a build script of ANY extension — because that is where developers
 * actually run them. It applies everywhere except documentation
 * (a README showing `signtool sign` is prose, not a build step). One token
 * (`codesign`) can also be matched by `cicd.ts` when it appears inside a CI
 * file; a duplicate finding across the two detectors is acceptable, and keeping
 * `codesign` here means a `codesign --sign` in a hand-written `build.sh` — which
 * `cicd.ts`'s CI-file gate deliberately skips — is still caught.
 *
 * Precision comes from two gates, mirroring `dnssec.ts`: a cheap file-level
 * fast-reject (bail unless some signing-command marker is present) and
 * comment-line masking (`#` for shell/PowerShell/Makefile/Gradle, `//` for
 * Gradle/Groovy) so a commented-out signing step never fires. The rule regexes
 * themselves key on distinctive `<tool> sign` command shapes, so the residual
 * false-positive risk is low and confidence is `high`.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskCommentLines,
  DOC_EXTENSIONS,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/** Shared one-line explanation, parameterised by the signing tool named in the finding. */
function signMessage(tool: string): string {
  return (
    `${tool} signs an artifact with a classical RSA/ECDSA key; the signature is ` +
    `forgeable once a CRQC can recover the signing key — inventory the signing ` +
    `identity and plan PQC migration.`
  );
}

/** Shared remediation: no PQC code-signing format is broadly standardized yet. */
const REMEDIATION =
  "No PQC code-signing format is broadly standardized yet; track platform roadmaps " +
  "(e.g. Sigstore/PQC, Authenticode); keep signing-key rotation ready.";

/**
 * Distinctive markers for the file-level fast-reject. Kept as a SUPERSET of the
 * rule tokens below so the cheap gate can never exclude a file one of the rules
 * would match: it includes every rule's trigger token (`--addsign`, `%_gpg_name`,
 * `codesign`, `nuget`, …), not only the headline command names.
 */
const MARKER_RE =
  /signtool|osslsigncode|AuthenticodeSignature|apksigner|signingConfigs|rpmsign|--addsign|%_gpg_name|dpkg-sig|nuget|notarytool|codesign/;

interface CsRule {
  re: RegExp;
  meta: RuleMeta;
}

const CS_RULES: CsRule[] = [
  {
    // Windows Authenticode: `signtool sign …` (optionally `signtool.exe`),
    // `osslsigncode sign …`, or the PowerShell `Set-AuthenticodeSignature` cmdlet.
    re: /\bsigntool(?:\.exe)?\s+sign\b|\bosslsigncode\s+sign\b|\bSet-AuthenticodeSignature\b/g,
    meta: {
      id: "codesign-authenticode",
      title: "Windows Authenticode code signing (RSA)",
      description: "signtool / osslsigncode / Set-AuthenticodeSignature Authenticode signing",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: signMessage(
        "Windows Authenticode (signtool/osslsigncode/Set-AuthenticodeSignature)",
      ),
      remediation: REMEDIATION,
    },
  },
  {
    // Android: `apksigner sign …` (covers `--ks` / `--ks-key-alias` forms), or a
    // Gradle `signingConfigs { … }` block (which carries `storeFile`/`keyAlias`).
    re: /\bapksigner\s+sign\b|\bsigningConfigs\s*\{/g,
    meta: {
      id: "codesign-apk",
      title: "Android APK signing (RSA)",
      description: "apksigner / Gradle signingConfigs APK signing",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: signMessage("Android APK signing (apksigner/Gradle signingConfigs)"),
      remediation: REMEDIATION,
    },
  },
  {
    // RPM/deb: `rpmsign --addsign`, `rpm --addsign`, the `%_gpg_name` rpmmacro, or
    // `dpkg-sig --sign`. All ultimately GPG (classically RSA) signatures.
    re: /\brpmsign\s+--addsign\b|\brpm\s+--addsign\b|%_gpg_name\b|\bdpkg-sig\s+--sign\b/g,
    meta: {
      id: "codesign-rpm",
      title: "RPM/deb package signing (RSA)",
      description: "rpmsign / rpm --addsign / %_gpg_name / dpkg-sig package signing",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: signMessage("RPM/deb package signing (rpmsign/rpm --addsign/dpkg-sig, GPG)"),
      remediation: REMEDIATION,
    },
  },
  {
    // NuGet: `nuget sign …` — also matches `dotnet nuget sign …` (the `nuget sign`
    // token is a substring of it), typically paired with `--certificate-*` flags.
    re: /\bnuget\s+sign\b/g,
    meta: {
      id: "codesign-nuget",
      title: "NuGet package signing (RSA)",
      description: "nuget sign / dotnet nuget sign package signing",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: signMessage("NuGet package signing (nuget sign/dotnet nuget sign)"),
      remediation: REMEDIATION,
    },
  },
  {
    // Apple: `xcrun notarytool submit …`, or `codesign --sign` / `codesign -s`.
    // Allow intervening flags before `--sign`/`-s`, bounded to the codesign
    // invocation so it can't latch onto a later command's flag across `&&`/`|`/`;`
    // (same shape as cicd.ts's codesign rule). Algorithm is "unknown": an Apple
    // signing identity may be RSA or ECDSA.
    re: /\bnotarytool\s+submit\b|\bcodesign\b[^\n&|;]{0,120}?\s(?:-s\b|--sign\b)/g,
    meta: {
      id: "codesign-apple",
      title: "Apple code signing / notarization",
      description: "codesign --sign / xcrun notarytool submit macOS signing",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: signMessage("Apple code signing (codesign/notarytool)"),
      remediation: REMEDIATION,
    },
  },
];

/** Detects classical code-signing CLI invocations in build scripts. */
export const codesignDetector: Detector = {
  id: "codesign-signing",
  description:
    "Classical code-signing CLIs in build scripts (Authenticode, APK, RPM, NuGet, Apple)",
  scope: "config",
  language: "any",
  rules: CS_RULES.map((r) => r.meta),
  // Applies to build scripts of any extension EXCEPT documentation: a README that
  // shows `signtool sign` in an example is prose, not a build step.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Cheap fast-reject: bail unless some signing-command marker is present, so
    // the per-rule regexes never run on the overwhelming majority of files.
    if (!MARKER_RE.test(content)) return [];

    // Mask whole comment lines so a commented-out signing step can't fire.
    // `#` covers shell / PowerShell / Makefile / Gradle(Groovy & Kotlin DSL);
    // `//` covers Gradle/Groovy. Offsets are preserved so finding locations stay
    // exact (see maskCommentLines).
    const scan = maskCommentLines(content, ["#", "//"]);
    const findings: Finding[] = [];
    for (const rule of CS_RULES) {
      eachMatch(rule.re, scan, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
