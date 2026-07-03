/**
 * Snippet-level fix verification: run the detectors over a piece of code (NOT
 * the filesystem) and report any classical crypto that remains. This is the
 * deterministic gate a fix must pass — the same logic the MCP `verify_fix` tool
 * and the remediation pipeline both use, so they can never disagree on what
 * "the finding is gone" means.
 */
import type { Finding } from "./types.js";
import { detectFile, detectors } from "./scan.js";

/**
 * Map a language name (or a bare extension) to a source extension whose
 * detectors we run. Returns null for languages the scanner does not analyze.
 */
export function languageToExtension(language: string): string | null {
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

/** Result of {@link verifyFix}: the findings that remain, and whether the
 * language is one the scanner actually analyzes (so `findings: []` on an
 * unsupported language is NOT a clean verification). */
export interface VerifyResult {
  supported: boolean;
  findings: Finding[];
}

/**
 * Run all detectors over `code`, selecting them by `filename` (extension) or
 * `language`. Pure: no I/O. When neither identifies an analyzable language,
 * `supported` is false and the empty findings list must not be read as "fixed".
 */
export function verifyFix(
  code: string,
  opts: { filename?: string; language?: string },
): VerifyResult {
  let name: string;
  if (opts.filename && opts.filename.trim()) {
    name = opts.filename.trim();
  } else if (opts.language && opts.language.trim()) {
    const ext = languageToExtension(opts.language);
    if (!ext) return { supported: false, findings: [] };
    name = `snippet${ext}`;
  } else {
    return { supported: false, findings: [] };
  }
  const dotExt = name.replace(/^.*(\.[^.]+)$/, "$1");
  const supported = languageToExtension(dotExt) !== null;
  const findings = detectFile(name, code, detectors, { source: true, config: true, deps: true });
  return { supported, findings };
}
