/**
 * Shared helpers for the regex-based source detectors: turning a string offset
 * into a 1-based line/column, extracting a trimmed single-line snippet, and a
 * small factory for building Finding objects with consistent remediation text.
 */
import type {
  AlgorithmFamily,
  Confidence,
  Finding,
  FindingCategory,
  RuleMeta,
  Severity,
} from "./types.js";
import { remediationText } from "./remediation.js";

/** A 1-based line/column position derived from a character offset. */
interface LineCol {
  line: number;
  column: number;
}

/**
 * Memoized line-start offsets for the CURRENT content string. A scan processes
 * all of one file's findings consecutively against the same `content` reference,
 * so a single-entry cache turns the previously O(offset)-per-finding line/column
 * math into O(log n) — the whole file is O(n log n) instead of O(n²). Without
 * this, a large file with many findings scaled quadratically (a real perf cliff,
 * caught by the ReDoS/time-budget test).
 */
let cachedContent: string | null = null;
let cachedLineStarts: number[] = [];
function lineStartsFor(content: string): number[] {
  if (content === cachedContent) return cachedLineStarts;
  const starts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  cachedContent = content;
  cachedLineStarts = starts;
  return starts;
}

/** Index of the line containing `offset` (0-based into the line-starts array). */
function lineIndexFor(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= offset) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

/**
 * Convert a 0-based character offset within `content` into a 1-based
 * line/column. Newlines are LF; CR is treated as an ordinary character, so on
 * CRLF files the column includes the trailing CR offset harmlessly.
 */
function offsetToLineCol(content: string, offset: number): LineCol {
  const starts = lineStartsFor(content);
  const idx = lineIndexFor(starts, offset);
  return { line: idx + 1, column: offset - starts[idx] + 1 };
}

/** Extract the (trimmed) single source line containing `offset`. */
function lineAt(content: string, offset: number): string {
  const starts = lineStartsFor(content);
  const idx = lineIndexFor(starts, offset);
  const start = starts[idx];
  const nextStart = idx + 1 < starts.length ? starts[idx + 1] : content.length + 1;
  // nextStart points just past the '\n'; the line content ends before it.
  const end = Math.min(nextStart - 1, content.length);
  return content.slice(start, end).replace(/\r$/, "").trim();
}

/** Inputs for {@link makeFinding}. */
interface FindingSpec {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  algorithm?: AlgorithmFamily;
  hndl: boolean;
  message: string;
  /** Override the auto-derived remediation text. */
  remediation?: string;
  /** Associated CWE id (e.g. "CWE-327"). */
  cwe?: string;
  /** Marks the matched snippet as the sensitive value itself (key material). */
  sensitive?: boolean;
  /** The matched source text and its start offset within `content`. */
  file: string;
  content: string;
  index: number;
  /** Length of the match, used to compute endLine for multi-line matches. */
  matchLength?: number;
}

/**
 * Build a {@link Finding} with location info derived from a match offset. When
 * no explicit remediation is given but an algorithm is, the canonical
 * remediation text for that family is used.
 */
export function makeFinding(spec: FindingSpec): Finding {
  const { line, column } = offsetToLineCol(spec.content, spec.index);
  const snippet = lineAt(spec.content, spec.index);

  const remediation =
    spec.remediation ?? (spec.algorithm ? remediationText(spec.algorithm) : undefined);

  const location: Finding["location"] = {
    file: spec.file,
    line,
    column,
    snippet: snippet.length > 200 ? `${snippet.slice(0, 197)}...` : snippet,
  };

  if (spec.matchLength && spec.matchLength > 0) {
    const matched = spec.content.slice(spec.index, spec.index + spec.matchLength);
    const extraLines = (matched.match(/\n/g) ?? []).length;
    if (extraLines > 0) location.endLine = line + extraLines;
  }

  const finding: Finding = {
    ruleId: spec.ruleId,
    title: spec.title,
    category: spec.category,
    severity: spec.severity,
    confidence: spec.confidence,
    hndl: spec.hndl,
    message: spec.message,
    location,
  };
  if (spec.algorithm) finding.algorithm = spec.algorithm;
  if (remediation) finding.remediation = remediation;
  if (spec.cwe) finding.cwe = spec.cwe;
  if (spec.sensitive) finding.sensitive = true;
  return finding;
}

/** Where a match occurred, plus optional per-finding field overrides. */
interface RuleMatch {
  file: string;
  content: string;
  /** Match start offset within `content`. */
  index: number;
  /** Length of the match (used to compute endLine for multi-line matches). */
  matchLength?: number;
}

/**
 * Fields of a {@link RuleMeta} a detector may refine at match time. Multi-variant
 * rules (e.g. key generation across algorithm families) override these; fixed
 * rules pass none and inherit the catalog metadata verbatim.
 */
type RuleOverrides = Partial<
  Pick<
    RuleMeta,
    "title" | "category" | "severity" | "confidence" | "algorithm" | "hndl" | "message" | "cwe"
  >
> & { remediation?: string };

/**
 * Build a {@link Finding} from a rule's catalog metadata plus a match location,
 * applying any per-finding overrides. This is the single construction path for
 * detector findings: the invariant fields (title/severity/category/…) live once
 * in the {@link RuleMeta} declaration, so they can't drift from what the SARIF
 * catalog and the MCP resolver report.
 */
export function findingFromRule(rule: RuleMeta, at: RuleMatch, overrides?: RuleOverrides): Finding {
  return makeFinding({
    ruleId: rule.id,
    title: overrides?.title ?? rule.title,
    category: overrides?.category ?? rule.category,
    severity: overrides?.severity ?? rule.severity,
    confidence: overrides?.confidence ?? rule.confidence,
    algorithm: overrides?.algorithm ?? rule.algorithm,
    hndl: overrides?.hndl ?? rule.hndl,
    cwe: overrides?.cwe ?? rule.cwe,
    remediation: overrides?.remediation ?? rule.remediation,
    sensitive: rule.sensitive,
    message: overrides?.message ?? rule.message,
    file: at.file,
    content: at.content,
    index: at.index,
    matchLength: at.matchLength,
  });
}

/** True if `filePath` has one of the given (lower-case, dotted) extensions. */
export function hasExtension(filePath: string, exts: readonly string[]): boolean {
  const lower = filePath.toLowerCase();
  return exts.some((e) => lower.endsWith(e));
}

/**
 * JavaScript / TypeScript source extensions handled by the source detectors.
 * `.vue` / `.svelte` single-file components embed a `<script>` block, so the
 * lexical detectors catch crypto usage inside them.
 */
export const JS_TS_EXTENSIONS: readonly string[] = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".vue",
  ".svelte",
];

/** Python source extensions handled by the Python detector. */
export const PYTHON_EXTENSIONS: readonly string[] = [".py", ".pyi", ".pyw"];

/** Go source extensions handled by the Go detector. */
export const GO_EXTENSIONS: readonly string[] = [".go"];

/** Java / Kotlin source extensions handled by the JCA detector. */
// The JVM detector also covers Kotlin (`.kt`/`.kts`) and Scala (`.scala`/`.sc`):
// all three compile against the same JCA (`KeyPairGenerator`, `Signature`,
// `KeyAgreement`) and BouncyCastle APIs the Java rules match.
export const JAVA_EXTENSIONS: readonly string[] = [".java", ".kt", ".kts", ".scala", ".sc"];

/** C# source extensions handled by the .NET detector. */
export const CSHARP_EXTENSIONS: readonly string[] = [".cs"];

/** Rust source extensions handled by the Rust detector. */
export const RUST_EXTENSIONS: readonly string[] = [".rs"];

/** Ruby source extensions handled by the Ruby detector. */
export const RUBY_EXTENSIONS: readonly string[] = [".rb"];

/** Elixir source extensions handled by the Elixir detector. */
export const ELIXIR_EXTENSIONS: readonly string[] = [".ex", ".exs"];

/** PHP source extensions handled by the PHP detector. */
export const PHP_EXTENSIONS: readonly string[] = [".php", ".phtml", ".php3", ".php4", ".php5"];

/** C / C++ source extensions handled by the OpenSSL detector. */
export const C_EXTENSIONS: readonly string[] = [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"];

/**
 * Prose/documentation extensions. The language-agnostic *token* detectors (SSH
 * public keys, TLS cipher suites, certificate signature algorithms) must not run
 * on these: a changelog or README that mentions `ssh-rsa` or `ECDHE-RSA` in a
 * sentence is prose, not crypto config. (PEM/`-----BEGIN` material stays in scope
 * everywhere, so a key pasted into docs is still caught.)
 */
export const DOC_EXTENSIONS: readonly string[] = [
  ".md",
  ".markdown",
  ".mdown",
  ".mkd",
  ".rst",
  ".adoc",
  ".asciidoc",
  ".textile",
  ".org",
  ".rdoc",
  ".pod",
];

/**
 * File-literal surfaces where a JWT/JOSE algorithm string (`"RS256"`, `"ES256"`)
 * is the same evidence regardless of language. Used to un-gate the JWT detector
 * from JS-only. Covers the languages whose JWT libraries pass the alg as a quoted
 * token — JS/TS, Python, Go (`jwt.GetSigningMethod("RS256")`) and Ruby
 * (`JWT.encode(payload, key, 'RS256')`) — so the regex stays precise (`HS*` HMAC
 * tokens are excluded by `RE_JWT_ALG`). Java/C# pass the alg as an *identifier*
 * (`SignatureAlgorithm.RS256`), which needs its own pattern — a later pass.
 * YAML/JSON config carry unquoted tokens and higher FP risk, so they wait too.
 */
export const JWT_HOST_EXTENSIONS: readonly string[] = [
  ...JS_TS_EXTENSIONS,
  ...PYTHON_EXTENSIONS,
  ...GO_EXTENSIONS,
  ...RUBY_EXTENSIONS,
];

/**
 * Extensions the scanner can actually analyze for inline crypto usage today
 * (the language-specific source detectors). A scan that walked files but found
 * none of these has NOT meaningfully assessed the codebase — reporters surface
 * that ({@link CryptoInventory}/coverage), so a bare 100/100 can't masquerade as
 * "safe" on, say, a Go or Rust repo. PEM / SSH / dependency detectors run on any
 * file and are intentionally excluded here.
 */
export const ANALYZABLE_SOURCE_EXTENSIONS: readonly string[] = [
  ...JS_TS_EXTENSIONS,
  ...PYTHON_EXTENSIONS,
  ...GO_EXTENSIONS,
  ...JAVA_EXTENSIONS,
  ...CSHARP_EXTENSIONS,
  ...RUST_EXTENSIONS,
  ...RUBY_EXTENSIONS,
  ...PHP_EXTENSIONS,
  ...ELIXIR_EXTENSIONS,
  ...C_EXTENSIONS,
];

/**
 * Human label for the source languages the scanner can analyze for inline
 * crypto, shown in coverage output. Kept next to {@link
 * ANALYZABLE_SOURCE_EXTENSIONS} so a new language pack updates one place.
 */
export const ANALYZABLE_LANGUAGES_LABEL =
  "JS/TS, Python, Go, Java/Kotlin/Scala, C#, Rust, Ruby, PHP, Elixir, C/C++";

/** True when a path is in a source language the scanner can analyze for crypto. */
export function isAnalyzableSource(filePath: string): boolean {
  return hasExtension(filePath, ANALYZABLE_SOURCE_EXTENSIONS);
}

/**
 * Given a SORTED ascending array of call offsets, return true when `idx` is at or
 * after some call offset `c` with `idx - c < window`. Deliberately ONE-SIDED
 * (forward only): the WebCrypto algorithm name follows the `subtle.*(` call it
 * belongs to, and reaching backward would wrongly attribute an UNRELATED earlier
 * call's argument (e.g. a Node `generateKeyPairSync('rsa-pss', …)` sitting a few
 * lines above a subtle call) to the wrong API. Runs in O(log n) by binary-searching
 * the largest call offset ≤ `idx` and checking the gap.
 */
export function nearSortedCall(
  sortedCalls: readonly number[],
  idx: number,
  window: number,
): boolean {
  // Find the rightmost element <= idx.
  let lo = 0;
  let hi = sortedCalls.length - 1;
  let best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (sortedCalls[mid] <= idx) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (best < 0) return false;
  return idx - sortedCalls[best] < window;
}

/**
 * Run a global regex over `content`, invoking `onMatch` for each hit. Resets
 * lastIndex and guards against zero-width matches (which would loop forever).
 */
export function eachMatch(
  re: RegExp,
  content: string,
  onMatch: (match: RegExpExecArray) => void,
): void {
  const g = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = g.exec(content)) !== null) {
    onMatch(m);
    if (m.index === g.lastIndex) g.lastIndex++; // avoid infinite loop on empty match
  }
}

/**
 * Return the innermost `{ … }` object that contains `index`, as a substring — so a
 * per-match check (e.g. a JWK's own `use`/`alg`, or whether an `alg` sits inside a
 * JWK) analyses ONLY that object and can't be contaminated by a neighbouring object
 * in a packed array. The scan is STRING-AWARE (braces and quotes inside JSON string
 * values, honouring `\"`, are ignored), so a value like `"a}b{c"` can't mis-scope the
 * object. Bounded by `maxSpan` each way so a pathological input can't blow up; falls
 * back to a bounded ±window when no enclosing object is found in range.
 */
export function enclosingObject(content: string, index: number, maxSpan = 4000): string {
  const lo = Math.max(0, index - maxSpan);
  const hi = Math.min(content.length, index + maxSpan);
  const stack: number[] = []; // positions of currently-open `{`
  let inStr = false;
  let esc = false;
  let enclosingOpen = -1; // innermost `{` open at `index`
  for (let i = lo; i < hi; i++) {
    const c = content[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
    } else if (c === "{") {
      stack.push(i);
    } else if (c === "}") {
      const open = stack.pop();
      if (open !== undefined && open === enclosingOpen) {
        return content.slice(enclosingOpen, i + 1); // closed the enclosing object
      }
    }
    if (i === index && enclosingOpen < 0 && stack.length > 0) {
      enclosingOpen = stack[stack.length - 1];
    }
  }
  // No complete enclosing object in range: if we found an (unclosed) enclosing open
  // brace, return from it to hi. Otherwise the token is not inside any object (top-level
  // token / brace-less config like YAML) — return a bounded ±250 window, NOT the full
  // forward span, so a `"kty"` far AFTER the token can't pull an unrelated JWK into
  // scope and over-suppress a legitimate standalone finding.
  if (enclosingOpen >= 0) return content.slice(enclosingOpen, hi);
  return content.slice(Math.max(0, index - 250), Math.min(content.length, index + 250));
}

/**
 * Blank out FULL-LINE comments so a commented-out directive isn't reported as an
 * active setting. A line counts as a comment when its first non-whitespace characters
 * match one of `markers` (e.g. `#`, `//`, `;`, `!`). Each such line's characters are
 * replaced with spaces of the SAME length (newlines preserved), so every byte offset
 * is unchanged — the finding line/column/snippet for the non-comment lines that remain
 * stay exactly correct. Inline trailing comments are intentionally left alone (the
 * directive before them is still active, so it should still be flagged).
 *
 * Config detectors run their rules over the masked content; matches can then only land
 * on live config, not on commented examples (mosquitto.conf, CI YAML, ipsec.conf, and
 * HCL all conventionally ship large blocks of commented-out directives).
 */
export function maskCommentLines(content: string, markers: readonly string[]): string {
  if (markers.length === 0) return content;
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lead = line.trimStart();
    if (lead !== "" && markers.some((mk) => lead.startsWith(mk))) {
      lines[i] = " ".repeat(line.length);
    }
  }
  return lines.join("\n");
}
