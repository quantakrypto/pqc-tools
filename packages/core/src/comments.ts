/**
 * Comment-aware false-positive suppression.
 *
 * The detectors are lexical (regex over source text), so a crypto API name
 * written in a COMMENT — `// migrated off createECDH()` — fires a finding just
 * like real code. This module computes the comment spans of a file (respecting
 * string literals, so a `//` inside a string is not a comment) and drops any
 * finding whose match starts inside one.
 *
 * The lexer is deliberately conservative: it only ever ENTERS a comment on a
 * literal line comment, block comment, or `#` in code position (all of which ARE
 * comments), so it never mis-classifies code as a comment and can only reduce
 * false positives, not recall. The one inherent lexical ambiguity — a regex
 * literal that looks like a block-comment open — is rare and guarded by the
 * detection benchmark's recall gate.
 */
import type { Finding } from "./types.js";

type CommentStyle = "c" | "hash";

/** C-style (line + block) comment languages, by extension. */
const C_LIKE: readonly string[] = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".vue",
  ".svelte",
  ".go",
  ".java",
  ".kt",
  ".kts",
  ".cs",
  ".rs",
  ".c",
  ".h",
  ".cc",
  ".cpp",
  ".cxx",
  ".hpp",
  ".hh",
  // PHP and Scala also use C-style `//` + `/* */` comments (PHP additionally uses
  // `#`, handled by the hash lexer running first would miss `//`; C-style covers both
  // since PHP `//` is the common form and `#` lines are rare in modern PHP).
  ".php",
  ".php3",
  ".php4",
  ".php5",
  ".phtml",
  ".scala",
  ".sc",
  ".swift",
];

/** Hash-style (`#`) comment languages, by extension. */
const HASH_LIKE: readonly string[] = [".py", ".pyi", ".pyw", ".rb", ".ex", ".exs"];

/** The comment style for a file path, or null when we don't strip comments for it. */
function commentStyleForFile(file: string): CommentStyle | null {
  const lower = file.toLowerCase();
  if (C_LIKE.some((e) => lower.endsWith(e))) return "c";
  if (HASH_LIKE.some((e) => lower.endsWith(e))) return "hash";
  return null;
}

/**
 * Advance past a string / char literal starting at `content[i]` (a quote char);
 * returns the index just after it. Two correctness rules a naive escape-scan got
 * wrong (both verified as real bugs):
 *   - a `'` char literal must close within a short window (`'\u{10FFFF}'` is ~11
 *     chars); otherwise it is a Rust lifetime (`'a`) or a stray apostrophe, NOT a
 *     literal — return `i + 1` so the scan continues instead of consuming the
 *     rest of the file.
 *   - Go raw strings (backtick, when `rawBacktick`) do NOT process escapes, so a
 *     trailing backslash (`` `C:\` ``) must not swallow the closing delimiter.
 */
function skipQuoted(content: string, i: number, n: number, rawBacktick: boolean): number {
  const quote = content[i];
  if (quote === "'") {
    const limit = Math.min(n, i + 1 + 12);
    let j = i + 1;
    while (j < limit) {
      if (content[j] === "\\") {
        j += 2;
        continue;
      }
      if (content[j] === "'") return j + 1;
      j++;
    }
    return i + 1; // a lifetime / stray apostrophe, not a char literal
  }
  const escapes = !(quote === "`" && rawBacktick);
  let j = i + 1;
  while (j < n) {
    if (escapes && content[j] === "\\") {
      j += 2;
      continue;
    }
    if (content[j] === quote) return j + 1;
    j++;
  }
  return n;
}

/**
 * Compute the comment spans (`[start, end)` offsets) of `content`, skipping over
 * string literals so a comment marker inside a string is not treated as a
 * comment. Spans are returned sorted and non-overlapping. `rawBacktick` (Go)
 * makes backtick strings raw (no escapes).
 */
export function commentSpans(
  content: string,
  style: CommentStyle,
  rawBacktick = false,
): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const n = content.length;
  let i = 0;
  while (i < n) {
    const c = content[i];
    // String / char literal: skip past it (lexically correct for lifetimes + raw strings).
    if (c === '"' || c === "'" || c === "`") {
      i = skipQuoted(content, i, n, rawBacktick);
      continue;
    }
    if (style === "c" && c === "/" && content[i + 1] === "/") {
      const start = i;
      i += 2;
      while (i < n && content[i] !== "\n") i++;
      spans.push([start, i]);
      continue;
    }
    if (style === "c" && c === "/" && content[i + 1] === "*") {
      const start = i;
      i += 2;
      while (i < n && !(content[i] === "*" && content[i + 1] === "/")) i++;
      i = Math.min(n, i + 2);
      spans.push([start, i]);
      continue;
    }
    if (style === "hash" && c === "#") {
      const start = i;
      i++;
      while (i < n && content[i] !== "\n") i++;
      spans.push([start, i]);
      continue;
    }
    i++;
  }
  return spans;
}

/**
 * Compute Python triple-quoted string spans (`"""…"""` / `'''…'''`). These are
 * docstrings / prose in practice, so a crypto *name* mentioned inside one
 * (`:param key_type: eg "ssh-ed25519"`) should not fire a token finding — but a
 * PEM key pasted into one is still real material, so {@link stripCommentFindings}
 * exempts `pem-*` rules. Comments and normal strings are skipped so a `"""`
 * delimiter inside them is not mis-detected.
 */
function pythonDocstringSpans(content: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const n = content.length;
  let i = 0;
  while (i < n) {
    const c = content[i];
    if (c === "#") {
      i++;
      while (i < n && content[i] !== "\n") i++;
      continue;
    }
    if ((c === '"' || c === "'") && content[i + 1] === c && content[i + 2] === c) {
      const start = i;
      i += 3;
      while (i < n && !(content[i] === c && content[i + 1] === c && content[i + 2] === c)) i++;
      i = Math.min(n, i + 3);
      spans.push([start, i]);
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c;
      i++;
      while (i < n) {
        if (content[i] === "\\") {
          i += 2;
          continue;
        }
        if (content[i] === q) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    i++;
  }
  return spans;
}

/** True if `offset` falls inside one of the (sorted, non-overlapping) spans. */
function offsetInSpans(spans: ReadonlyArray<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Line numbers (1-based) suppressed by an inline ignore directive:
 *   - `qscan-ignore-line` on a line suppresses findings on THAT line.
 *   - `qscan-ignore-next-line` on a line suppresses findings on the NEXT line.
 * The directive text is matched anywhere on the line (usually in a comment), so
 * it is language-agnostic. `qscan-ignore-line` is not a substring of
 * `qscan-ignore-next-line`, so the two never collide.
 */
function ignoredLines(content: string): Set<number> {
  const ignored = new Set<number>();
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("qscan-ignore-next-line")) ignored.add(i + 2);
    else if (line.includes("qscan-ignore-line")) ignored.add(i + 1);
  }
  return ignored;
}

/** Drop findings on lines suppressed by an inline `qscan-ignore` directive. */
export function stripIgnoredFindings(findings: Finding[], content: string): Finding[] {
  if (findings.length === 0 || !content.includes("qscan-ignore")) return findings;
  const ignored = ignoredLines(content);
  if (ignored.size === 0) return findings;
  return findings.filter((f) => !ignored.has(f.location.line));
}

/**
 * Drop findings whose match starts inside a comment. No-op when the file's
 * language has no comment style we handle, or when it has no comments.
 */
export function stripCommentFindings(
  findings: Finding[],
  content: string,
  file: string,
): Finding[] {
  if (findings.length === 0) return findings;
  const style = commentStyleForFile(file);
  if (!style) return findings;
  const spans = commentSpans(content, style, /\.go$/i.test(file));
  // Python docstrings suppress prose *token* rules but keep real PEM material.
  const docSpans = style === "hash" ? pythonDocstringSpans(content) : [];
  if (spans.length === 0 && docSpans.length === 0) return findings;

  // 1-based line → start offset, to turn a finding's (line, column) back into an
  // absolute offset (column is 1-based: offset = lineStart + column - 1).
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }

  return findings.filter((f) => {
    const start = lineStarts[f.location.line - 1] ?? 0;
    const offset = start + ((f.location.column ?? 1) - 1);
    if (offsetInSpans(spans, offset)) return false;
    if (docSpans.length > 0 && !f.ruleId.startsWith("pem-") && offsetInSpans(docSpans, offset)) {
      return false;
    }
    return true;
  });
}

/**
 * Compute the string-literal spans (`[start, end)`) of `content`, skipping over
 * comments so a quote inside a comment is not treated as a string. Used to
 * suppress findings from IDENTIFIER-only rules (e.g. a Go `SigningMethodRS256`
 * mentioned inside an error-message string) — the mirror of {@link commentSpans}.
 */
export function stringSpans(
  content: string,
  style: CommentStyle,
  rawBacktick = false,
): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const n = content.length;
  let i = 0;
  while (i < n) {
    const c = content[i];
    if (style === "c" && c === "/" && content[i + 1] === "/") {
      i += 2;
      while (i < n && content[i] !== "\n") i++;
      continue;
    }
    if (style === "c" && c === "/" && content[i + 1] === "*") {
      i += 2;
      while (i < n && !(content[i] === "*" && content[i + 1] === "/")) i++;
      i = Math.min(n, i + 2);
      continue;
    }
    if (style === "hash" && c === "#") {
      i++;
      while (i < n && content[i] !== "\n") i++;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const start = i;
      const end = skipQuoted(content, i, n, rawBacktick);
      // A lone `'` (Rust lifetime, end === start+1) is not a string; skip it.
      if (c !== "'" || end > start + 1) spans.push([start, end]);
      i = end;
      continue;
    }
    i++;
  }
  return spans;
}

/**
 * Drop findings of "code-only" rules (`ruleIds`) whose match starts inside a
 * string literal. Some rules — an identifier-form JWT signing method, a Go
 * `SigningMethodRS256` — are only meaningful as code; when the same token appears
 * inside a string (a test's `t.Error("SigningMethodPS256 …")`) it is prose, not a
 * usage. Rules that legitimately match inside strings (quoted `"RS256"` alg
 * tokens, cipher-suite strings, ssh-key tokens) are NOT in `ruleIds` and pass
 * through untouched.
 */
export function stripStringLiteralFindings(
  findings: Finding[],
  content: string,
  file: string,
  ruleIds: ReadonlySet<string>,
): Finding[] {
  if (findings.length === 0 || !findings.some((f) => ruleIds.has(f.ruleId))) return findings;
  const style = commentStyleForFile(file);
  if (!style) return findings;
  const spans = stringSpans(content, style, /\.go$/i.test(file));
  if (spans.length === 0) return findings;

  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }

  return findings.filter((f) => {
    if (!ruleIds.has(f.ruleId)) return true;
    const start = lineStarts[f.location.line - 1] ?? 0;
    const offset = start + ((f.location.column ?? 1) - 1);
    return !offsetInSpans(spans, offset);
  });
}
