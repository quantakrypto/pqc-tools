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

export type CommentStyle = "c" | "hash";

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
];

/** Hash-style (`#`) comment languages, by extension. */
const HASH_LIKE: readonly string[] = [".py", ".pyi", ".pyw", ".rb"];

/** The comment style for a file path, or null when we don't strip comments for it. */
export function commentStyleForFile(file: string): CommentStyle | null {
  const lower = file.toLowerCase();
  if (C_LIKE.some((e) => lower.endsWith(e))) return "c";
  if (HASH_LIKE.some((e) => lower.endsWith(e))) return "hash";
  return null;
}

/**
 * Compute the comment spans (`[start, end)` offsets) of `content`, skipping over
 * string literals so a comment marker inside a string is not treated as a
 * comment. Spans are returned sorted and non-overlapping.
 */
export function commentSpans(content: string, style: CommentStyle): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const n = content.length;
  let i = 0;
  while (i < n) {
    const c = content[i];
    // String / template literal: skip to the matching unescaped delimiter.
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < n) {
        if (content[i] === "\\") {
          i += 2;
          continue;
        }
        if (content[i] === quote) {
          i++;
          break;
        }
        i++;
      }
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

/** True if `offset` falls inside one of the (sorted, non-overlapping) spans. */
export function offsetInSpans(spans: ReadonlyArray<[number, number]>, offset: number): boolean {
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
export function ignoredLines(content: string): Set<number> {
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
  const spans = commentSpans(content, style);
  if (spans.length === 0) return findings;

  // 1-based line → start offset, to turn a finding's (line, column) back into an
  // absolute offset (column is 1-based: offset = lineStart + column - 1).
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }

  return findings.filter((f) => {
    const start = lineStarts[f.location.line - 1] ?? 0;
    const offset = start + ((f.location.column ?? 1) - 1);
    return !offsetInSpans(spans, offset);
  });
}
