/**
 * Context redactor: turn a finding + its file into the payload the LLM sees,
 * bounded to a chosen {@link ContextLevel} and with secrets ALWAYS stripped.
 *
 * This is a hard privacy boundary and lives in `@quantakrypto/core` (offline) so
 * the deterministic MCP plane redacts identically to the networked CLI. A
 * `sensitive` finding (the match IS key material) never emits code at any level.
 */
import type { Finding } from "./types.js";
import type { ContextLevel, RedactedContext } from "./agent-types.js";

/** Lines of context on each side of the match at `snippet` level. */
const SNIPPET_RADIUS = 8;

/**
 * PEM blocks and long unbroken base64 runs (≥120 chars) are treated as secret
 * material and masked, even inside otherwise-shareable code.
 */
const SECRET_RE =
  /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----|[A-Za-z0-9+/]{120,}={0,2}/g;

function stripSecrets(text: string): { text: string; redacted: boolean } {
  let redacted = false;
  const out = text.replace(SECRET_RE, () => {
    redacted = true;
    return "«redacted-secret»";
  });
  return { text: out, redacted };
}

/** Best-effort enclosing brace/colon block around a 0-based line index. */
function enclosingBlock(lines: string[], idx: number): string {
  let start = idx;
  while (start > 0 && !/[{:]\s*$/.test(lines[start - 1] ?? "")) start--;
  let end = idx;
  let depth = 0;
  for (let i = start; i < lines.length; i++) {
    const line = lines[i] ?? "";
    depth += (line.match(/{/g) ?? []).length - (line.match(/}/g) ?? []).length;
    end = i;
    if (i > idx && depth <= 0) break;
  }
  return lines.slice(start, end + 1).join("\n");
}

/**
 * Build the redacted context for `finding` at `level`. `fileContent` is the full
 * text of the file the finding lives in (unused at `metadata` level). Secrets
 * are always removed; a `sensitive` finding yields `code: null`.
 */
export function buildContext(
  finding: Finding,
  level: ContextLevel,
  fileContent: string,
): RedactedContext {
  const meta = {
    ruleId: finding.ruleId,
    algorithm: finding.algorithm,
    severity: finding.severity,
    hndl: finding.hndl,
    file: finding.location.file,
    line: finding.location.line,
    message: finding.message,
  };
  // Sensitive findings never emit code, at any level.
  if (finding.sensitive) return { level, meta, code: null, redactedSecret: true };
  if (level === "metadata") return { level, meta, code: null, redactedSecret: false };

  const lines = fileContent.split("\n");
  let code: string;
  if (level === "file") {
    code = fileContent;
  } else if (level === "function") {
    code = enclosingBlock(lines, finding.location.line - 1);
  } else {
    const i = finding.location.line - 1;
    code = lines.slice(Math.max(0, i - SNIPPET_RADIUS), i + SNIPPET_RADIUS + 1).join("\n");
  }
  const { text, redacted } = stripSecrets(code);
  return { level, meta, code: text, redactedSecret: redacted };
}

/** Render the exact payload text a `--dry-run` preflight would send. */
export function renderPreflight(contexts: RedactedContext[]): string {
  return contexts
    .map((c) => {
      const flags = `level=${c.level}${c.redactedSecret ? ", secret-redacted" : ""}`;
      const head = `[${c.meta.severity}] ${c.meta.ruleId} ${c.meta.file}:${c.meta.line} (${flags})`;
      return c.code ? `${head}\n${c.code}` : head;
    })
    .join("\n\n---\n\n");
}
