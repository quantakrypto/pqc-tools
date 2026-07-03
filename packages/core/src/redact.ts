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

/** The placeholder that replaces any redacted secret. */
const REDACTED = "«redacted-secret»";

/**
 * Text longer than this is not scanned pattern-by-pattern — we fail CLOSED
 * (redact the whole thing). Bounds worst-case work and sidesteps any engine
 * limit on pathological single-token runs.
 */
const MAX_SECRET_SCAN = 2_000_000;

/**
 * High-signal secret shapes. EVERY quantifier has an explicit upper bound so
 * matching stays linear — no catastrophic backtracking and no regex-engine
 * stack overflow on multi-megabyte runs (both were real DoS vectors with the
 * old unbounded `{120,}` / `[\s\S]*?` patterns). Private-key BLOCKS are handled
 * separately, line-by-line, so a truncated key (missing `-----END-----`) is
 * still caught.
 */
const TOKEN_PATTERNS: readonly RegExp[] = [
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, // AWS access key id
  /\bgh[posru]_[A-Za-z0-9]{20,255}\b/g, // GitHub token
  /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g, // GitHub fine-grained PAT
  /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g, // Slack
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b/g, // OpenAI
  /\b[rs]k_live_[A-Za-z0-9]{20,255}\b/g, // Stripe
  /\bAIza[A-Za-z0-9_-]{35}\b/g, // Google API key
  /\bglpat-[A-Za-z0-9_-]{20,255}\b/g, // GitLab PAT
  /\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{6,4096}\b/g, // JWT
  // Assignment of a secret-looking key (.env / config lines).
  /(?:secret|token|passwd|password|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)["'`]?\s*[:=]\s*["'`]?[^\s"'`,;]{6,4096}/gi,
  /\b[0-9a-fA-F]{40,4096}\b/g, // long hex run (≥20 bytes)
  /[A-Za-z0-9+/]{44,4096}={0,2}/g, // long base64 run (≥32 bytes)
];

/** Redact PEM/OpenSSH/PGP private-key blocks line-by-line (linear; tolerant of
 * a missing END marker — a truncated key is still fully redacted). */
function redactPrivateKeyBlocks(text: string): { text: string; redacted: boolean } {
  const begin =
    /-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
  const end = /-----END /;
  let redacted = false;
  let inKey = false;
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!inKey && begin.test(line)) {
      inKey = true;
      redacted = true;
      out.push(REDACTED);
      continue;
    }
    if (inKey) {
      if (end.test(line)) inKey = false;
      continue; // drop key-body / END lines
    }
    out.push(line);
  }
  return { text: out.join("\n"), redacted };
}

// Single-entry memo: same-file findings re-request the identical file content;
// this makes the whole-file redaction O(n) across all of them instead of O(n·k).
let memoInput: string | undefined;
let memoResult: { text: string; redacted: boolean } | undefined;

/** Replace every secret-looking token/block in `text` with {@link REDACTED}.
 * Fails CLOSED: on oversized input or any error, the whole text is redacted. */
function stripSecrets(text: string): { text: string; redacted: boolean } {
  if (memoInput === text && memoResult) return memoResult;
  let result: { text: string; redacted: boolean };
  if (text.length > MAX_SECRET_SCAN) {
    result = { text: REDACTED, redacted: true };
  } else {
    try {
      const pem = redactPrivateKeyBlocks(text);
      let out = pem.text;
      let redacted = pem.redacted;
      for (const re of TOKEN_PATTERNS) {
        out = out.replace(re, () => {
          redacted = true;
          return REDACTED;
        });
      }
      result = { text: out, redacted };
    } catch {
      result = { text: REDACTED, redacted: true };
    }
  }
  memoInput = text;
  memoResult = result;
  return result;
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
