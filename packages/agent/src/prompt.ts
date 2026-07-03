/**
 * Prompt assembly for triage. The system message is a fixed rubric (bumping it
 * bumps {@link TRIAGE_PROMPT_VERSION}, which invalidates cached responses); the
 * user message is built from a {@link RedactedContext}, so nothing unredacted
 * can reach the provider.
 */
import type { RedactedContext } from "@quantakrypto/core";
import { TRIAGE_RUBRIC, TRIAGE_VERDICT_SCHEMA } from "@quantakrypto/core";
import type { JsonSchema } from "./validate.js";

/** Bump when the rubric/schema changes so the response cache invalidates. */
export const TRIAGE_PROMPT_VERSION = "triage-1";

/** The system rubric — shared with the MCP plane via `@quantakrypto/core`. */
export const TRIAGE_SYSTEM = TRIAGE_RUBRIC;

/** Response schema for a single triage verdict (shared with core). */
export const TRIAGE_SCHEMA: JsonSchema = TRIAGE_VERDICT_SCHEMA;

/** Render the per-finding user prompt from its redacted context. */
export function triageUserPrompt(ctx: RedactedContext): string {
  const m = ctx.meta;
  const lines = [
    `Finding: ${m.ruleId}`,
    `Severity: ${m.severity}`,
    `Algorithm: ${m.algorithm ?? "unknown"}`,
    `Harvest-now-decrypt-later: ${m.hndl ? "yes" : "no"}`,
    `Location: ${m.file}:${m.line}`,
    `Detector message: ${m.message}`,
  ];
  if (ctx.code) {
    lines.push(
      "",
      `Context (level=${ctx.level}${ctx.redactedSecret ? ", secrets redacted" : ""}):`,
      ctx.code,
    );
  } else {
    lines.push("", "No source context was shared for this finding.");
  }
  return lines.join("\n");
}
