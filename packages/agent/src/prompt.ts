/**
 * Prompt assembly for triage. The system message is a fixed rubric (bumping it
 * bumps {@link TRIAGE_PROMPT_VERSION}, which invalidates cached responses); the
 * user message is built from a {@link RedactedContext}, so nothing unredacted
 * can reach the provider.
 */
import type { RedactedContext } from "@quantakrypto/core";
import type { JsonSchema } from "./validate.js";

/** Bump when the rubric/schema changes so the response cache invalidates. */
export const TRIAGE_PROMPT_VERSION = "triage-1";

export const TRIAGE_SYSTEM =
  "You are a post-quantum cryptography triage assistant. You are given ONE finding " +
  "of classical (quantum-vulnerable) cryptography detected in a codebase, with " +
  "limited, possibly-redacted context. Assess its REAL-WORLD exposure and urgency. " +
  "exposureScore (0-100): how exploitable/exposed this usage is — a long-lived " +
  "confidentiality key over the network (harvest-now-decrypt-later) scores high; a " +
  "short-lived local signature scores lower. priority: 'now' for HNDL/high-exposure, " +
  "'soon' for important-but-not-urgent, 'later' for low-exposure. You NEVER decide " +
  "whether the finding is valid and you NEVER suppress it — you only rank exposure. " +
  "Base your rationale only on the given context; do not invent facts.";

/** Response schema for a single triage verdict. */
export const TRIAGE_SCHEMA: JsonSchema = {
  type: "object",
  required: ["exposureScore", "priority", "rationale"],
  properties: {
    exposureScore: { type: "number", minimum: 0, maximum: 100 },
    priority: { enum: ["now", "soon", "later"] },
    rationale: { type: "string" },
  },
};

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
