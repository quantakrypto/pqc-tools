/**
 * LLM fix orchestrator. For a finding no deterministic codemod covers, ask the
 * model for the FULL corrected file, and return it as a {@link FixProposal} for
 * the deterministic pipeline to gate (patch-policy + verify_fix). The model only
 * ever proposes; nothing here trusts its output.
 *
 * Safety: files whose context has secrets stripped are SKIPPED entirely — we
 * would otherwise ask the model to rewrite redacted content and could write the
 * `«redacted-secret»` placeholder back over a real key. Sensitive findings
 * (the match IS key material) are likewise never sent.
 */
import type { Finding, FixProposal } from "@quantakrypto/core";
import { buildContext, REMEDIATE_RUBRIC, FIX_REQUEST_SCHEMA } from "@quantakrypto/core";

import type { LlmClient } from "./client.js";
import type { JsonSchema } from "./validate.js";

/** Bump when the fix rubric/schema changes. */
export const FIX_PROMPT_VERSION = "fix-1";

/** Fix rubric + schema — shared with the MCP plane via `@quantakrypto/core`. */
const FIX_SYSTEM = REMEDIATE_RUBRIC;
const FIX_SCHEMA: JsonSchema = FIX_REQUEST_SCHEMA;

export interface ProposeFixOptions {
  client: LlmClient;
  readFile: (relPath: string) => Promise<string>;
  fingerprint: (finding: Finding) => string;
}

function fixUserPrompt(finding: Finding, fileCode: string): string {
  return [
    `Finding: ${finding.ruleId} (${finding.severity})`,
    `Location: ${finding.location.file}:${finding.location.line}`,
    `Detector message: ${finding.message}`,
    finding.remediation ? `Suggested direction: ${finding.remediation}` : "",
    "",
    "Full file content:",
    "```",
    fileCode,
    "```",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Ask the model for a fix. Returns a {@link FixProposal} (full new file content)
 * or null when there is nothing safe to propose (secret-bearing file, sensitive
 * finding, unreadable file, or the model declined / echoed the input).
 */
export async function proposeFix(
  finding: Finding,
  opts: ProposeFixOptions,
): Promise<FixProposal | null> {
  let content: string;
  try {
    content = await opts.readFile(finding.location.file);
  } catch {
    return null;
  }
  if (!content) return null;

  const ctx = buildContext(finding, "file", content);
  // Sensitive finding (code === null) or any secret stripped → do not remediate.
  if (ctx.code === null || ctx.redactedSecret) return null;

  const raw = (await opts.client.complete({
    system: FIX_SYSTEM,
    user: fixUserPrompt(finding, ctx.code),
    schema: FIX_SCHEMA,
    maxTokens: 8192,
  })) as { path: string; newContent: string; explanation: string };

  if (!raw.newContent || raw.newContent === content) return null;
  // Defense in depth: never write the redaction placeholder back to disk.
  if (raw.newContent.includes("«redacted-secret»")) return null;

  return {
    fingerprint: opts.fingerprint(finding),
    path: finding.location.file,
    newContent: raw.newContent,
    explanation: raw.explanation,
  };
}
