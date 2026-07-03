/**
 * Remediation rubric, fix schema, and request-bundle builder — offline and
 * deterministic, shared by `@quantakrypto/agent` (which prompts a model with
 * them) and the MCP `remediate_findings` tool (which hands the bundle to the
 * host agent). Keeping them here means the MCP server stays offline/key-free.
 */
import type { Finding } from "./types.js";
import type { ContextLevel, RedactedContext } from "./agent-types.js";
import { buildContext } from "./redact.js";

/** The system rubric for a fix proposal. */
export const REMEDIATE_RUBRIC =
  "You are a post-quantum cryptography migration engineer. Given the FULL content " +
  "of one source file plus a finding describing classical (quantum-vulnerable) " +
  "cryptography in it, return the FULL corrected file content that removes the " +
  "flagged usage, migrating to a post-quantum or hybrid construction " +
  "(ML-KEM-768 / ML-DSA-65, hybrid X25519MLKEM768) where a safe replacement " +
  "exists. Change as little as possible; preserve all other code and formatting " +
  "exactly. If you cannot safely fix it, return newContent identical to the " +
  "input. NEVER invent or alter secrets/keys. After proposing, VERIFY with the " +
  "verify_fix tool and keep only fixes that clear the finding.";

/** JSON Schema every fix proposal must satisfy. */
export const FIX_REQUEST_SCHEMA: Record<string, unknown> = {
  type: "object",
  required: ["path", "newContent", "explanation"],
  properties: {
    path: { type: "string" },
    newContent: { type: "string" },
    explanation: { type: "string" },
  },
};

/** A remediation request bundle for the host agent. */
export interface RemediateRequest {
  instructions: string;
  schema: Record<string, unknown>;
  contexts: RedactedContext[];
}

/** Build a remediation request bundle (offline; metadata level unless `readContent`). */
export function buildRemediateRequest(
  findings: readonly Finding[],
  level: ContextLevel = "metadata",
  readContent?: (finding: Finding) => string,
): RemediateRequest {
  const effectiveLevel: ContextLevel = readContent ? level : "metadata";
  const contexts = findings.map((f) =>
    buildContext(f, effectiveLevel, readContent ? readContent(f) : ""),
  );
  return { instructions: REMEDIATE_RUBRIC, schema: FIX_REQUEST_SCHEMA, contexts };
}
