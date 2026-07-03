/**
 * Shared types for the agent (BYOK) plane. These live in `@quantakrypto/core`
 * (offline) so both the deterministic MCP tools and the networked
 * `@quantakrypto/agent` package speak the same shapes without the offline side
 * ever importing the network client.
 */
import type { Severity, TriageAnnotation } from "./types.js";

/** How much source context a redacted request carries. */
export type ContextLevel = "metadata" | "snippet" | "function" | "file";

/** A finding's context, redacted to a {@link ContextLevel} and secret-stripped. */
export interface RedactedContext {
  level: ContextLevel;
  meta: {
    ruleId: string;
    algorithm?: string;
    severity: Severity;
    hndl: boolean;
    file: string;
    line: number;
    message: string;
  };
  /** Redacted source, or null at `metadata` level / for a `sensitive` finding. */
  code: string | null;
  /** True when key material was stripped from the context. */
  redactedSecret: boolean;
}

/** An LLM triage verdict for a single finding (never suppresses it). The
 * exposure/priority/rationale body is the {@link TriageAnnotation} that gets
 * attached to the finding; `fingerprint` links it back to that finding. */
export interface TriageVerdict extends TriageAnnotation {
  fingerprint: string;
}

/** A concrete proposed edit: the full new content for a single file. */
export interface Patch {
  path: string;
  /** Full replacement content for `path` after the fix. */
  newContent: string;
  ruleId: string;
  source: "codemod" | "llm";
}

/** An LLM-proposed fix before it enters the deterministic pipeline. */
export interface FixProposal {
  fingerprint: string;
  path: string;
  newContent: string;
  explanation: string;
}
