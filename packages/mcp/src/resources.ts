/**
 * MCP resources + prompts. Resources expose read-only reference data (the full
 * rule catalog + a migration guide); the prompt gives a client a one-call
 * "migrate this path" workflow that drives the deterministic tools. All offline
 * and static — no filesystem, no network, no key.
 */
import { defaultRegistry, REMEDIATE_RUBRIC } from "@quantakrypto/core";

/** A resource descriptor for `resources/list`. */
interface ResourceDescriptor {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

export const RESOURCES: ResourceDescriptor[] = [
  {
    uri: "quantakrypto://rules",
    name: "Quantakrypto rule catalog",
    description:
      "Every detection rule quantakrypto can emit (id, title, severity, category, HNDL, remediation).",
    mimeType: "application/json",
  },
  {
    uri: "quantakrypto://guide/migration",
    name: "PQC migration guide",
    description: "How to migrate quantum-vulnerable cryptography using the quantakrypto MCP tools.",
    mimeType: "text/markdown",
  },
];

const MIGRATION_GUIDE = `# Post-Quantum Migration with quantakrypto

A safe, deterministic loop ("the model proposes, the engine disposes"):

1. **Inventory** — call \`scan_path\` on the target to list quantum-vulnerable findings.
2. **Triage** — call \`triage_findings\` for the bundle, decide an exposure verdict per
   finding, then \`apply_triage\` to rank them (harvest-now-decrypt-later first).
3. **Remediate** — call \`remediate_findings\`; for each finding propose the corrected
   full file, then \`verify_fix\` on your result. Keep ONLY fixes that clear the finding
   and introduce no new one. Skip any file containing secrets.
4. Open a **draft** PR for review. Never auto-merge.

## Remediation rubric

${REMEDIATE_RUBRIC}
`;

/** Read a resource body by URI, or null when the URI is unknown. */
export function readResource(uri: string): { uri: string; mimeType: string; text: string } | null {
  if (uri === "quantakrypto://rules") {
    return {
      uri,
      mimeType: "application/json",
      text: JSON.stringify(defaultRegistry.ruleCatalog(), null, 2),
    };
  }
  if (uri === "quantakrypto://guide/migration") {
    return { uri, mimeType: "text/markdown", text: MIGRATION_GUIDE };
  }
  return null;
}

/** A prompt descriptor for `prompts/list`. */
interface PromptDescriptor {
  name: string;
  description: string;
  arguments?: { name: string; description: string; required?: boolean }[];
}

export const PROMPTS: PromptDescriptor[] = [
  {
    name: "migrate",
    description:
      "Plan and apply a post-quantum migration for a path using the deterministic tools.",
    arguments: [{ name: "path", description: "Path to scan (default: .)", required: false }],
  },
];

/** A prompt message (MCP `prompts/get` shape). */
interface PromptMessage {
  role: "user";
  content: { type: "text"; text: string };
}

/** Materialize a prompt by name, or null when unknown. */
export function getPrompt(
  name: string,
  args: Record<string, unknown>,
): { description: string; messages: PromptMessage[] } | null {
  if (name !== "migrate") return null;
  const path = typeof args.path === "string" && args.path ? args.path : ".";
  const text =
    `Migrate ${path} off quantum-vulnerable cryptography using the quantakrypto tools.\n` +
    `1) Call scan_path on "${path}".\n` +
    `2) Call triage_findings, decide exposure verdicts, then apply_triage to rank them.\n` +
    `3) For each finding: call remediate_findings, propose the corrected full file, then\n` +
    `   verify_fix on your result — keep only fixes that clear the finding.\n` +
    `Never touch files containing secrets; never auto-merge — open a draft PR for review.`;
  return {
    description: "Plan and apply a post-quantum migration.",
    messages: [{ role: "user", content: { type: "text", text } }],
  };
}
