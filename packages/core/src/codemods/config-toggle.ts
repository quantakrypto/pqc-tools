/**
 * Config-toggle codemod: mechanical, unambiguous fixes for insecure TLS config.
 * Both target rules have a single correct replacement, so the fix is
 * deterministic and clears the finding (verified by the pipeline's gate).
 *
 *  - `tls-legacy-version`  — bump a pinned TLS 1.0/1.1 to TLS 1.3.
 *  - `tls-reject-unauthorized` — turn certificate verification back on.
 */
import type { Finding } from "../types.js";
import type { Patch } from "../agent-types.js";
import type { Codemod } from "./registry.js";

export const configToggleCodemod: Codemod = {
  id: "config-toggle",
  applies(finding: Finding): boolean {
    return finding.ruleId === "tls-legacy-version" || finding.ruleId === "tls-reject-unauthorized";
  },
  apply(content: string, finding: Finding): Patch | null {
    // Normalize ALL insecure TLS config in one pass (not just this finding's
    // aspect), so a file with both issues is fully fixed by a single patch — the
    // pipeline dedupes patches by file, and a partial patch would drop a sibling.
    const out = content
      .replace(/((?:minVersion|maxVersion)\s*:\s*['"`])TLSv1(?:\.1)?(['"`])/g, "$1TLSv1.3$2")
      .replace(/(secureProtocol\s*:\s*['"`])TLSv1(?:_1)?_method(['"`])/g, "$1TLSv1_3_method$2")
      .replace(/(rejectUnauthorized\s*:\s*)false/g, "$1true");
    if (out === content) return null;
    return {
      path: finding.location.file,
      newContent: out,
      ruleId: finding.ruleId,
      source: "codemod",
    };
  },
};
