/**
 * Shared parse → validate → repair-retry loop used by every provider adapter.
 * Keeps the adapters to just their HTTP shape; the structured-output discipline
 * lives here, so all providers fail closed identically on a malformed reply.
 */
import type { LlmRequest } from "./client.js";
import { validateAgainstSchema } from "./validate.js";

/** Extract the first balanced-looking JSON object from a text blob. */
function tryParse(text: string): unknown {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return undefined;
  try {
    return JSON.parse(m[0]);
  } catch {
    return undefined;
  }
}

/**
 * Drive a provider `call(prompt)` through parse → validate → repair. Returns
 * schema-valid JSON, or throws after `maxRetries` repair attempts.
 */
export async function completeWith(
  call: (prompt: string) => Promise<string>,
  req: LlmRequest,
  maxRetries: number,
  label: string,
): Promise<unknown> {
  const base = `${req.system}\n\n${req.user}\n\nReturn ONLY JSON matching this schema:\n${JSON.stringify(
    req.schema,
  )}`;
  let prompt = base;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const text = await call(prompt);
    const parsed = tryParse(text);
    const check =
      parsed !== undefined
        ? validateAgainstSchema(parsed, req.schema)
        : ({ ok: false, error: "response was not JSON" } as const);
    if (check.ok) return parsed;
    if (attempt === maxRetries) {
      throw new Error(`${label}: invalid response after ${maxRetries} repair(s) (${check.error})`);
    }
    prompt = `${base}\n\nYour previous reply was invalid: ${check.error}. Reply with corrected JSON only.`;
  }
  /* c8 ignore next */
  throw new Error(`${label}: exhausted retries`);
}
