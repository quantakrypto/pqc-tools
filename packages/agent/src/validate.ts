/**
 * A tiny JSON-Schema validator covering exactly the subset the agent emits
 * (`type`, `required`, `enum`, `minimum`/`maximum`, `properties`, `items`).
 * Hand-rolled to keep the package zero-dependency. Used to force LLM responses
 * into a known shape before anything downstream trusts them.
 */
export type JsonSchema = Record<string, unknown>;
type Ok = { ok: true; value: unknown };
type Err = { ok: false; error: string };

/** Validate `value` against the JSON-Schema subset we emit. */
export function validateAgainstSchema(value: unknown, schema: JsonSchema, path = "$"): Ok | Err {
  const err = (m: string): Err => ({ ok: false, error: `${path} ${m}` });

  const en = (schema as { enum?: unknown[] }).enum;
  if (Array.isArray(en) && !en.includes(value)) {
    return err(`must be one of ${JSON.stringify(en)}`);
  }

  const t = schema.type as string | undefined;
  if (t === "number") {
    if (typeof value !== "number" || Number.isNaN(value)) return err("must be a number");
    const { minimum, maximum } = schema as { minimum?: number; maximum?: number };
    if (minimum !== undefined && value < minimum) return err(`must be >= ${minimum}`);
    if (maximum !== undefined && value > maximum) return err(`must be <= ${maximum}`);
  } else if (t === "string") {
    if (typeof value !== "string") return err("must be a string");
  } else if (t === "boolean") {
    if (typeof value !== "boolean") return err("must be a boolean");
  } else if (t === "array") {
    if (!Array.isArray(value)) return err("must be an array");
    const items = (schema as { items?: JsonSchema }).items;
    if (items) {
      for (let i = 0; i < value.length; i++) {
        const r = validateAgainstSchema(value[i], items, `${path}[${i}]`);
        if (!r.ok) return r;
      }
    }
  } else if (t === "object" || schema.properties) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return err("must be an object");
    }
    const obj = value as Record<string, unknown>;
    for (const req of (schema as { required?: string[] }).required ?? []) {
      if (!(req in obj)) return err(`missing required "${req}"`);
    }
    const props = (schema as { properties?: Record<string, JsonSchema> }).properties ?? {};
    for (const [k, sub] of Object.entries(props)) {
      if (k in obj) {
        const r = validateAgainstSchema(obj[k], sub, `${path}.${k}`);
        if (!r.ok) return r;
      }
    }
  }
  return { ok: true, value };
}
