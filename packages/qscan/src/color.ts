/**
 * Color-output policy for the human report.
 *
 * ANSI color is decoration, never the sole carrier of meaning (every severity,
 * count, and score is also printed as text), so turning it off never loses
 * information — it's an accessibility and pipe-safety control. This module is the
 * single place that decides whether to emit it, with an explicit precedence so
 * the behaviour is predictable and testable:
 *
 *   1. Non-`human` formats are NEVER colored — ANSI would corrupt JSON/SARIF/CBOM.
 *   2. An explicit `--color` / `--no-color` flag wins over everything else.
 *   3. `NO_COLOR` (present, non-empty) disables — https://no-color.org.
 *   4. `FORCE_COLOR` enables (Node/supports-color convention: `0`/`false` disable,
 *      any other value — including empty — enables).
 *   5. Otherwise: color only a live terminal (`stdout.isTTY`), never a file or pipe.
 */

/** What the user asked for on the command line. `"auto"` = decide from context. */
export type ColorChoice = "always" | "never" | "auto";

/** Just the environment variables the decision reads. */
export interface ColorEnv {
  NO_COLOR?: string | undefined;
  FORCE_COLOR?: string | undefined;
}

export interface ColorContext {
  /** From `--color` / `--no-color`; defaults to `"auto"`. */
  choice: ColorChoice;
  /** Report format; only `"human"` is ever colored. */
  format: string;
  /** True when the report goes to an output file rather than stdout. */
  toFile: boolean;
  /** `process.stdout.isTTY`. */
  isTTY: boolean;
  env: ColorEnv;
}

/** NO_COLOR counts when present and non-empty (per the no-color.org wording). */
function noColorRequested(v: string | undefined): boolean {
  return v !== undefined && v !== "";
}

/** FORCE_COLOR enables unless it is `0`/`false` (Node/supports-color semantics). */
function forceColorRequested(v: string | undefined): boolean {
  return v !== undefined && v !== "0" && v.toLowerCase() !== "false";
}

/** Resolve whether the human report should emit ANSI color. */
export function resolveColor(ctx: ColorContext): boolean {
  // (1) Machine-readable formats must stay byte-clean.
  if (ctx.format !== "human") return false;

  // (2) Explicit CLI intent is absolute.
  if (ctx.choice === "never") return false;
  if (ctx.choice === "always") return true;

  // (3) Accessibility opt-out wins over FORCE_COLOR when both are set.
  if (noColorRequested(ctx.env.NO_COLOR)) return false;

  // (4) FORCE_COLOR, when present, decides (enables, unless 0/false).
  if (ctx.env.FORCE_COLOR !== undefined) return forceColorRequested(ctx.env.FORCE_COLOR);

  // (5) Auto: a live terminal only.
  return ctx.isTTY && !ctx.toFile;
}
