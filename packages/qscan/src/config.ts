/**
 * qScan-side resolution of `quantakrypto.config.json` (ROADMAP P2-9, docs/CONFIG.md).
 *
 * core's {@link loadConfig} does the reading + type-validation; this module
 * applies the file's values onto parsed CLI options with the documented
 * precedence:
 *
 *     CLI flags  >  quantakrypto.config.json  >  built-in defaults
 *
 * Resolution is **per-key**: a key set by a flag (tracked in the `explicit` set
 * from `parseArgs`) is left alone; otherwise the config value fills it. The
 * list-valued keys (`include` / `ignore`→`exclude`) *append* — the config
 * provides a base set and any CLI flags add to it (docs/CONFIG.md §4.2).
 */

import { loadConfig } from "@quantakrypto/core";
import type { QuantakryptoFileConfig } from "@quantakrypto/core";

import type { ConfigurableKey, QscanOptions } from "./args.js";

/** What {@link resolveConfig} returns: the merged options + provenance. */
export interface ResolvedConfig {
  /** Options with config applied under the flags > config > defaults rule. */
  options: QscanOptions;
  /** Absolute path of the config file that was applied, when one was. */
  configPath?: string;
  /** Non-fatal warnings from parsing (unknown keys, future version, …). */
  warnings: string[];
}

/**
 * Load and merge `quantakrypto.config.json` into the parsed CLI options.
 *
 * @param options Fully-resolved options from {@link parseArgs} (defaults filled).
 * @param explicit The set of configurable keys the user set via a flag.
 * @returns The merged options plus the applied config path + any warnings.
 * @throws {ConfigError} (from core) on a malformed config or a missing
 *   explicitly-named `--config` file. The CLI maps this to exit 2.
 */
export async function resolveConfig(
  options: QscanOptions,
  explicit: ReadonlySet<ConfigurableKey>,
): Promise<ResolvedConfig> {
  // `--no-config-file` disables discovery entirely; nothing to merge.
  if (options.noConfigFile && options.configFile === undefined) {
    return { options, warnings: [] };
  }

  // `--config <path>` names the file explicitly (a missing file is then fatal);
  // otherwise auto-discover at the scan root.
  const target = options.configFile ?? options.path;
  const loaded = await loadConfig(target, { explicit: options.configFile !== undefined });

  if (loaded.path === undefined) {
    // No file found (auto-discovery, tolerant): options unchanged.
    return { options, warnings: loaded.warnings };
  }

  const merged = applyConfig(options, loaded.config, explicit);
  // Security: an AUTO-DISCOVERED config (no explicit `--config`) can come from the
  // scanned tree itself, so a hostile repo could silently WEAKEN its own scan
  // (disable rules, raise the severity threshold, exclude files → flip exit 1→0).
  // Never silently: warn loudly for each policy-weakening key it applied. An explicit
  // `--config` is the operator's own choice and stays quiet. Use `--no-config-file`
  // to ignore a discovered config entirely.
  const warnings = [...loaded.warnings];
  if (options.configFile === undefined) {
    warnings.push(...weakeningWarnings(loaded.config, explicit));
  }
  return { options: merged, configPath: loaded.path, warnings };
}

/**
 * Warnings for each SCAN-WEAKENING key an auto-discovered config actually applied
 * (present in the file and not overridden by a CLI flag). These are the keys that can
 * make a scan pass that would otherwise fail, so an operator scanning an untrusted
 * tree must see them rather than have the verdict silently softened.
 */
function weakeningWarnings(
  config: QuantakryptoFileConfig,
  explicit: ReadonlySet<ConfigurableKey>,
): string[] {
  const w: string[] = [];
  const applied = <K extends ConfigurableKey>(key: K): boolean => !explicit.has(key);
  const note = (s: string) =>
    w.push(
      `auto-discovered config ${s} — a scanned repo may author this; re-run with --no-config-file to ignore it`,
    );

  if (config.disabledRules && config.disabledRules.length > 0) {
    note(
      `disabled ${config.disabledRules.length} detection rule(s): ${config.disabledRules.join(", ")}`,
    );
  }
  if (config.severityThreshold !== undefined && applied("severityThreshold")) {
    note(`set the failure severity-threshold to "${config.severityThreshold}"`);
  }
  if (config.exclude && config.exclude.length > 0) {
    note(`excluded ${config.exclude.length} path pattern(s) from the scan`);
  }
  if (config.source === false && applied("source")) note("disabled source scanning");
  if (config.dependencies === false && applied("dependencies"))
    note("disabled dependency scanning");
  if (config.config === false && applied("config")) note("disabled config-file scanning");
  if (config.maxFileSize !== undefined && applied("maxFileSize")) {
    note(`capped scanned file size at ${config.maxFileSize} bytes`);
  }
  return w;
}

/**
 * Apply a parsed config onto options under the precedence rule. Pure; returns a
 * new options object. Scalars: config fills only keys NOT set by a flag. Lists:
 * config provides the base and the CLI flag values are appended.
 */
export function applyConfig(
  options: QscanOptions,
  config: QuantakryptoFileConfig,
  explicit: ReadonlySet<ConfigurableKey>,
): QscanOptions {
  const out: QscanOptions = {
    ...options,
    ignore: [...options.ignore],
    include: [...options.include],
  };

  /** Set a scalar key from config only when the user didn't set it via a flag. */
  const fillScalar = <K extends ConfigurableKey & keyof QscanOptions>(
    key: K,
    value: QscanOptions[K] | undefined,
  ): void => {
    if (value === undefined) return;
    if (explicit.has(key)) return; // flag wins.
    out[key] = value;
  };

  fillScalar("severityThreshold", config.severityThreshold);
  fillScalar("source", config.source);
  fillScalar("dependencies", config.dependencies);
  fillScalar("config", config.config);
  fillScalar("noDefaultIgnores", config.noDefaultIgnores);
  fillScalar("scanMinified", config.scanMinified);
  fillScalar("maxFileSize", config.maxFileSize);
  fillScalar("baseline", config.baseline);

  // List-valued keys: config is the base, CLI flags append (config first so the
  // committed policy reads as the baseline, ad-hoc CLI excludes/includes after).
  if (config.exclude && config.exclude.length > 0) {
    out.ignore = [...config.exclude, ...options.ignore];
  }
  if (config.include && config.include.length > 0) {
    out.include = [...config.include, ...options.include];
  }
  // disabledRules is config-only (no CLI flag today) — set it straight through.
  if (config.disabledRules && config.disabledRules.length > 0) {
    out.disabledRules = [...config.disabledRules];
  }

  return out;
}
