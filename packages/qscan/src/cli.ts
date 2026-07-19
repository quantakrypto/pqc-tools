#!/usr/bin/env node
/**
 * qScan command-line entry point.
 *
 * Thin shell over the programmatic API in `./index.ts`:
 *   parse argv → runQscan → print/write report → process.exit(code).
 *
 * All policy (scanning, baseline, thresholds, rendering) lives in `index.ts`;
 * this file only deals with argv, stdout/stderr, files, and exit codes.
 */

import { realpathSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { ConfigError } from "@quantakrypto/core";

import { ArgError, parseArgs } from "./args.js";
import type { ParsedArgs, QscanOptions } from "./args.js";
import { resolveColor } from "./color.js";
import { resolveConfig } from "./config.js";
import { HELP_TEXT, versionLine } from "./help.js";
import { EXIT, runQscan } from "./index.js";
import type { QscanRun } from "./index.js";

/** Run the CLI and return the desired process exit code (never throws). */
export async function main(argv: readonly string[]): Promise<number> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    if (err instanceof ArgError) {
      process.stderr.write(`qscan: ${err.message}\n`);
      process.stderr.write(`Run "qscan --help" for usage.\n`);
      return EXIT.ERROR;
    }
    throw err;
  }

  if (parsed.kind === "help") {
    process.stdout.write(HELP_TEXT);
    return EXIT.OK;
  }
  if (parsed.kind === "version") {
    process.stdout.write(`${versionLine()}\n`);
    return EXIT.OK;
  }

  // Resolve `quantakrypto.config.json` (flags > config > defaults) before scanning.
  let options: QscanOptions;
  try {
    const resolved = await resolveConfig(parsed.options, parsed.explicit);
    options = resolved.options;
    if (!options.quiet) {
      for (const w of resolved.warnings) {
        process.stderr.write(`qscan: config warning: ${w}\n`);
      }
      if (resolved.configPath) {
        process.stderr.write(`qscan: using config ${resolved.configPath}\n`);
      }
    }
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`qscan: ${err.message}\n`);
      return EXIT.ERROR;
    }
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qscan: ${message}\n`);
    return EXIT.ERROR;
  }

  // Color policy: --color/--no-color > NO_COLOR/FORCE_COLOR > interactive stdout.
  // Color is decoration only (every signal is also text), so this is purely an
  // accessibility / pipe-safety control. See resolveColor for the precedence.
  const color = resolveColor({
    choice: options.colorChoice,
    format: options.format,
    toFile: Boolean(options.output),
    isTTY: Boolean(process.stdout.isTTY),
    env: { NO_COLOR: process.env.NO_COLOR, FORCE_COLOR: process.env.FORCE_COLOR },
  });

  let run: QscanRun;
  try {
    run = await runQscan(options, { color });
  } catch (err) {
    // A missing scan path is the most common failure; a raw
    // "ENOENT: no such file or directory, stat '…'" reads like a tool bug.
    // Turn it into a plain, actionable line (still exit 2).
    if (isErrno(err) && err.code === "ENOENT") {
      process.stderr.write(`qscan: path not found: ${options.path}\n`);
      return EXIT.ERROR;
    }
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qscan: ${message}\n`);
    return EXIT.ERROR;
  }

  // --write-baseline: report what was written and stop.
  if (run.baselineWritten) {
    if (!options.quiet) {
      const n = run.baselineWritten.fingerprints.length;
      process.stderr.write(
        `qscan: wrote baseline with ${n} fingerprint${n === 1 ? "" : "s"} to ${options.writeBaseline}\n`,
      );
    }
    return run.exitCode;
  }

  const report = run.report ?? "";
  try {
    if (options.output) {
      await writeFile(options.output, report.endsWith("\n") ? report : `${report}\n`, "utf8");
      if (!options.quiet) {
        process.stderr.write(`qscan: wrote ${options.format} report to ${options.output}\n`);
      }
    } else if (!options.quiet || options.format !== "human") {
      // In quiet mode we still emit machine formats to stdout (the point of a
      // pipe), but suppress the human banner.
      await writeStdout(report.endsWith("\n") ? report : `${report}\n`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qscan: ${message}\n`);
    return EXIT.ERROR;
  }

  if (!options.quiet && run.suppressed.length > 0) {
    process.stderr.write(`qscan: suppressed ${run.suppressed.length} finding(s) via baseline\n`);
  }

  return run.exitCode;
}

/** True for Node system errors (fs/os), which carry a string `code` like `ENOENT`. */
function isErrno(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && typeof (err as NodeJS.ErrnoException).code === "string";
}

/**
 * Write to stdout, awaiting `drain` when the kernel buffer is full.
 *
 * `process.stdout.write` returns `false` when the OS buffer can't accept the
 * whole chunk (typical for large reports down a pipe or file redirect). If the
 * process then exits before the buffer flushes, the tail of the report is lost.
 * When the write is not fully flushed we wait for the `drain` event, so the
 * bytes are handed to the OS before we return and the report is never
 * truncated, regardless of how the caller exits. A fully-flushed write (the
 * common case, and a TTY) resolves synchronously on the next microtask.
 */
function writeStdout(chunk: string): Promise<void> {
  const flushed = process.stdout.write(chunk);
  if (flushed) return Promise.resolve();
  return new Promise((resolve) => process.stdout.once("drain", resolve));
}

/**
 * True when this module is the program's entry point. Resolves symlinks so the
 * check also holds when launched via the `qscan` bin shim in node_modules/.bin
 * (npm symlinks it) or through /tmp -> /private/tmp on macOS — otherwise
 * `npx @quantakrypto/qscan` (and `npm i -g`) would be a silent no-op.
 */
function isMainModule(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  const thisPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(argv1) === realpathSync(thisPath);
  } catch {
    return argv1 === thisPath;
  }
}

// Only auto-run when invoked as a script (not when imported by a test).
const invokedDirectly = isMainModule();

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => {
      // Set the exit code and return WITHOUT calling process.exit(): a bare
      // process.exit() tears down the event loop before stdout's async buffer
      // drains, truncating large SARIF/JSON reports written to a pipe or file
      // redirect. Letting the loop empty naturally lets the buffer flush first.
      process.exitCode = code;
    })
    .catch((err) => {
      const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
      process.stderr.write(`qscan: fatal: ${message}\n`);
      process.exitCode = EXIT.ERROR;
    });
}
