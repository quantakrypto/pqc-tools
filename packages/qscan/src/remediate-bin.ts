#!/usr/bin/env node
/**
 * qremediate command-line entry point. Thin shell over `runRemediate`:
 * parse argv → run → print → exit.
 */
import { realpathSync } from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { versionLine } from "./help.js";
import {
  parseRemediateArgs,
  runRemediate,
  REMEDIATE_HELP,
  REMEDIATE_EXIT,
} from "./remediate-cli.js";

export async function main(argv: readonly string[]): Promise<number> {
  const parsed = parseRemediateArgs(argv);
  if (parsed.kind === "help") {
    process.stdout.write(REMEDIATE_HELP);
    return REMEDIATE_EXIT.OK;
  }
  if (parsed.kind === "version") {
    process.stdout.write(`${versionLine().replace("qscan", "qremediate")}\n`);
    return REMEDIATE_EXIT.OK;
  }
  if (parsed.kind === "error") {
    process.stderr.write(`qremediate: ${parsed.message}\n`);
    return REMEDIATE_EXIT.ERROR;
  }
  try {
    const run = await runRemediate(parsed.options);
    process.stdout.write(run.output.endsWith("\n") ? run.output : `${run.output}\n`);
    return run.exitCode;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qremediate: ${message}\n`);
    return REMEDIATE_EXIT.ERROR;
  }
}

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

if (isMainModule()) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
      process.stderr.write(`qremediate: fatal: ${message}\n`);
      process.exitCode = REMEDIATE_EXIT.ERROR;
    });
}
