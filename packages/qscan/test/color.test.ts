/**
 * Color-policy tests: the resolveColor precedence contract, plus the
 * --color / --no-color argument parsing.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveColor } from "../src/color.js";
import type { ColorContext } from "../src/color.js";
import { parseArgs, defaultOptions } from "../src/args.js";

/** A human/TTY/stdout baseline; tests override just the fields they exercise. */
function ctx(over: Partial<ColorContext> = {}): ColorContext {
  return {
    choice: "auto",
    format: "human",
    toFile: false,
    isTTY: true,
    env: {},
    ...over,
  };
}

test("non-human formats are never colored, even with --color", () => {
  for (const format of ["json", "sarif", "cbom", "evidence"]) {
    assert.equal(resolveColor(ctx({ format, choice: "always" })), false, format);
  }
});

test("--no-color wins over an interactive terminal and FORCE_COLOR", () => {
  assert.equal(
    resolveColor(ctx({ choice: "never", isTTY: true, env: { FORCE_COLOR: "1" } })),
    false,
  );
});

test("--color wins over NO_COLOR and a non-tty pipe", () => {
  assert.equal(resolveColor(ctx({ choice: "always", isTTY: false, env: { NO_COLOR: "1" } })), true);
});

test("NO_COLOR (present, non-empty) disables in auto mode", () => {
  assert.equal(resolveColor(ctx({ env: { NO_COLOR: "1" } })), false);
});

test("NO_COLOR empty string is ignored (auto falls through to tty)", () => {
  assert.equal(resolveColor(ctx({ isTTY: true, env: { NO_COLOR: "" } })), true);
});

test("NO_COLOR beats FORCE_COLOR when both are set", () => {
  assert.equal(resolveColor(ctx({ env: { NO_COLOR: "1", FORCE_COLOR: "1" } })), false);
});

test("FORCE_COLOR forces color onto a non-tty pipe", () => {
  assert.equal(resolveColor(ctx({ isTTY: false, env: { FORCE_COLOR: "1" } })), true);
});

test("FORCE_COLOR=0 / false disables even on a tty", () => {
  assert.equal(resolveColor(ctx({ isTTY: true, env: { FORCE_COLOR: "0" } })), false);
  assert.equal(resolveColor(ctx({ isTTY: true, env: { FORCE_COLOR: "false" } })), false);
});

test("FORCE_COLOR empty string enables (supports-color convention)", () => {
  assert.equal(resolveColor(ctx({ isTTY: false, env: { FORCE_COLOR: "" } })), true);
});

test("auto colors a live terminal but not a file or a pipe", () => {
  assert.equal(resolveColor(ctx({ isTTY: true, toFile: false })), true);
  assert.equal(resolveColor(ctx({ isTTY: true, toFile: true })), false);
  assert.equal(resolveColor(ctx({ isTTY: false, toFile: false })), false);
});

test("parseArgs: --color / --no-color set colorChoice; default is auto", () => {
  assert.equal(defaultOptions().colorChoice, "auto");
  const on = parseArgs(["--color"]);
  assert.equal(on.kind, "run");
  if (on.kind === "run") assert.equal(on.options.colorChoice, "always");
  const off = parseArgs(["--no-color"]);
  assert.equal(off.kind, "run");
  if (off.kind === "run") assert.equal(off.options.colorChoice, "never");
});

test("parseArgs: --color rejects an inline value (boolean flag)", () => {
  assert.throws(() => parseArgs(["--color=1"]), /boolean flag/);
});
