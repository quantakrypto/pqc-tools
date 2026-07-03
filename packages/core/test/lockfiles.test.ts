/**
 * yarn.lock / pnpm-lock.yaml dependency scanning: transitive vulnerable
 * packages that never appear in package.json are still caught.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { scanManifest, manifestEcosystem, isManifestFile } from "../src/dependencies.js";

test("yarn.lock and pnpm-lock.yaml are recognized as npm manifests", () => {
  assert.equal(manifestEcosystem("yarn.lock"), "npm");
  assert.equal(manifestEcosystem("pnpm-lock.yaml"), "npm");
  assert.equal(manifestEcosystem("npm-shrinkwrap.json"), "npm");
  assert.ok(isManifestFile("a/b/yarn.lock"));
});

test("yarn v1 lockfile: a vulnerable dep is flagged", () => {
  const yarn = [
    "# yarn lockfile v1",
    "",
    "elliptic@^6.5.4:",
    '  version "6.5.4"',
    '  resolved "https://registry.yarnpkg.com/elliptic/-/elliptic-6.5.4.tgz#abc"',
    "",
    '"@noble/curves@^1.2.0":',
    '  version "1.2.0"',
  ].join("\n");
  const findings = scanManifest("yarn.lock", yarn);
  const rules = findings.map((f) => f.title);
  assert.ok(
    findings.some((f) => f.message.includes("elliptic")),
    "elliptic flagged",
  );
  assert.ok(
    findings.some((f) => f.message.includes("@noble/curves")),
    "scoped dep flagged",
  );
  assert.ok(rules.length >= 2);
});

test("yarn berry lockfile (name@npm:range) is parsed", () => {
  const berry = ['"elliptic@npm:^6.5.4":', "  version: 6.5.4"].join("\n");
  assert.ok(scanManifest("yarn.lock", berry).some((f) => f.message.includes("elliptic")));
});

test("pnpm-lock.yaml: /name@version and scoped names are parsed", () => {
  const pnpm = [
    "lockfileVersion: '6.0'",
    "packages:",
    "  /elliptic@6.5.4:",
    "    resolution: {integrity: sha512-abc}",
    "  /@noble/curves@1.2.0:",
    "    resolution: {integrity: sha512-def}",
  ].join("\n");
  const findings = scanManifest("pnpm-lock.yaml", pnpm);
  assert.ok(findings.some((f) => f.message.includes("elliptic")));
  assert.ok(findings.some((f) => f.message.includes("@noble/curves")));
});

test("a lockfile with no known-vulnerable deps yields nothing", () => {
  const yarn = ["lodash@^4.17.21:", '  version "4.17.21"'].join("\n");
  assert.deepEqual(scanManifest("yarn.lock", yarn), []);
});
