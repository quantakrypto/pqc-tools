/**
 * Tests for supply-chain signing detection (Docker Content Trust, Notation, in-toto).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("Docker Content Trust, Notation, and in-toto signing are detected", () => {
  assert.ok(
    rule(
      run(".github/workflows/release.yml", "env:\n  DOCKER_CONTENT_TRUST: 1\n"),
      "sc-docker-content-trust",
    ),
  );
  assert.ok(rule(run("build.sh", "notation sign $REGISTRY/app:$TAG\n"), "sc-notation-sign"));
  assert.ok(rule(run("Jenkinsfile", "sh 'in-toto-run --step build -- make'"), "sc-in-toto"));
});

test("signing findings are signature-side (hndl:false)", () => {
  const f = rule(run("build.sh", "docker trust sign img:latest\n"), "sc-docker-content-trust");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("gating: tokens in a doc/non-signing file, or in a comment, do not fire", () => {
  assert.deepEqual(
    run("README.md", "We use notation sign and DOCKER_CONTENT_TRUST=1.").filter((f) =>
      f.ruleId.startsWith("sc-"),
    ),
    [],
  );
  assert.deepEqual(
    run("build.sh", "# notation sign is disabled for now\n").filter((f) =>
      f.ruleId.startsWith("sc-"),
    ),
    [],
  );
});
