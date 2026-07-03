/**
 * Guards that the hand-maintained `VERSION` constant stays in lockstep with
 * `package.json`. The two are separate on purpose (the constant avoids an
 * import cycle through index.ts and lets reporters embed the version without
 * reading disk), but that means a release bump has to touch both — forget one
 * and every report/SARIF/CBOM ships a version that lies about the build. This
 * test fails the release before that can happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { VERSION } from "../src/version.js";

test("VERSION matches package.json", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
    version: string;
  };
  assert.equal(
    VERSION,
    pkg.version,
    `src/version.ts VERSION (${VERSION}) is out of sync with package.json (${pkg.version}) — bump both`,
  );
});
