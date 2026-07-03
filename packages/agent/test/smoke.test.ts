import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT_PACKAGE } from "../src/index.js";

test("package identifier is exported", () => {
  assert.equal(AGENT_PACKAGE, "@quantakrypto/agent");
});
