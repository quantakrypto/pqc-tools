import { test } from "node:test";
import assert from "node:assert/strict";

import { validateAgainstSchema } from "../src/validate.js";

const schema = {
  type: "object",
  required: ["exposureScore", "priority"],
  properties: {
    exposureScore: { type: "number", minimum: 0, maximum: 100 },
    priority: { enum: ["now", "soon", "later"] },
  },
};

test("valid object passes", () => {
  const r = validateAgainstSchema({ exposureScore: 40, priority: "soon" }, schema);
  assert.equal(r.ok, true);
});

test("missing required field fails with a message", () => {
  const r = validateAgainstSchema({ priority: "soon" }, schema);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /exposureScore/);
});

test("out-of-range number fails", () => {
  const r = validateAgainstSchema({ exposureScore: 900, priority: "now" }, schema);
  assert.equal(r.ok, false);
});

test("bad enum fails", () => {
  const r = validateAgainstSchema({ exposureScore: 1, priority: "urgent" }, schema);
  assert.equal(r.ok, false);
});

test("nested array items are validated", () => {
  const arrSchema = { type: "array", items: { type: "string" } };
  assert.equal(validateAgainstSchema(["a", "b"], arrSchema).ok, true);
  assert.equal(validateAgainstSchema(["a", 2], arrSchema).ok, false);
});
