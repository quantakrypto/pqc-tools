import { test } from "node:test";
import assert from "node:assert/strict";
import { authorizeTargets, parseOwnedHosts, AttestationError } from "../src/attest.js";
import type { Target } from "../src/target.js";

const T: Target[] = [{ host: "example.com", port: 443 }];

test("refuses to authorize without any attestation (nothing connects)", () => {
  assert.throws(() => authorizeTargets(T, { iOwnThis: false }), AttestationError);
});

test("--i-own-this authorizes", () => {
  assert.doesNotThrow(() => authorizeTargets(T, { iOwnThis: true }));
});

test("ownership manifest authorizes only listed hosts", () => {
  const owned = parseOwnedHosts("# my hosts\nexample.com\napi.internal:8443\n");
  assert.doesNotThrow(() => authorizeTargets(T, { iOwnThis: false, ownedHosts: owned }));
  assert.throws(
    () =>
      authorizeTargets([{ host: "evil.com", port: 443 }], { iOwnThis: false, ownedHosts: owned }),
    AttestationError,
  );
});

test("parseOwnedHosts strips comments, blanks, and ports", () => {
  assert.deepEqual(parseOwnedHosts("\n# c\nfoo.com\nbar.com:22\n"), ["foo.com", "bar.com"]);
});
