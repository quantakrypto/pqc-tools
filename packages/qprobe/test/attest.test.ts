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

test("parseOwnedHosts normalizes IPv6 (bracketed + bare) to match target hosts", () => {
  // parseTarget yields host "::1" for "[::1]:443" and "2001:db8::1" for a bare IPv6,
  // so the manifest must reduce to the same strings or IPv6 could never be authorized.
  assert.deepEqual(parseOwnedHosts("[::1]:443\n[2001:db8::1]\n2001:db8::2\n"), [
    "::1",
    "2001:db8::1",
    "2001:db8::2",
  ]);
});

test("ownership manifest authorizes an IPv6 endpoint", () => {
  const owned = parseOwnedHosts("[::1]:443\n2001:db8::2\n");
  assert.doesNotThrow(() =>
    authorizeTargets([{ host: "::1", port: 443 }], { iOwnThis: false, ownedHosts: owned }),
  );
  assert.doesNotThrow(() =>
    authorizeTargets([{ host: "2001:db8::2", port: 443 }], { iOwnThis: false, ownedHosts: owned }),
  );
  assert.throws(
    () =>
      authorizeTargets([{ host: "2001:db8::99", port: 443 }], {
        iOwnThis: false,
        ownedHosts: owned,
      }),
    AttestationError,
  );
});
