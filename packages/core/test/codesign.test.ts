/**
 * Tests for code-signing CLI detection — classical RSA/ECDSA signatures over
 * long-lived distributable artifacts (Authenticode, APK, RPM/deb, NuGet, Apple)
 * in build scripts, forgeable once a CRQC exists.
 *
 * Imports the detector DIRECTLY (it is exercised in isolation, not via the shared
 * registry) so no registry/index wiring is required to run these.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { codesignDetector } from "../src/detectors/codesign.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  if (!codesignDetector.appliesTo(file)) return [];
  return codesignDetector.detect({ file, content });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("signtool sign in a PowerShell build script is flagged as Authenticode (RSA, signature, not HNDL)", () => {
  const f = rule(
    run("build.ps1", "signtool sign /fd SHA256 /a app.exe\n"),
    "codesign-authenticode",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("osslsigncode and Set-AuthenticodeSignature also fire the Authenticode rule", () => {
  assert.ok(
    rule(
      run("sign.sh", "osslsigncode sign -pkcs12 c.pfx -in a.exe -out a-signed.exe\n"),
      "codesign-authenticode",
    ),
  );
  assert.ok(
    rule(
      run("sign.ps1", "Set-AuthenticodeSignature -FilePath app.exe -Certificate $cert\n"),
      "codesign-authenticode",
    ),
  );
});

test("apksigner sign in a shell build script is flagged as APK signing (RSA)", () => {
  const f = rule(run("build.sh", "apksigner sign --ks release.jks app.apk\n"), "codesign-apk");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("Gradle signingConfigs block fires the APK rule", () => {
  assert.ok(
    rule(
      run(
        "build.gradle",
        "android {\n  signingConfigs {\n    release { storeFile file('r.jks') }\n  }\n}\n",
      ),
      "codesign-apk",
    ),
  );
});

test("rpmsign --addsign is flagged as RPM/deb signing (RSA)", () => {
  const f = rule(run("release.sh", "rpmsign --addsign pkg.rpm\n"), "codesign-rpm");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, false);
});

test("rpm --addsign, %_gpg_name macro and dpkg-sig also fire the RPM/deb rule", () => {
  assert.ok(rule(run("sign.sh", "rpm --addsign pkg.rpm\n"), "codesign-rpm"));
  assert.ok(rule(run(".rpmmacros", "%_gpg_name Build Bot <bot@example.com>\n"), "codesign-rpm"));
  assert.ok(rule(run("sign.sh", "dpkg-sig --sign builder app.deb\n"), "codesign-rpm"));
});

test("dotnet nuget sign is flagged as NuGet signing (RSA)", () => {
  const f = rule(
    run("build.sh", "dotnet nuget sign pkg.nupkg --certificate-path c.pfx\n"),
    "codesign-nuget",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("Apple codesign / notarytool are flagged (algorithm unknown: RSA or ECDSA)", () => {
  const f = rule(run("build.sh", "codesign --sign 'Developer ID' MyApp.app\n"), "codesign-apple");
  assert.equal(f?.algorithm, "unknown");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  assert.ok(
    rule(run("notarize.sh", "xcrun notarytool submit MyApp.zip --wait\n"), "codesign-apple"),
  );
});

test("a build script with no signing command produces no findings", () => {
  assert.deepEqual(run("build.sh", "npm ci && npm run build && npm test\n"), []);
});

test("a doc (.md) showing `signtool sign` is prose, not a build step — no findings", () => {
  assert.deepEqual(
    run("README.md", "Release engineers run `signtool sign /a app.exe` to sign.\n"),
    [],
  );
});

test("a commented-out signing command is NOT flagged", () => {
  assert.deepEqual(run("build.sh", "# signtool sign /fd SHA256 /a app.exe\n"), []);
  // An active step with a trailing comment still fires.
  assert.ok(
    rule(run("build.sh", "apksigner sign --ks r.jks app.apk # release build\n"), "codesign-apk"),
  );
});
