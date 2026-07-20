/**
 * Tests for the selectable standards regime profiles (NIST / CNSA / BSI / ANSSI /
 * NCSC) and the profile-aware remediation composer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  STANDARDS_PROFILES,
  DEFAULT_PROFILE_ID,
  standardsProfileIds,
  getStandardsProfile,
  defaultStandardsProfile,
  remediationForProfile,
  PQC_STANDARDS,
} from "../src/index.js";
import type { AlgorithmFamily } from "../src/index.js";

test("every built-in profile is well-formed and self-consistent", () => {
  for (const [id, p] of Object.entries(STANDARDS_PROFILES)) {
    assert.equal(p.id, id, "id matches its key");
    assert.ok(p.name && p.authority && p.citation, `${id} has name/authority/citation`);
    assert.match(p.paramSets.kem, /ML-KEM-\d+/);
    assert.match(p.paramSets.signature, /ML-DSA-\d+/);
    assert.ok(["required", "recommended", "optional"].includes(p.hybridStance));
    assert.ok(p.deprecateAfter <= p.disallowAfter, `${id}: deprecate before disallow`);
    assert.match(p.asOf, /^\d{4}-\d{2}$/);
  }
});

test("the default profile is NIST and is listed first", () => {
  assert.equal(DEFAULT_PROFILE_ID, "nist");
  assert.equal(defaultStandardsProfile().id, "nist");
  assert.equal(standardsProfileIds()[0], "nist");
  assert.equal(getStandardsProfile("nope"), undefined);
});

test("hybrid stance is regime-correct (the bug this feature fixes)", () => {
  // The pre-profile code told everyone 'hybrids optional' (CNSA's stance) — wrong for
  // ANSSI/BSI, where hybrid is REQUIRED. Pin each regime's stance.
  assert.equal(getStandardsProfile("anssi")?.hybridStance, "required");
  assert.equal(getStandardsProfile("bsi-tr-02102")?.hybridStance, "required");
  assert.equal(getStandardsProfile("cnsa-2.0")?.hybridStance, "optional");
  assert.equal(getStandardsProfile("nist")?.hybridStance, "recommended");
  assert.equal(getStandardsProfile("uk-ncsc")?.hybridStance, "recommended");
});

test("remediationForProfile surfaces the regime's params + hybrid stance", () => {
  const anssi = getStandardsProfile("anssi")!;
  const ecdh = remediationForProfile("ECDH", anssi);
  assert.match(ecdh.recommendation, /ML-KEM-1024/); // ANSSI wants the high param set
  assert.match(ecdh.recommendation, /hybrid required/);
  assert.match(ecdh.detail, /ANSSI/);
  assert.match(ecdh.detail, /disallowed after 2035/);

  const cnsa = getStandardsProfile("cnsa-2.0")!;
  const cnsaEcdh = remediationForProfile("ECDH", cnsa);
  assert.match(cnsaEcdh.recommendation, /hybrids optional/);
  assert.match(cnsaEcdh.detail, /SecP384r1MLKEM1024/); // regime hybrid note

  // A signature family shows the signer param, no hybrid stance in the headline.
  const nist = getStandardsProfile("nist")!;
  const ecdsa = remediationForProfile("ECDSA", nist);
  assert.match(ecdsa.recommendation, /ML-DSA-65/);
  assert.doesNotMatch(ecdsa.recommendation, /hybrid/);
});

test("DRIFT: profile param sets stay aligned with the standards source of truth", () => {
  // If someone bumps a CNSA param in PQC_STANDARDS without the profile (or vice versa),
  // this fails — the two can't silently diverge.
  assert.equal(
    getStandardsProfile("cnsa-2.0")?.paramSets.kem,
    PQC_STANDARDS.cnsa.category5.kem,
    "cnsa-2.0 profile KEM tracks PQC_STANDARDS category5",
  );
  assert.equal(
    getStandardsProfile("cnsa-2.0")?.paramSets.signature,
    PQC_STANDARDS.cnsa.category5.signature,
  );
  assert.equal(getStandardsProfile("nist")?.paramSets.kem, PQC_STANDARDS.cnsa.category3.kem);
  assert.equal(
    getStandardsProfile("nist")?.paramSets.signature,
    PQC_STANDARDS.cnsa.category3.signature,
  );
  // The NIST profile's deadlines track the IR 8547 transition timeline.
  assert.equal(
    getStandardsProfile("nist")?.deprecateAfter,
    PQC_STANDARDS.transitionTimeline.deprecateAfter,
  );
  assert.equal(
    getStandardsProfile("nist")?.disallowAfter,
    PQC_STANDARDS.transitionTimeline.disallowAfter,
  );
});

test("every confidentiality + signature family resolves under every profile", () => {
  const fams: AlgorithmFamily[] = [
    "RSA",
    "ECDH",
    "ECDSA",
    "EdDSA",
    "DH",
    "DSA",
    "X25519",
    "X448",
    "ECIES",
  ];
  for (const p of Object.values(STANDARDS_PROFILES)) {
    for (const fam of fams) {
      const r = remediationForProfile(fam, p);
      assert.ok(r.recommendation.length > 0 && r.detail.length > 0, `${p.id}/${fam}`);
    }
  }
});
