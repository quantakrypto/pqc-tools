/**
 * Tests for CloudFormation / Azure ARM (IaC) crypto detection — keys,
 * certificates, and legacy TLS config declared in AWS CloudFormation / ARM
 * (incl. Bicep-compiled JSON) templates, a surface the language packs and the
 * Terraform detector never see.
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

test("AWS::KMS::Key KeySpec RSA_* / ECC_* classify correctly", () => {
  const rsaTemplate = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      MyKey: {
        Type: "AWS::KMS::Key",
        Properties: { KeySpec: "RSA_2048", KeyUsage: "ENCRYPT_DECRYPT" },
      },
    },
  });
  const rsa = rule(run("template.json", rsaTemplate), "cfn-kms-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);

  const ecTemplate = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      MyKey: {
        Type: "AWS::KMS::Key",
        Properties: { KeySpec: "ECC_NIST_P384", KeyUsage: "SIGN_VERIFY" },
      },
    },
  });
  const ec = rule(run("template.json", ecTemplate), "cfn-kms-ec");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test("AWS::CertificateManager::Certificate KeyAlgorithm RSA_* / EC_* classify correctly", () => {
  const rsaTemplate = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Cert: {
        Type: "AWS::CertificateManager::Certificate",
        Properties: { DomainName: "example.com", KeyAlgorithm: "RSA_2048" },
      },
    },
  });
  const rsa = rule(run("template.json", rsaTemplate), "cfn-acm-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);

  const ecTemplate = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Cert: {
        Type: "AWS::CertificateManager::Certificate",
        Properties: { DomainName: "example.com", KeyAlgorithm: "EC_prime256v1" },
      },
    },
  });
  const ec = rule(run("template.json", ecTemplate), "cfn-acm-ec");
  assert.equal(ec?.algorithm, "ECDSA");
  assert.equal(ec?.hndl, false);
});

test("CloudFront MinimumProtocolVersion flags legacy TLSv1 / TLSv1.1_2016 but not TLSv1.2", () => {
  const legacy = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Dist: {
        Type: "AWS::CloudFront::Distribution",
        Properties: {
          DistributionConfig: { ViewerCertificate: { MinimumProtocolVersion: "TLSv1" } },
        },
      },
    },
  });
  assert.ok(rule(run("template.json", legacy), "cfn-cloudfront-legacy-tls"));

  const legacy2016 = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Dist: {
        Type: "AWS::CloudFront::Distribution",
        Properties: {
          DistributionConfig: { ViewerCertificate: { MinimumProtocolVersion: "TLSv1.1_2016" } },
        },
      },
    },
  });
  assert.ok(rule(run("template.json", legacy2016), "cfn-cloudfront-legacy-tls"));

  const modern = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Dist: {
        Type: "AWS::CloudFront::Distribution",
        Properties: {
          DistributionConfig: { ViewerCertificate: { MinimumProtocolVersion: "TLSv1.2_2021" } },
        },
      },
    },
  });
  assert.equal(rule(run("template.json", modern), "cfn-cloudfront-legacy-tls"), undefined);
});

test("ELB/ALB SslPolicy flags legacy named policies", () => {
  const legacy2016 = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Listener: {
        Type: "AWS::ElasticLoadBalancingV2::Listener",
        Properties: { SslPolicy: "ELBSecurityPolicy-2016-08" },
      },
    },
  });
  assert.ok(rule(run("template.json", legacy2016), "cfn-elb-legacy-tls"));

  const legacyTls10 = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      Listener: {
        Type: "AWS::ElasticLoadBalancingV2::Listener",
        Properties: { SslPolicy: "ELBSecurityPolicy-TLS-1-0-2015-04" },
      },
    },
  });
  assert.ok(rule(run("template.json", legacyTls10), "cfn-elb-legacy-tls"));
});

test("Azure ARM Microsoft.KeyVault key kty RSA / EC classify correctly", () => {
  const rsaTemplate = JSON.stringify({
    $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    resources: [
      {
        type: "Microsoft.KeyVault/vaults/keys",
        properties: { kty: "RSA", keySize: 2048 },
      },
    ],
  });
  const rsa = rule(run("template.json", rsaTemplate), "cfn-arm-keyvault-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);

  const ecTemplate = JSON.stringify({
    $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    resources: [
      {
        type: "Microsoft.KeyVault/vaults/keys",
        properties: { kty: "EC" },
      },
    ],
  });
  const ec = rule(run("template.json", ecTemplate), "cfn-arm-keyvault-ec");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test("CloudFormation detector is gated to a CFN/ARM marker (not arbitrary JSON)", () => {
  // The same attribute text in a .txt file must not fire.
  assert.deepEqual(
    run("notes.txt", '"KeySpec": "RSA_2048"').filter((f) => f.ruleId.startsWith("cfn-")),
    [],
  );
  // A .json file with the token but no CFN/ARM marker anywhere must not fire
  // (the fast-reject requires AWS::KMS / AWS::CertificateManager /
  // AWSTemplateFormatVersion / MinimumProtocolVersion / Microsoft.KeyVault /
  // "SslPolicy" to be present somewhere in the file).
  assert.deepEqual(
    run("plain.json", JSON.stringify({ KeySpec: "RSA_2048" })).filter((f) =>
      f.ruleId.startsWith("cfn-"),
    ),
    [],
  );
  // A real CFN template (marker present) is in scope.
  const withMarker = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: { K: { Type: "AWS::KMS::Key", Properties: { KeySpec: "RSA_2048" } } },
  });
  assert.ok(rule(run("template.json", withMarker), "cfn-kms-rsa"));
});

test("clean CloudFormation (symmetric KMS key, no asymmetric crypto) produces no findings", () => {
  const clean = JSON.stringify({
    AWSTemplateFormatVersion: "2010-09-09",
    Resources: {
      MyKey: {
        Type: "AWS::KMS::Key",
        Properties: { KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT" },
      },
    },
  });
  assert.deepEqual(
    run("template.json", clean).filter((f) => f.ruleId.startsWith("cfn-")),
    [],
  );
});
