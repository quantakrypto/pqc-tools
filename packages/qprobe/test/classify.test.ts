import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyTls, classifySsh } from "../src/classify.js";
import type { Target } from "../src/target.js";

const T: Target = { host: "example.com", port: 443 };
const has = (fs: { ruleId: string }[], id: string) => fs.some((f) => f.ruleId === id);

test("classical TLS KEX with no hybrid → flags harvestable key exchange + cert", () => {
  const fs = classifyTls(
    T,
    {
      protocol: "TLSv1.3",
      cipher: "TLS_AES_128_GCM_SHA256",
      kexGroup: "X25519",
      certKeyType: "RSA",
      certKeyBits: 2048,
    },
    { hybridSelected: false },
  );
  assert.ok(has(fs, "qprobe-tls-classical-kex"));
  assert.ok(has(fs, "qprobe-tls-classical-cert"));
  const kex = fs.find((f) => f.ruleId === "qprobe-tls-classical-kex")!;
  assert.equal(kex.algorithm, "X25519");
  assert.equal(kex.hndl, true);
});

test("when the server SELECTS the hybrid group, no classical-KEX finding is emitted", () => {
  const fs = classifyTls(
    T,
    { protocol: "TLSv1.3", kexGroup: "X25519", certKeyType: "RSA" },
    { hybridSelected: true, selectedGroup: 0x11ec },
  );
  assert.ok(!has(fs, "qprobe-tls-classical-kex"));
});

test("legacy TLS version is flagged high", () => {
  const fs = classifyTls(T, { protocol: "TLSv1.1" }, { hybridSelected: false });
  const v = fs.find((f) => f.ruleId === "qprobe-tls-legacy-version")!;
  assert.equal(v.severity, "high");
});

test("SSH: classical-only KEX flagged; PQC-offering endpoint clean", () => {
  const classical = classifySsh(T, {
    pqKexOffered: false,
    kex: { kexAlgorithms: ["curve25519-sha256"], hostKeyAlgorithms: ["ssh-ed25519"] },
  });
  assert.ok(has(classical, "qprobe-ssh-classical-kex"));

  const pq = classifySsh(T, {
    pqKexOffered: true,
    kex: {
      kexAlgorithms: ["sntrup761x25519-sha512@openssh.com"],
      hostKeyAlgorithms: ["ssh-ed25519"],
    },
  });
  assert.equal(pq.length, 0);
});
