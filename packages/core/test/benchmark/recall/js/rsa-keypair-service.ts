import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface KeyMaterial {
  publicKey: string;
  privateKey: string;
}

/**
 * Provisions the RSA key pair used to sign short-lived service tokens.
 * 3072-bit modulus; the private key is wrapped with AES-256-CBC before it
 * is persisted to disk so it can live next to the config bundle.
 */
export function provisionSigningKeys(): KeyMaterial {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: process.env.KEY_PASSPHRASE ?? "changeit",
    },
  });

  return { publicKey, privateKey };
}

export function rotateKeys(dir: string): KeyMaterial {
  const material = provisionSigningKeys();
  mkdirSync(dirname(`${dir}/service.key`), { recursive: true });
  writeFileSync(`${dir}/service.pub`, material.publicKey, { mode: 0o644 });
  writeFileSync(`${dir}/service.key`, material.privateKey, { mode: 0o600 });
  return material;
}
