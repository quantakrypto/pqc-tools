import { compactDecrypt } from "jose";

// JWE RSA key transport — classical RSA-OAEP key encryption (harvest-now).
export const defaultAlg = "RSA-OAEP-256";

export function keyEncAlg(a: string): string {
  switch (a) {
    case "RSA-OAEP":
      return "rsa";
    case "RSA-OAEP-384":
      return "rsa";
    default:
      return a;
  }
}

export async function decrypt(jwe: string, key: CryptoKey) {
  return compactDecrypt(jwe, key);
}
