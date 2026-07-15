import jwt from "jsonwebtoken";
import { readFileSync } from "node:fs";
import { SignJWT, importPKCS8 } from "jose";

const rsaPrivateKey = readFileSync("./keys/rs256-private.pem", "utf8");

/**
 * Legacy access tokens are signed with RSA (RS256). The `jsonwebtoken`
 * library picks the RSASSA-PKCS1-v1_5 primitive from the algorithm string.
 */
export function issueAccessToken(sub: string, scope: string): string {
  return jwt.sign({ sub, scope }, rsaPrivateKey, {
    algorithm: "RS256",
    issuer: "auth.internal",
    audience: "api.internal",
    expiresIn: "15m",
  });
}

/**
 * Newer refresh tokens are signed with EdDSA (Ed25519) via `jose`. The key
 * is loaded from an env-supplied PKCS#8 blob.
 */
export async function issueRefreshToken(sub: string): Promise<string> {
  const key = await importPKCS8(process.env.ED25519_PRIVATE_KEY!, "EdDSA");
  return new SignJWT({ sub })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(key);
}
