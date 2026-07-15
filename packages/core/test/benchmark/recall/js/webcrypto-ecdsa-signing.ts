/**
 * Client-side request signing using the Web Crypto API.
 * Each session mints an ephemeral ECDSA key pair on the P-384 curve and
 * signs the canonicalised request body with it. The public key is uploaded
 * once during registration.
 */
export interface SignedRequest {
  signature: ArrayBuffer;
  publicKey: JsonWebKey;
}

export async function signRequest(body: ArrayBuffer): Promise<SignedRequest> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    keyPair.privateKey,
    body,
  );

  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { signature, publicKey };
}
