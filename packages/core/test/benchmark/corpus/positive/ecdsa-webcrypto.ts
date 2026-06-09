// Positive: ECDSA signing via WebCrypto SubtleCrypto.
// Expected: webcrypto-classical (ECDSA).
export async function signEcdsa(key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
}
