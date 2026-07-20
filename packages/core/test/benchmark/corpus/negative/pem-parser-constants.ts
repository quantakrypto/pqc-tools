// A PEM parser that only NAMES the markers as string constants — no key material.
export const PEM_RSA_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
export const PEM_RSA_END = "-----END RSA PRIVATE KEY-----";
export const PEM_PK8_BEGIN = "-----BEGIN PRIVATE KEY-----";
export function isPrivateKeyHeader(line: string): boolean {
  return line.startsWith("-----BEGIN") && line.includes("PRIVATE KEY-----");
}
