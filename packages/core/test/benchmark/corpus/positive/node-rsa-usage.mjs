// Positive: node-rsa wraps classical RSA encryption/signing.
// Expected: node-rsa (RSA).
import NodeRSA from "node-rsa";

export function makeKey() {
  return new NodeRSA({ b: 2048 });
}
