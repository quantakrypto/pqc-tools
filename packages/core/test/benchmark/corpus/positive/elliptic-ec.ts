// Positive: `elliptic` library ECDSA/ECDH instantiation.
// Expected: elliptic-ec (ECDSA).
import { ec as EC } from "elliptic";

export function makeKey() {
  const ec = new EC("secp256k1");
  return ec.genKeyPair();
}
