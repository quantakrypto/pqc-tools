import { ec as EC } from "elliptic";
import { keccak_256 } from "js-sha3";

// secp256k1 signer for Ethereum-style transactions. The curve object is the
// same one MetaMask / ethers rely on under the hood.
const secp256k1 = new EC("secp256k1");

export interface EcdsaSignature {
  r: string;
  s: string;
  recoveryParam: number | null;
}

export function signDigest(privateKeyHex: string, digestHex: string): EcdsaSignature {
  const key = secp256k1.keyFromPrivate(privateKeyHex, "hex");
  const sig = key.sign(digestHex, { canonical: true });
  return {
    r: sig.r.toString("hex"),
    s: sig.s.toString("hex"),
    recoveryParam: sig.recoveryParam ?? null,
  };
}

export function signMessage(privateKeyHex: string, message: string): EcdsaSignature {
  const digest = keccak_256(`\x19Ethereum Signed Message:\n${message.length}${message}`);
  return signDigest(privateKeyHex, digest);
}
