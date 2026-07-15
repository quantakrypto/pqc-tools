import { generateKeyPairSync as gk, diffieHellman as agree } from "node:crypto";
import { hkdfSync } from "node:crypto";

// Forward-secret channel setup. Each session generates a fresh X25519 key
// pair and derives a 32-byte channel key from the raw shared secret via HKDF.
export function openChannel(peerPublicKey) {
  const { publicKey, privateKey } = gk("x25519");

  const shared = agree({ privateKey, publicKey: peerPublicKey });
  const channelKey = Buffer.from(
    hkdfSync("sha256", shared, Buffer.alloc(0), "x25519-channel", 32),
  );

  return { publicKey, channelKey };
}
