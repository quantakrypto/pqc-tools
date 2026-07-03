// RSA-PSS signing key + WebCrypto modern curves.
const pss = crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 });

async function agree(pk: CryptoKey, priv: CryptoKey) {
  await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  await crypto.subtle.deriveBits({ name: 'X25519', public: pk }, priv, 256);
}
