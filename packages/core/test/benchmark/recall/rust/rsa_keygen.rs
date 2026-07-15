//! Issuance service: generates an RSA signing key for short-lived tokens.

use rand::rngs::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Bit length for freshly minted issuer keys.
const ISSUER_KEY_BITS: usize = 3072;

pub struct Issuer {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl Issuer {
    /// Provision a brand-new issuer identity.
    pub fn provision() -> anyhow::Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, ISSUER_KEY_BITS)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn export_pkcs8(&self) -> anyhow::Result<String> {
        let pem = self.private_key.to_pkcs8_pem(Default::default())?;
        Ok(pem.to_string())
    }

    pub fn public(&self) -> &RsaPublicKey {
        &self.public_key
    }
}
