//! Request signing for the internal admission webhook (ECDSA over NIST P-256).

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

/// Wraps a P-256 signing key used to authenticate admission requests.
pub struct AdmissionKey {
    signing_key: SigningKey,
}

impl AdmissionKey {
    pub fn random() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Sign the canonicalized request body.
    pub fn sign(&self, body: &[u8]) -> Signature {
        self.signing_key.sign(body)
    }
}
