//! Detached signatures over release manifests using Ed25519.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Holds the signing half of a release identity.
pub struct ReleaseSigner {
    key: SigningKey,
}

impl ReleaseSigner {
    /// Generate a fresh signing identity backed by a CSPRNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        Self { key }
    }

    /// Produce a detached signature over the manifest bytes.
    pub fn sign_manifest(&self, manifest: &[u8]) -> Signature {
        self.key.sign(manifest)
    }

    /// Public half, distributed to verifiers.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}
