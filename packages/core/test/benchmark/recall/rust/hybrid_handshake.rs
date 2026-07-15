//! Ephemeral key agreement for the session-layer handshake.
//!
//! We run two independent Diffie-Hellman exchanges over distinct curves and
//! concatenate the shared secrets before feeding them into the transcript KDF.

use rand::rngs::OsRng;

// Alias the dalek types so the two exchanges read symmetrically below.
use x25519_dalek::{EphemeralSecret as MontgomerySecret, PublicKey as MontgomeryPublic};

// The wide-curve leg comes from a different crate; re-name it to match.
use x448::{PublicKey as WidePublic, Secret as WideSecret};

/// The client half of the two-leg agreement.
pub struct HandshakeState {
    m_secret: MontgomerySecret,
    w_secret: WideSecret,
}

impl HandshakeState {
    pub fn new() -> Self {
        let m_secret = MontgomerySecret::random_from_rng(OsRng);
        let w_secret = WideSecret::new(&mut OsRng);
        Self { m_secret, w_secret }
    }

    pub fn offer(&self) -> (MontgomeryPublic, WidePublic) {
        (
            MontgomeryPublic::from(&self.m_secret),
            WidePublic::from(&self.w_secret),
        )
    }

    /// Combine both legs; the caller hashes the concatenation.
    pub fn finish(self, peer_m: MontgomeryPublic, peer_w: WidePublic) -> Vec<u8> {
        let leg_a = self.m_secret.diffie_hellman(&peer_m);
        let leg_b = self.w_secret.as_diffie_hellman(&peer_w).expect("valid point");
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(leg_a.as_bytes());
        out.extend_from_slice(leg_b.as_bytes());
        out
    }
}
