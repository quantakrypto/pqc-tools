//! Secure channel bootstrap built on *ring*.
//!
//! Peers agree on a shared secret over NIST P-256, then authenticate the
//! transcript with an Ed25519 identity key. Both primitives come from ring's
//! lower-level API rather than the more common dalek crates.

use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub struct ChannelInit {
    rng: SystemRandom,
}

impl ChannelInit {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate our ephemeral P-256 contribution to the exchange.
    pub fn ephemeral(&self) -> Result<EphemeralPrivateKey, ring::error::Unspecified> {
        EphemeralPrivateKey::generate(&ECDH_P256, &self.rng)
    }

    /// Complete the exchange against the peer's public point.
    pub fn agree(
        &self,
        mine: EphemeralPrivateKey,
        peer: &[u8],
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let peer_pub = UnparsedPublicKey::new(&ECDH_P256, peer);
        agreement::agree_ephemeral(mine, &peer_pub, |secret| secret.to_vec())
    }

    /// Long-term identity used to sign the handshake transcript.
    pub fn identity(&self) -> Result<Ed25519KeyPair, ring::error::Unspecified> {
        let doc = Ed25519KeyPair::generate_pkcs8(&self.rng)?;
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref())
            .map_err(|_| ring::error::Unspecified)?;
        let _pubkey = pair.public_key();
        Ok(pair)
    }
}
