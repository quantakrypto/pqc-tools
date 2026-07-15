//! Deterministic wallet: derives spend keys and signs transaction digests.
//!
//! Uses the upstream libsecp256k1 bindings. Imports are brought in braced and
//! renamed to fit the wallet's own vocabulary ("spend key", "curve").

use secp256k1::rand::rngs::OsRng;
use secp256k1::{
    ecdsa::Signature as TxSignature, Message as Digest, PublicKey as SpendPub,
    Secp256k1 as Curve, SecretKey as SpendKey,
};

pub struct Account {
    curve: Curve<secp256k1::All>,
    spend_key: SpendKey,
    spend_pub: SpendPub,
}

impl Account {
    pub fn derive() -> Self {
        let curve = Curve::new();
        let (spend_key, spend_pub) = curve.generate_keypair(&mut OsRng);
        Self {
            curve,
            spend_key,
            spend_pub,
        }
    }

    pub fn address_pubkey(&self) -> SpendPub {
        self.spend_pub
    }

    /// Sign a 32-byte transaction digest.
    pub fn sign_tx(&self, digest: [u8; 32]) -> TxSignature {
        let msg = Digest::from_digest(digest);
        self.curve.sign_ecdsa(&msg, &self.spend_key)
    }
}
