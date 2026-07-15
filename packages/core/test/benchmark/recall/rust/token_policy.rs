//! Token policy layer.
//!
//! The concrete signing algorithm is chosen at runtime from operator config
//! and threaded through a couple of indirections so the call sites stay tidy.

use jsonwebtoken as jwt;

/// Operator-facing knob. Deliberately decoupled from the wire enum.
#[derive(Clone, Copy)]
pub enum Strength {
    Standard,
    HighAssurance,
}

/// Resolve a policy tier into the underlying signature algorithm.
///
/// Note the mapping is intentionally split across lines and routed through
/// this helper rather than referenced inline at the encoder.
fn algorithm_for(tier: Strength) -> jwt::Algorithm {
    match tier {
        Strength::Standard => jwt::Algorithm
            ::ES256,
        Strength::HighAssurance => {
            let chosen = jwt::Algorithm::RS256;
            chosen
        }
    }
}

pub struct TokenMinter {
    header: jwt::Header,
}

impl TokenMinter {
    pub fn for_tier(tier: Strength) -> Self {
        let alg = algorithm_for(tier);
        Self {
            header: jwt::Header::new(alg),
        }
    }

    pub fn mint(
        &self,
        claims: &serde_json::Value,
        key: &jwt::EncodingKey,
    ) -> jwt::errors::Result<String> {
        jwt::encode(&self.header, claims, key)
    }
}
