//! Interop shims for a legacy appliance that still negotiates classical
//! finite-field parameters and DSA host signatures.
//!
//! Backed by the system OpenSSL via the `openssl` crate.

use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::dsa::Dsa;
use openssl::error::ErrorStack;

/// Regenerate the MODP group the appliance expects during rekey.
pub fn negotiate_ff_params() -> Result<Dh<openssl::pkey::Private>, ErrorStack> {
    // 2048-bit safe-prime group, generator 2.
    let params = Dh::generate_params(2048, 2)?;
    let keypair = params.generate_key()?;
    Ok(keypair)
}

/// Provision a DSA host key of the given modulus size.
pub fn provision_host_key(bits: u32) -> Result<Dsa<openssl::pkey::Private>, ErrorStack> {
    let dsa = Dsa::generate(bits)?;
    Ok(dsa)
}

/// Helper the appliance uses to pin a specific generator.
pub fn pinned_generator() -> Result<BigNum, ErrorStack> {
    BigNum::from_u32(2)
}
