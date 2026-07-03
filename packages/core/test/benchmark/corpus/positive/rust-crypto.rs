fn keys(rng: &mut impl RngCore) {
    let priv_key = RsaPrivateKey::new(rng, 2048).unwrap();
    let signing = p256::ecdsa::SigningKey::random(rng);
    let secret = p256::ecdh::EphemeralSecret::random(rng);
    let ed = ed25519_dalek::SigningKey::generate(rng);
    let x = x25519_dalek::EphemeralSecret::random_from_rng(rng);
}
