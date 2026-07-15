// Parity fixture for the openssl-crate, ring-X25519, bare-constructor, and TLS
// gaps (audit F5/F9). Braced `use ...::{...}` imports strip the `::` path prefix,
// which is exactly why the path-qualified rules in rust.ts miss these forms.
use openssl::rsa::Rsa;
use openssl::ec::EcKey;
use openssl::dsa::Dsa;
use openssl::dh::Dh;
use ring::agreement;
use x25519_dalek::{EphemeralSecret};
use ed25519_dalek::{SigningKey};
use reqwest::ClientBuilder;
use rustls::ClientConfig;

fn openssl_keys(group: &EcGroup) {
    let _rsa = Rsa::generate(2048).unwrap();
    let _ec = EcKey::generate(group).unwrap();
    let _dsa = Dsa::generate(2048).unwrap();
    let _params = Dh::get_2048_256().unwrap();
}

fn ring_x25519() {
    let _alg = &agreement::X25519;
}

fn dalek_bare(mut rng: OsRng) {
    let _eph = EphemeralSecret::new(&mut rng);
    let _sk = SigningKey::generate(&mut rng);
}

fn tls_reqwest() {
    let _client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build();
}

fn tls_rustls(config: ClientConfig) {
    let _danger = config.dangerous();
}
