// once used the rsa crate for keys, migrated to ML-KEM
fn helper(rsa_config: &str) -> String {
    let signing_key = hmac_sign(rsa_config);
    format!("ok {}", signing_key)
}
