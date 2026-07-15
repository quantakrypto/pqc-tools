require "openssl"

# ruby-rsa-crypt: RSA public-key encryption on an already-loaded key (RSA, kem, HNDL).
ciphertext = rsa_pub.public_encrypt(message)

# ruby-dh-agree: finite-field DH shared-secret agreement (DH, key-exchange, HNDL).
shared = dh_compute_key(peer_pub)

# ruby-pkey-read: type-agnostic key loader (unknown, key-exchange, HNDL, conservative).
loaded = OpenSSL::PKey.read(pem_string)

# ruby-ed25519: Ed25519 signing key via the generic factory (EdDSA, signature).
signer = OpenSSL::PKey.generate_key("ED25519")

# ruby-tls-verify-none: disabled TLS peer verification (tls, cert-validation).
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
