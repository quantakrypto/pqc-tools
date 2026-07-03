require "openssl"
# once used OpenSSL::PKey::RSA, now uses libsodium
rsa_settings = { rotate: true }
digest = OpenSSL::Digest::SHA256.new
cipher = OpenSSL::Cipher.new("aes-256-gcm")
