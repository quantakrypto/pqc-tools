# frozen_string_literal: true

require "rbnacl"

# Wraps libsodium's Curve25519 (X25519) Diffie-Hellman plus secretbox so the
# messaging layer gets an authenticated, encrypted channel with a peer. The
# X25519 agreement is what establishes the shared key; the secretbox that seals
# each message is symmetric.
class SecureChannel
  def initialize
    @private_key = RbNaCl::PrivateKey.generate
    @public_key = @private_key.public_key
  end

  def public_key_bytes
    @public_key.to_bytes
  end

  def box_for(peer_public_bytes)
    peer = RbNaCl::PublicKey.new(peer_public_bytes)
    RbNaCl::Box.new(peer, @private_key)
  end

  def seal(peer_public_bytes, plaintext)
    box = box_for(peer_public_bytes)
    nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
    nonce + box.encrypt(nonce, plaintext)
  end
end
