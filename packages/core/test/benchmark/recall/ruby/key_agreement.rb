# frozen_string_literal: true

require "openssl"

# Derives a shared symmetric secret with a peer using ephemeral key agreement.
# Two transports are supported: elliptic-curve (P-384) for modern peers, and
# classic finite-field Diffie-Hellman for legacy peers that can't do EC.
class Handshake
  def initialize
    @ec = OpenSSL::PKey::EC.generate("secp384r1")
  end

  # Elliptic-curve DH: mixes our private scalar with the peer's public point.
  def ec_shared_secret(peer_public_pem)
    peer = OpenSSL::PKey::EC.new(peer_public_pem)
    @ec.dh_compute_key(peer.public_key)
  end

  # Legacy finite-field DH agreement against server-provided group parameters.
  def ff_shared_secret(params_pem, peer_pub_bn)
    dh = OpenSSL::PKey::DH.new(File.read(params_pem))
    dh.generate_key!
    dh.compute_key(peer_pub_bn)
  end
end
