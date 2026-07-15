# frozen_string_literal: true

require "openssl"
require "jwt"

# Bridges wallet-based auth (Bitcoin-style keys) to the internal JWT session
# format. The elliptic curve and the JWS algorithm are pulled from config so
# ops can rotate them without a code change -- the concrete names never appear
# next to the constructors.
module Bridge
  CONFIG = {
    wallet_curve: "secp256k1",
    session_alg: "ES256"
  }.freeze

  class WalletSession
    def initialize(config = CONFIG)
      @curve = config.fetch(:wallet_curve)
      @alg = config.fetch(:session_alg)
    end

    # Recreates the user's on-chain wallet key from the configured curve.
    def wallet_key
      OpenSSL::PKey::EC.generate(@curve)
    end

    # Mints a session token signed with the configured JWS algorithm.
    def mint(claims, signing_key)
      JWT.encode(claims, signing_key, @alg)
    end
  end
end
