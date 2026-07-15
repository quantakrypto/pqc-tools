# frozen_string_literal: true

require "openssl"
require "jwt"

# Issues and verifies short-lived access tokens for the internal API gateway.
# On first boot with no key on disk we mint a fresh RSA signing key; otherwise
# the PEM is loaded and reused across restarts.
module Auth
  class TokenIssuer
    ACCESS_TTL = 900 # seconds

    def initialize(key_path: ENV.fetch("JWT_SIGNING_KEY", "config/signing_key.pem"))
      @private_key =
        if File.exist?(key_path)
          OpenSSL::PKey::RSA.new(File.read(key_path))
        else
          OpenSSL::PKey::RSA.new(2048)
        end
    end

    def issue(subject, scopes)
      now = Time.now.to_i
      payload = {
        sub: subject,
        scp: Array(scopes).join(" "),
        iat: now,
        exp: now + ACCESS_TTL,
        iss: "gateway.internal"
      }
      JWT.encode(payload, @private_key, "RS256", { kid: fingerprint })
    end

    def verify(token)
      claims, = JWT.decode(token, @private_key.public_key, true, { algorithm: "RS256" })
      claims
    end

    private

    # Short key id derived from the public key; the SHA-256 digest here is just
    # for identification, not signing.
    def fingerprint
      OpenSSL::Digest::SHA256.hexdigest(@private_key.public_key.to_der)[0, 16]
    end
  end
end
