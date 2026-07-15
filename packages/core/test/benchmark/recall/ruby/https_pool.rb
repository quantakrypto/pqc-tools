# frozen_string_literal: true

require "openssl"
require "net/http"

# Builds a hardened HTTPS connection context for talking to partner APIs.
# Pins the negotiated protocol range and the classical cipher suites we allow.
module Outbound
  class TlsPool
    CIPHERS = [
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "DHE-RSA-AES256-GCM-SHA384"
    ].join(":").freeze

    def self.ssl_context
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
      ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
      ctx.ciphers = CIPHERS
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx
    end
  end
end
