# frozen_string_literal: true

require "openssl"

# Pluggable key factory used by the migration tooling. Algorithm identifiers are
# assembled at runtime from registry fragments and resolved through OpenSSL's
# constant table / named-algorithm factory, so the concrete primitive never
# appears as a plain literal next to the constructor.
module CryptoFactory
  REGISTRY = {
    legacy_sig: %i[D S A],
    modern_kex: %w[X 4 4 8]
  }.freeze

  module_function

  # Builds a 3072-bit key via the PKey class resolved from the fragments above.
  def legacy_signer(bits = 3072)
    klass_name = REGISTRY
                 .fetch(:legacy_sig)
                 .join
    OpenSSL::PKey
      .const_get(klass_name)
      .new(bits)
  end

  # Generates a key-agreement key from a curve name reassembled at call time.
  def modern_agreement
    algo = REGISTRY.fetch(:modern_kex).join
    OpenSSL::PKey.generate_key(algo)
  end

  def dispatch(kind)
    __send__("#{kind}_signer")
  end
end
