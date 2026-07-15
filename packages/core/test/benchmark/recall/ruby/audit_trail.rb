# frozen_string_literal: true

require "ed25519"

# Append-only audit log where every entry is signed with an Ed25519 key so the
# chain can be independently verified by auditors holding only the public key.
class AuditTrail
  def initialize(seed: nil)
    @signing_key = seed ? Ed25519::SigningKey.new(seed) : Ed25519::SigningKey.generate
    @verify_key = @signing_key.verify_key
  end

  def verify_key_bytes
    @verify_key.to_bytes
  end

  def append(entry)
    message = canonicalize(entry)
    signature = @signing_key.sign(message)
    { entry: entry, sig: signature.unpack1("H*") }
  end

  private

  def canonicalize(entry)
    entry.sort.map { |k, v| "#{k}=#{v}" }.join("&")
  end
end
