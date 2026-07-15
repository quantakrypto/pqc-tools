# frozen_string_literal: true

require "openssl"
require "base64"

# Signs point-of-sale receipts so downstream services can verify authenticity
# without ever holding the private key. Uses NIST P-256 (prime256v1) ECDSA.
class ReceiptSigner
  DIGEST = OpenSSL::Digest::SHA256

  def initialize
    @key = OpenSSL::PKey::EC.generate("prime256v1")
  end

  # Distributes the verification key to receipt consumers.
  def public_pem
    @key.public_to_pem
  end

  def sign(receipt_json)
    der = @key.sign(DIGEST.new, receipt_json)
    Base64.strict_encode64(der)
  end

  def verify(receipt_json, signature_b64)
    @key.verify(DIGEST.new, Base64.strict_decode64(signature_b64), receipt_json)
  end
end
