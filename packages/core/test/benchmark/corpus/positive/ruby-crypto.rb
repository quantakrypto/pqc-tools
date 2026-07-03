require "openssl"

rsa = OpenSSL::PKey::RSA.new(2048)
ec = OpenSSL::PKey::EC.generate("prime256v1")
dsa = OpenSSL::PKey::DSA.new(2048)
dh = OpenSSL::PKey::DH.new(2048)
