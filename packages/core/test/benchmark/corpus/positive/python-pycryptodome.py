from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Cipher import PKCS1_OAEP

rsa_key = RSA.generate(2048)
ecc_key = ECC.generate(curve="P-256")
dsa_key = DSA.generate(2048)
cipher = PKCS1_OAEP.new(rsa_key.publickey())
