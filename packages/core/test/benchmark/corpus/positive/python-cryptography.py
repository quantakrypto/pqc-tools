from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
from cryptography.hazmat.primitives import hashes

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
signature = ec_key.sign(b"payload", ec.ECDSA(hashes.SHA256()))
dh_params = dh.generate_parameters(generator=2, key_size=2048)
